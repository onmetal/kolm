// Copyright 2022 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kolm

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/go-logr/logr"
	"github.com/onmetal/kolm/addr"
	"github.com/onmetal/kolm/api/v1alpha1"
	"github.com/onmetal/kolm/api/v1alpha1/helper"
	"github.com/onmetal/kolm/apiserver"
	"github.com/onmetal/kolm/certutil"
	"github.com/onmetal/kolm/etcd"
	"github.com/onmetal/kolm/kubeconfigs"
	"github.com/onmetal/kolm/logger"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/cert"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	manifestName       = "kolm.yaml"
	certsDirectoryName = "certs"

	caPairName         = "ca"
	serverPairName     = "server"
	kubeconfigPairName = "client"
)

type Kolm interface {
	List(ctx context.Context) (*v1alpha1.APIList, error)
	Get(ctx context.Context, name string) (*v1alpha1.API, error)
	Create(ctx context.Context, api *v1alpha1.API) (*v1alpha1.API, error)
	Delete(ctx context.Context, name string) error

	Start(ctx context.Context, name string) (Handle, error)
	Kubeconfig(ctx context.Context, name string) (*clientcmdapi.Config, error)
}

type kolm struct {
	dir string
}

func New(dir string) (Kolm, error) {
	stat, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("error stat-ing %s: %w", dir, err)
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("file at %s is not a directory", dir)
	}

	return &kolm{
		dir: dir,
	}, nil
}

func (k *kolm) List(ctx context.Context) (*v1alpha1.APIList, error) {
	log := ctrl.LoggerFrom(ctx)

	entries, err := os.ReadDir(k.dir)
	if err != nil {
		return nil, fmt.Errorf("error reading base directory: %w", err)
	}

	var items []v1alpha1.API
	for _, entry := range entries {
		if entry.IsDir() {
			item, err := k.Get(ctx, entry.Name())
			if err != nil {
				if !apierrors.IsNotFound(err) {
					log.Error(err, "Error getting item", "Name", entry.Name())
				}
				continue
			}

			items = append(items, *item)
		}
	}
	return &v1alpha1.APIList{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       v1alpha1.APIKind,
		},
		Items: items,
	}, nil
}

func (k *kolm) itemDirectory(name string) string {
	return filepath.Join(k.dir, name)
}

func (k *kolm) itemCertsDirectory(name string) string {
	return filepath.Join(k.itemDirectory(name), certsDirectoryName)
}

func (k *kolm) itemManifestFilename(name string) string {
	return filepath.Join(k.itemDirectory(name), manifestName)
}

func (k *kolm) itemCAPairName(name string) string {
	return filepath.Join(k.itemCertsDirectory(name), caPairName)
}

func (k *kolm) itemServerPairName(name string) string {
	return filepath.Join(k.itemCertsDirectory(name), serverPairName)
}

func (k *kolm) itemKubeconfigPairName(name string) string {
	return filepath.Join(k.itemCertsDirectory(name), kubeconfigPairName)
}

func (k *kolm) Get(ctx context.Context, name string) (*v1alpha1.API, error) {
	if name == "" {
		return nil, fmt.Errorf("must specify name")
	}

	item, err := helper.ReadAPIFile(k.itemManifestFilename(name))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("error reading api file: %w", err)
		}

		return nil, apierrors.NewNotFound(v1alpha1.Resource(v1alpha1.APIResource), name)
	}
	return item, nil
}

func (k *kolm) checkExists(ctx context.Context, name string) (bool, error) {
	_, err := k.Get(ctx, name)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("error checking whether %s exists: %w", name, err)
		}
		return false, nil
	}
	return true, nil
}

func (k *kolm) initCertificates(name string, certs v1alpha1.APICerts) error {
	if err := os.Mkdir(k.itemCertsDirectory(name), 0700); err != nil {
		return fmt.Errorf("error creating certificate directory: %w", err)
	}

	caPair, err := certutil.GenerateSelfSignedCA(certs.CommonName, certs.Organization)
	if err != nil {
		return fmt.Errorf("error generating self-signed ca: %w", err)
	}

	serverPair, err := certutil.GenerateCertificate(caPair, cert.Config{
		CommonName:   certs.CommonName,
		Organization: certs.Organization,
		AltNames: cert.AltNames{
			DNSNames: []string{"localhost"},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("error generating server certificate: %w", err)
	}

	if err := certutil.WritePairFiles(caPair, k.itemCAPairName(name)); err != nil {
		return fmt.Errorf("error writing ca files: %w", err)
	}

	if err := certutil.WritePairFiles(serverPair, k.itemServerPairName(name)); err != nil {
		return fmt.Errorf("error writing server files: %w", err)
	}

	return nil
}

func (k *kolm) suggestPorts(api *v1alpha1.API) error {
	pc := addr.NewPortCache()
	if err := pc.Start(); err != nil {
		return err
	}
	defer func() { _ = pc.Stop() }()

	if api.APIServer.Host == "" && api.APIServer.Port == 0 {
		port, err := pc.Suggest("localhost")
		if err != nil {
			return fmt.Errorf("error suggesting api server port: %w", err)
		}

		api.APIServer.Host = "localhost"
		api.APIServer.Port = port.Port
	}

	if api.ETCD.Host == "" && api.ETCD.Port == 0 {
		port, err := pc.Suggest("localhost")
		if err != nil {
			return fmt.Errorf("error suggesting etcd port: %w", err)
		}

		api.ETCD.Host = "localhost"
		api.ETCD.Port = port.Port
	}

	if api.ETCD.PeerHost == "" && api.ETCD.PeerPort == 0 {
		port, err := pc.Suggest("localhost")
		if err != nil {
			return fmt.Errorf("error suggesting etcd peer port: %w", err)
		}

		api.ETCD.PeerHost = "localhost"
		api.ETCD.PeerPort = port.Port
	}

	return nil
}

func (k *kolm) Create(ctx context.Context, api *v1alpha1.API) (*v1alpha1.API, error) {
	if api == nil {
		return nil, fmt.Errorf("must specify api")
	}
	if api.Name == "" {
		return nil, fmt.Errorf("must specify name")
	}

	if err := k.suggestPorts(api); err != nil {
		return nil, fmt.Errorf("error suggesting api ports: %w", err)
	}

	exists, err := k.checkExists(ctx, api.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, apierrors.NewAlreadyExists(v1alpha1.Resource(v1alpha1.APIResource), api.Name)
	}

	if err := os.Mkdir(k.itemDirectory(api.Name), 0700); err != nil {
		return nil, fmt.Errorf("error creating api directory: %w", err)
	}
	if err := k.initCertificates(api.Name, api.Certs); err != nil {
		return nil, fmt.Errorf("error initializing certificates")
	}
	if err := helper.WriteAPIFile(api, k.itemManifestFilename(api.Name)); err != nil {
		return nil, fmt.Errorf("error writing api file: %w", err)
	}
	return api, nil
}

func (k *kolm) Delete(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("must specify name")
	}

	if _, err := k.Get(ctx, name); err != nil {
		return err
	}

	if err := os.RemoveAll(k.itemDirectory(name)); err != nil {
		return fmt.Errorf("error removing api directory: %w", err)
	}
	return nil
}

type StartOptions struct {
	Stdout io.Writer
	Stderr io.Writer
}

func (k *kolm) Start(ctx context.Context, name string) (Handle, error) {
	log := ctrl.LoggerFrom(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startLog := log.WithName(color.New(color.Bold).Sprint("🛠 setup"))

	startLog.V(1).Info("Getting api definition")
	api, err := k.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	startLog.V(1).Info("Successfully got api definition")

	startLog.V(1).Info("Starting etcd")
	etcdLogWriter := logger.NewJSONLogWriter(log.V(2).WithName(color.GreenString("📦 etcd")))
	e, err := etcd.Start(etcd.Options{
		Dir:      k.itemDirectory(name),
		Host:     api.ETCD.Host,
		Port:     api.ETCD.Port,
		PeerHost: api.ETCD.PeerHost,
		PeerPort: api.ETCD.PeerPort,
		Stdout:   etcdLogWriter,
		Stderr:   etcdLogWriter,
	})
	if err != nil {
		return nil, err
	}
	startLog.V(1).Info("Successfully started etcd")

	startLog.V(1).Info("Starting api server")
	apiSrvLogWriter := logger.NewKLogLogWriter(log.V(2).WithName(color.BlueString("☸ apiserver")))
	apiSrv, err := apiserver.Start(apiserver.Options{
		Dir:                k.itemDirectory(name),
		ETCDServers:        []string{fmt.Sprintf("http://%s:%d", api.ETCD.Host, api.ETCD.Port)},
		ServerCertPairName: k.itemServerPairName(name),
		Host:               api.APIServer.Host,
		SecurePort:         api.APIServer.Port,
		Stdout:             apiSrvLogWriter,
		Stderr:             apiSrvLogWriter,
	})
	if err != nil {
		if err := e.Stop(); err != nil {
			startLog.Error(err, "Error stopping etcd")
		}
		return nil, err
	}

	startLog.V(1).Info("Successfully started api server")
	return &apiHandle{
		log:       log,
		apiServer: apiSrv,
		etcd:      e,
	}, nil
}

type apiHandle struct {
	log       logr.Logger
	apiServer *apiserver.APIServer
	etcd      *etcd.ETCD
}

func (h *apiHandle) Stop() error {
	var errs []error

	h.log.V(1).Info("Stopping api server")
	if err := h.apiServer.Stop(); err != nil {
		errs = append(errs, err)
	}

	h.log.V(1).Info("Stopping etcd")
	if err := h.etcd.Stop(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("error(s) stopping api: %v", errs)
	}

	h.log.V(1).Info("Successfully stopped api")
	return nil
}

type Handle interface {
	Stop() error
}

func (k *kolm) getOrCreateKubeconfigCertificate(api *v1alpha1.API) (caCert *x509.Certificate, certPair *certutil.Pair, err error) {
	certPair, err = certutil.ReadPairFiles(k.itemKubeconfigPairName(api.Name))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("error checking for kubeconfig certificate pair: %w", err)
		}

		caPair, err := certutil.ReadPairFiles(k.itemCAPairName(api.Name))
		if err != nil {
			return nil, nil, fmt.Errorf("error reading ca certificate pair: %w", err)
		}

		certPair, err = certutil.GenerateCertificate(caPair, cert.Config{
			CommonName:   api.Certs.CommonName,
			Organization: api.Certs.Organization,
			AltNames: cert.AltNames{
				DNSNames: []string{"localhost"},
				IPs:      []net.IP{net.ParseIP("127.0.0.1")},
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("error generating kubeconfig certificate: %w", err)
		}

		if err := certutil.WritePairFiles(certPair, k.itemKubeconfigPairName(api.Name)); err != nil {
			return nil, nil, fmt.Errorf("error writing kubeconfig certificate pair: %w", err)
		}

		return caPair.Cert, certPair, nil
	}

	caCert, err = certutil.ReadCertificateFile(k.itemCAPairName(api.Name))
	if err != nil {
		return nil, nil, fmt.Errorf("error reading ca certificate: %w", err)
	}

	return caCert, certPair, nil
}

const (
	DefaultName = "kolm"
)

func (k *kolm) Kubeconfig(ctx context.Context, name string) (*clientcmdapi.Config, error) {
	api, err := k.Get(ctx, name)
	if err != nil {
		return nil, err
	}

	caCert, certPair, err := k.getOrCreateKubeconfigCertificate(api)
	if err != nil {
		return nil, fmt.Errorf("error getting / creating kubeconfig certificate: %w", err)
	}

	server := fmt.Sprintf("https://%s:%d", api.APIServer.Host, api.APIServer.Port)
	return kubeconfigs.New(name, server, caCert, certPair)
}

func Export(ctx context.Context, k Kolm, name string, kubeCfg *clientcmdapi.Config) (*clientcmdapi.Config, error) {
	override, err := k.Kubeconfig(ctx, name)
	if err != nil {
		return nil, err
	}

	return kubeconfigs.Merge(kubeCfg, override)
}

func ExportFile(ctx context.Context, k Kolm, name, filename string) error {
	kubeCfg, err := clientcmd.LoadFromFile(filename)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("error loading kubeconfig %s: %w", filename, err)
		}

		kubeCfg = clientcmdapi.NewConfig()
	}

	kubeCfg, err = Export(ctx, k, name, kubeCfg)
	if err != nil {
		return fmt.Errorf("error exporting kubeconfig: %w", err)
	}

	return clientcmd.WriteToFile(*kubeCfg, filename)
}

type RunOptions struct {
	Remove             bool
	KubeconfigFilename string
}

func Run(ctx context.Context, k Kolm, api *v1alpha1.API, opts RunOptions) error {
	log := ctrl.LoggerFrom(ctx)
	var cleanup []func()
	defer func() {
		for _, f := range cleanup {
			f()
		}
	}()

	api, err := k.Create(ctx, api)
	if err != nil {
		return fmt.Errorf("error creating api: %w", err)
	}
	if opts.Remove {
		cleanup = append(cleanup, func() {
			if err := k.Delete(ctx, api.Name); err != nil {
				log.Error(err, "Error deleting api after start failed")
			}
		})
	}

	handle, err := k.Start(ctx, api.Name)
	if err != nil {
		return err
	}
	cleanup = append(cleanup, func() {
		if err := handle.Stop(); err != nil {
			log.Error(err, "Error stopping api")
		}
	})

	if err := ExportFile(ctx, k, api.Name, opts.KubeconfigFilename); err != nil {
		return fmt.Errorf("error exporting kubeconfig: %w", err)
	}
	if opts.Remove {
		cleanup = append(cleanup, func() {
			if err := kubeconfigs.PruneFile(opts.KubeconfigFilename, api.Name); err != nil {
				log.Error(err, "Error pruning api from kubeconfig")
			}
		})
	}

	<-ctx.Done()

	return nil
}
