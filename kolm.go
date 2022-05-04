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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/cert"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	apisDir = "apis"

	manifestName       = "kolm.yaml"
	certsDirectoryName = "certs"

	caPairName             = "ca"
	serverPairName         = "server"
	serviceAccountPairName = "sa"
	proxyCAPairName        = "proxy-ca"
	proxyClientPairName    = "proxy-client"
	kubeconfigPairName     = "client"
	hostCAPairName         = "host-ca"
	hostPairName           = "host"

	fieldOwner = client.FieldOwner("kolm.onmetal.de/kolm")

	serviceOwnerLabel = "kolm.onmetal.de/service-owner"
)

var (
	commonName   = "kolm"
	organization = []string{"kolm"}
)

func init() {
	_ = apiregistrationv1.AddToScheme(scheme.Scheme)
}

type Kolm interface {
	APIs() APIs
}

type APIs interface {
	List(ctx context.Context) (*v1alpha1.APIList, error)
	Get(ctx context.Context, name string) (*v1alpha1.API, error)
	Create(ctx context.Context, api *v1alpha1.API) (*v1alpha1.API, error)
	Delete(ctx context.Context, name string) error

	Start(ctx context.Context, name string) (Handle, error)
	Kubeconfig(ctx context.Context, name string) (*clientcmdapi.Config, error)
	APIServices(name string) APIServices
	HostCertificate(ctx context.Context, name string) (*certutil.Pair, error)

	HostKeyFilename(ctx context.Context, name string) (string, error)
	HostCertificateFilename(ctx context.Context, name string) (string, error)
}

type APIServices interface {
	Apply(ctx context.Context, svcName, host string, port int32, apiServices []*apiregistrationv1.APIService) error
	Delete(ctx context.Context, svcName string) error
}

type kolm struct {
	dir string
}

func (k *kolm) apisDir() string {
	return filepath.Join(k.dir, apisDir)
}

func New(dir string) (Kolm, error) {
	k := &kolm{dir}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("error creating directory at %s: %w", dir, err)
	}
	if err := os.MkdirAll(k.apisDir(), 0700); err != nil {
		return nil, fmt.Errorf("error creating apis directory at %s: %w", k.apisDir(), err)
	}

	return &kolm{
		dir: dir,
	}, nil
}

type apis struct {
	dir string
}

func (k *kolm) APIs() APIs {
	return &apis{
		dir: k.apisDir(),
	}
}

func (a *apis) List(ctx context.Context) (*v1alpha1.APIList, error) {
	log := ctrl.LoggerFrom(ctx)

	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return nil, fmt.Errorf("error reading base directory: %w", err)
	}

	var items []v1alpha1.API
	for _, entry := range entries {
		if entry.IsDir() {
			item, err := a.Get(ctx, entry.Name())
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

func (a *apis) itemDirectory(name string) string {
	return filepath.Join(a.dir, name)
}

func (a *apis) itemCertsDirectory(name string) string {
	return filepath.Join(a.itemDirectory(name), certsDirectoryName)
}

func (a *apis) itemManifestFilename(name string) string {
	return filepath.Join(a.itemDirectory(name), manifestName)
}

func (a *apis) itemCAPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), caPairName)
}

func (a *apis) itemServerPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), serverPairName)
}

func (a *apis) itemServiceAccountPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), serviceAccountPairName)
}

func (a *apis) itemProxyCAPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), proxyCAPairName)
}

func (a *apis) itemProxyClientPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), proxyClientPairName)
}

func (a *apis) itemKubeconfigPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), kubeconfigPairName)
}

func (a *apis) itemHostCAPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), hostCAPairName)
}

func (a *apis) itemHostPairName(name string) string {
	return filepath.Join(a.itemCertsDirectory(name), hostPairName)
}

func (a *apis) Get(ctx context.Context, name string) (*v1alpha1.API, error) {
	if name == "" {
		return nil, fmt.Errorf("must specify name")
	}

	item, err := helper.ReadAPIFile(a.itemManifestFilename(name))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("error reading api file: %w", err)
		}

		return nil, apierrors.NewNotFound(v1alpha1.Resource(v1alpha1.APIResource), name)
	}
	return item, nil
}

func (a *apis) checkExists(ctx context.Context, name string) (bool, error) {
	_, err := a.Get(ctx, name)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("error checking whether %s exists: %w", name, err)
		}
		return false, nil
	}
	return true, nil
}

func (a *apis) initCertificates(name string) error {
	if err := os.Mkdir(a.itemCertsDirectory(name), 0700); err != nil {
		return fmt.Errorf("error creating certificate directory: %w", err)
	}

	caPair, err := certutil.GenerateSelfSignedCA(commonName, organization)
	if err != nil {
		return fmt.Errorf("error generating ca: %w", err)
	}

	serverPair, err := certutil.GenerateCertificate(caPair, cert.Config{
		CommonName:   commonName,
		Organization: organization,
		AltNames: cert.AltNames{
			DNSNames: []string{"localhost"},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("error generating server certificate: %w", err)
	}

	serviceAccountPair, err := certutil.GenerateSelfSignedCA(commonName, organization)
	if err != nil {
		return fmt.Errorf("error generating service account certificate: %w", err)
	}

	proxyCAPair, err := certutil.GenerateSelfSignedCA(commonName, organization)
	if err != nil {
		return fmt.Errorf("error generating proxy ca: %w", err)
	}

	proxyClientPair, err := certutil.GenerateCertificate(proxyCAPair, cert.Config{
		CommonName:   commonName,
		Organization: organization,
		AltNames: cert.AltNames{
			DNSNames: []string{"localhost"},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("error generating proxy client certificate: %w", err)
	}

	hostSvcCAPair, err := certutil.GenerateSelfSignedCA(commonName, organization)
	if err != nil {
		return fmt.Errorf("error generating host ca: %w", err)
	}

	hostSvcPair, err := certutil.GenerateCertificate(hostSvcCAPair, cert.Config{
		CommonName:   commonName,
		Organization: organization,
		AltNames: cert.AltNames{
			DNSNames: []string{"localhost", "*.kube-system.svc"},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("error generating host certificate: %w", err)
	}

	if err := certutil.WritePairFiles(caPair, a.itemCAPairName(name)); err != nil {
		return fmt.Errorf("error writing ca files: %w", err)
	}

	if err := certutil.WritePairFiles(serverPair, a.itemServerPairName(name)); err != nil {
		return fmt.Errorf("error writing server files: %w", err)
	}

	if err := certutil.WritePairFiles(serviceAccountPair, a.itemServiceAccountPairName(name)); err != nil {
		return fmt.Errorf("error writing service account files: %w", err)
	}

	if err := certutil.WritePairFiles(proxyCAPair, a.itemProxyCAPairName(name)); err != nil {
		return fmt.Errorf("error writing proxy ca: %w", err)
	}

	if err := certutil.WritePairFiles(proxyClientPair, a.itemProxyClientPairName(name)); err != nil {
		return fmt.Errorf("error writing proxy client files: %w", err)
	}

	if err := certutil.WritePairFiles(hostSvcCAPair, a.itemHostCAPairName(name)); err != nil {
		return fmt.Errorf("error writing host ca pair name: %w", err)
	}

	if err := certutil.WritePairFiles(hostSvcPair, a.itemHostPairName(name)); err != nil {
		return fmt.Errorf("error writing host pair name: %w", err)
	}

	return nil
}

func (a *apis) suggestPorts(api *v1alpha1.API) error {
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

func (a *apis) Create(ctx context.Context, api *v1alpha1.API) (*v1alpha1.API, error) {
	if api == nil {
		return nil, fmt.Errorf("must specify api")
	}
	if api.Name == "" {
		return nil, fmt.Errorf("must specify name")
	}

	if err := a.suggestPorts(api); err != nil {
		return nil, fmt.Errorf("error suggesting api ports: %w", err)
	}

	exists, err := a.checkExists(ctx, api.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, apierrors.NewAlreadyExists(v1alpha1.Resource(v1alpha1.APIResource), api.Name)
	}

	if err := os.Mkdir(a.itemDirectory(api.Name), 0700); err != nil {
		return nil, fmt.Errorf("error creating api directory: %w", err)
	}
	if err := a.initCertificates(api.Name); err != nil {
		return nil, fmt.Errorf("error initializing certificates")
	}
	if err := helper.WriteAPIFile(api, a.itemManifestFilename(api.Name)); err != nil {
		return nil, fmt.Errorf("error writing api file: %w", err)
	}
	return api, nil
}

func (a *apis) Delete(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("must specify name")
	}

	if _, err := a.Get(ctx, name); err != nil {
		return err
	}

	if err := os.RemoveAll(a.itemDirectory(name)); err != nil {
		return fmt.Errorf("error removing api directory: %w", err)
	}
	return nil
}

type StartOptions struct {
	Stdout io.Writer
	Stderr io.Writer
}

func (a *apis) Start(ctx context.Context, name string) (Handle, error) {
	log := ctrl.LoggerFrom(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startLog := log.WithName(color.New(color.Bold).Sprint("🛠 setup"))

	startLog.V(1).Info("Getting api definition")
	api, err := a.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	startLog.V(1).Info("Successfully got api definition")

	startLog.V(1).Info("Starting etcd")
	etcdLogWriter := logger.NewJSONLogWriter(log.V(2).WithName(color.GreenString("📦 etcd")))
	e, err := etcd.Start(etcd.Options{
		Dir:      a.itemDirectory(name),
		Host:     api.ETCD.Host,
		Port:     api.ETCD.Port,
		PeerHost: api.ETCD.PeerHost,
		PeerPort: api.ETCD.PeerPort,
		Stdout:   etcdLogWriter,
		Stderr:   etcdLogWriter,
	})
	if err != nil {
		return nil, fmt.Errorf("error starting etcd: %w", err)
	}
	startLog.V(1).Info("Successfully started etcd")

	startLog.V(1).Info("Starting api server")
	apiSrvLogWriter := logger.NewKLogLogWriter(log.V(2).WithName(color.BlueString("☸ apiserver")))
	apiSrv, err := apiserver.Start(apiserver.Options{
		Dir: a.itemDirectory(name),

		ETCDServers: []string{fmt.Sprintf("http://%s:%d", api.ETCD.Host, api.ETCD.Port)},

		CAPairName:                 a.itemCAPairName(name),
		ServerCertPairName:         a.itemServerPairName(name),
		ServiceAccountCertPairName: a.itemServiceAccountPairName(name),
		ProxyCAPairName:            a.itemProxyCAPairName(name),
		ProxyClientPairName:        a.itemProxyClientPairName(name),

		Host: api.APIServer.Host,
		Port: api.APIServer.Port,

		Stdout: apiSrvLogWriter,
		Stderr: apiSrvLogWriter,
	})
	if err != nil {
		if err := e.Stop(); err != nil {
			startLog.Error(err, "Error stopping etcd")
		}
		return nil, fmt.Errorf("error starting api server: %w", err)
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

func (a *apis) getOrCreateKubeconfigCertificate(api *v1alpha1.API) (caCert *x509.Certificate, certPair *certutil.Pair, err error) {
	certPair, err = certutil.ReadPairFiles(a.itemKubeconfigPairName(api.Name))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("error checking for kubeconfig certificate pair: %w", err)
		}

		caPair, err := certutil.ReadPairFiles(a.itemCAPairName(api.Name))
		if err != nil {
			return nil, nil, fmt.Errorf("error reading ca certificate pair: %w", err)
		}

		certPair, err = certutil.GenerateCertificate(caPair, cert.Config{
			CommonName:   "admin",
			Organization: []string{"system:masters"},
			AltNames: cert.AltNames{
				DNSNames: []string{"localhost"},
				IPs:      []net.IP{net.ParseIP("127.0.0.1")},
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("error generating kubeconfig certificate: %w", err)
		}

		if err := certutil.WritePairFiles(certPair, a.itemKubeconfigPairName(api.Name)); err != nil {
			return nil, nil, fmt.Errorf("error writing kubeconfig certificate pair: %w", err)
		}

		return caPair.Cert, certPair, nil
	}

	caCert, err = certutil.ReadCertificateFile(a.itemCAPairName(api.Name))
	if err != nil {
		return nil, nil, fmt.Errorf("error reading ca certificate: %w", err)
	}

	return caCert, certPair, nil
}

const (
	DefaultName = "kolm"
)

func (a *apis) Kubeconfig(ctx context.Context, name string) (*clientcmdapi.Config, error) {
	api, err := a.Get(ctx, name)
	if err != nil {
		return nil, err
	}

	caCert, certPair, err := a.getOrCreateKubeconfigCertificate(api)
	if err != nil {
		return nil, fmt.Errorf("error getting / creating kubeconfig certificate: %w", err)
	}

	server := fmt.Sprintf("https://%s:%d", api.APIServer.Host, api.APIServer.Port)
	return kubeconfigs.New(name, server, caCert, certPair)
}

func (a *apis) HostCertificate(ctx context.Context, name string) (*certutil.Pair, error) {
	if _, err := a.Get(ctx, name); err != nil {
		return nil, err
	}

	return certutil.ReadPairFiles(a.itemHostPairName(name))
}

func (a *apis) HostKeyFilename(ctx context.Context, name string) (string, error) {
	if _, err := a.Get(ctx, name); err != nil {
		return "", err
	}
	return a.itemHostPairName(name) + ".key", nil
}

func (a *apis) HostCertificateFilename(ctx context.Context, name string) (string, error) {
	if _, err := a.Get(ctx, name); err != nil {
		return "", err
	}
	return a.itemHostPairName(name) + ".crt", nil
}

func (a *apis) APIServices(name string) APIServices {
	return &apiAPIServices{
		apis: *a,
		name: name,
	}
}

type apiAPIServices struct {
	apis apis
	name string
}

func (a *apiAPIServices) Apply(ctx context.Context, svcName, host string, port int32, apiServices []*apiregistrationv1.APIService) error {
	c, err := a.getClient(ctx)
	if err != nil {
		return err
	}

	aggregatedServiceCAPair, err := certutil.ReadPairFiles(a.apis.itemHostCAPairName(a.name))
	if err != nil {
		return fmt.Errorf("error reading aggregated service ca certificate: %w", err)
	}

	aggregatedServiceCABytes, err := aggregatedServiceCAPair.CertBytes()
	if err != nil {
		return fmt.Errorf("error getting aggregated service ca bytes: %w", err)
	}

	svc := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceSystem,
			Name:      svcName,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: host,
		},
	}
	if err := c.Patch(ctx, svc, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("error applying service %s: %w", svcName, err)
	}

	for _, apiService := range apiServices {
		apiService.TypeMeta = metav1.TypeMeta{
			APIVersion: apiregistrationv1.SchemeGroupVersion.String(),
			Kind:       "APIService",
		}
		_, err := ctrl.CreateOrUpdate(ctx, c, apiService, func() error {
			metav1.SetMetaDataLabel(&apiService.ObjectMeta, serviceOwnerLabel, string(svc.UID))
			apiService.Spec.CABundle = aggregatedServiceCABytes
			apiService.Spec.Service = &apiregistrationv1.ServiceReference{
				Namespace: metav1.NamespaceSystem,
				Name:      svcName,
				Port:      pointer.Int32(port),
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("[apiservice %s] error applying: %w", apiService.Name, err)
		}
	}
	return nil
}

func (a *apiAPIServices) Delete(ctx context.Context, svcName string) error {
	c, err := a.getClient(ctx)
	if err != nil {
		return err
	}

	svc := &corev1.Service{}
	svcKey := client.ObjectKey{Namespace: metav1.NamespaceSystem, Name: svcName}
	if err := c.Get(ctx, svcKey, svc); err != nil {
		return fmt.Errorf("error getting service %s: %w", svcName, err)
	}

	apiServiceList := &apiregistrationv1.APIServiceList{}
	if err := c.List(ctx, apiServiceList,
		client.MatchingLabels{
			serviceOwnerLabel: string(svc.UID),
		},
	); err != nil {
		return fmt.Errorf("error listing api services for service %s: %w", svcName, err)
	}

	var errs []error
	for _, apiService := range apiServiceList.Items {
		if err := c.Delete(ctx, &apiService); client.IgnoreNotFound(err) != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("error(s) deleting api services: %v", errs)
	}

	if err := c.Delete(ctx, svc); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("error deleting service %s: %w", svcName, err)
	}
	return nil
}

func (a *apiAPIServices) getClient(ctx context.Context) (client.Client, error) {
	kubeCfg, err := a.apis.Kubeconfig(ctx, a.name)
	if err != nil {
		return nil, fmt.Errorf("error obtaining kubeconfig: %w", err)
	}

	restCfg, err := clientcmd.NewDefaultClientConfig(*kubeCfg, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error getting rest config: %w", err)
	}

	c, err := client.New(restCfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}
	return c, nil
}

func ExportHostCertificate(ctx context.Context, apis APIs, name string, dir string) error {
	pair, err := apis.HostCertificate(ctx, name)
	if err != nil {
		return fmt.Errorf("error getting host service certificate: %w", err)
	}

	if err := certutil.WritePairFiles(pair, filepath.Join(dir, "tls")); err != nil {
		return fmt.Errorf("error writing pair files: %w", err)
	}
	return nil
}

func ExportKubeconfig(ctx context.Context, apis APIs, name string, kubeCfg *clientcmdapi.Config) (*clientcmdapi.Config, error) {
	override, err := apis.Kubeconfig(ctx, name)
	if err != nil {
		return nil, err
	}

	return kubeconfigs.Merge(kubeCfg, override)
}

func ExportKubeconfigFile(ctx context.Context, apis APIs, name, filename string) error {
	kubeCfg, err := clientcmd.LoadFromFile(filename)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("error loading kubeconfig %s: %w", filename, err)
		}

		kubeCfg = clientcmdapi.NewConfig()
	}

	kubeCfg, err = ExportKubeconfig(ctx, apis, name, kubeCfg)
	if err != nil {
		return fmt.Errorf("error exporting kubeconfig: %w", err)
	}

	return clientcmd.WriteToFile(*kubeCfg, filename)
}

type RunAPIOptions struct {
	Remove             bool
	KubeconfigFilename string
}

func RunAPI(ctx context.Context, apis APIs, api *v1alpha1.API, opts RunAPIOptions) error {
	log := ctrl.LoggerFrom(ctx)
	var cleanup []func()
	defer func() {
		for _, f := range cleanup {
			f()
		}
	}()

	api, err := apis.Create(ctx, api)
	if err != nil {
		return fmt.Errorf("error creating api: %w", err)
	}
	if opts.Remove {
		cleanup = append(cleanup, func() {
			if err := apis.Delete(ctx, api.Name); err != nil {
				log.Error(err, "Error deleting api after start failed")
			}
		})
	}

	handle, err := apis.Start(ctx, api.Name)
	if err != nil {
		return err
	}
	cleanup = append(cleanup, func() {
		if err := handle.Stop(); err != nil {
			log.Error(err, "Error stopping api")
		}
	})

	if err := ExportKubeconfigFile(ctx, apis, api.Name, opts.KubeconfigFilename); err != nil {
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
