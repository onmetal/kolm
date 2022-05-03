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

package kubeconfigs

import (
	"crypto/x509"

	"github.com/onmetal/kolm/certutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func New(name, server string, caCert *x509.Certificate, certPair *certutil.Pair) (*clientcmdapi.Config, error) {
	caData, err := certutil.EncodeCertificate(caCert)
	if err != nil {
		return nil, err
	}

	certBytes, keyBytes, err := certPair.Bytes()
	if err != nil {
		return nil, err
	}

	return &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			name: {
				Server:                   server,
				CertificateAuthorityData: caData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			name: {
				ClientCertificateData: certBytes,
				ClientKeyData:         keyBytes,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			name: {
				Cluster:   name,
				AuthInfo:  name,
				Namespace: corev1.NamespaceDefault,
			},
		},
		CurrentContext: name,
	}, nil
}

func Merge(base, override *clientcmdapi.Config) (*clientcmdapi.Config, error) {
	res := base.DeepCopy()

	if res.Clusters == nil && len(override.Clusters) > 0 {
		res.Clusters = make(map[string]*clientcmdapi.Cluster)
	}
	for name, cluster := range override.Clusters {
		res.Clusters[name] = cluster
	}

	if res.AuthInfos == nil && len(override.AuthInfos) > 0 {
		res.AuthInfos = make(map[string]*clientcmdapi.AuthInfo)
	}
	for name, authInfo := range override.AuthInfos {
		res.AuthInfos[name] = authInfo
	}

	if res.Contexts == nil && len(override.Contexts) > 0 {
		res.Contexts = make(map[string]*clientcmdapi.Context)
	}
	for name, context := range override.Contexts {
		res.Contexts[name] = context
	}

	if override.CurrentContext != "" {
		res.CurrentContext = override.CurrentContext
	}

	if res.Extensions == nil && len(override.Extensions) > 0 {
		res.Extensions = make(map[string]runtime.Object)
	}
	for name, extension := range override.Extensions {
		res.Extensions[name] = extension
	}

	return res, nil
}

func MergeFile(filename string, override *clientcmdapi.Config) error {
	kubeCfg, err := clientcmd.LoadFromFile(filename)
	if err != nil {
		return err
	}

	merged, err := Merge(kubeCfg, override)
	if err != nil {
		return err
	}

	return clientcmd.WriteToFile(*merged, filename)
}

func Prune(kubeCfg *clientcmdapi.Config, name string) (*clientcmdapi.Config, error) {
	kubeCfg = kubeCfg.DeepCopy()

	delete(kubeCfg.Clusters, name)
	delete(kubeCfg.Contexts, name)
	delete(kubeCfg.AuthInfos, name)

	if len(kubeCfg.Contexts) > 0 {
		var name string
		for contextName := range kubeCfg.Contexts {
			if name == "" || contextName > name {
				name = contextName
			}
		}

		kubeCfg.CurrentContext = name
	} else {
		kubeCfg.CurrentContext = ""
	}

	return kubeCfg, nil
}

func PruneFile(filename string, name string) error {
	kubeCfg, err := clientcmd.LoadFromFile(filename)
	if err != nil {
		return err
	}

	pruned, err := Prune(kubeCfg, name)
	if err != nil {
		return err
	}

	return clientcmd.WriteToFile(*pruned, filename)
}
