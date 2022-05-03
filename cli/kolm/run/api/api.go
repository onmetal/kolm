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

package api

import (
	"context"

	kolm "github.com/onmetal/kolm"
	"github.com/onmetal/kolm/api/v1alpha1"
	"github.com/onmetal/kolm/cli/kolm/common"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Options struct {
	Name string

	CertificateCommonName   string
	CertificateOrganization []string

	APIServerHost       string
	APIServerSecurePort int32

	Remove     bool
	Kubeconfig string
}

func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Name, "name", kolm.DefaultName, "Name of the api to create.")

	fs.StringVar(&o.CertificateCommonName, "certificate-common-name", "test", "Common name to use for all certificates.")
	fs.StringSliceVar(&o.CertificateOrganization, "certificate-organization", []string{"test"}, "Organization to use for all certificates.")

	fs.StringVar(&o.APIServerHost, "apiserver-host", "", "Host to run the api server on. If unspecified, localhost will be used.")
	fs.Int32Var(&o.APIServerSecurePort, "apiserver-port", 0, "Port to run the api server on. If unspecified, a dynamic port will be allocated.")

	fs.BoolVar(&o.Remove, "rm", false, "Remove api after running it.")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", "", "The kubeconfig file to modify instead of KUBECONFIG or HOME/.kube/config.")
}

func Command(getKolm common.GetKolm) *cobra.Command {
	var opts Options

	cmd := &cobra.Command{
		Use:   "api",
		Short: "Create and start (optionally delete) a local Kubernetes API.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			l, err := getKolm()
			if err != nil {
				return err
			}

			return Run(ctx, l, opts)
		},
	}

	opts.AddFlags(cmd.Flags())

	return cmd
}

func Run(ctx context.Context, k kolm.Kolm, opts Options) error {
	kubeconfigFilename := common.DetermineKubeconfig(opts.Kubeconfig)

	return kolm.Run(ctx, k,
		&v1alpha1.API{
			ObjectMeta: metav1.ObjectMeta{
				Name: opts.Name,
			},
			Certs: v1alpha1.APICerts{
				CommonName:   opts.CertificateCommonName,
				Organization: opts.CertificateOrganization,
			},
			ETCD: v1alpha1.APIETCD{},
			APIServer: v1alpha1.APIAPIServer{
				Host: opts.APIServerHost,
				Port: opts.APIServerSecurePort,
			},
		},
		kolm.RunOptions{
			Remove:             opts.Remove,
			KubeconfigFilename: kubeconfigFilename,
		},
	)
}
