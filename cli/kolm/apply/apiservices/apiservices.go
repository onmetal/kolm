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

package apiservices

import (
	"context"
	"fmt"

	"github.com/onmetal/kolm"
	"github.com/onmetal/kolm/apiservices"
	"github.com/onmetal/kolm/cli/kolm/common"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Options struct {
	APIName string
	Name    string
	Host    string
	Port    int32
}

func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.APIName, "api-name", "a", kolm.DefaultName, "Name of the api whose API services to modify.")
	fs.StringVar(&o.Name, "name", kolm.DefaultName, "Name of the service owner to create.")
	fs.StringVar(&o.Host, "host", "localhost", "Host where the aggregated service will be running.")
	fs.Int32Var(&o.Port, "port", 6443, "Port the aggregated service is running on.")
}

func Command(getKolm common.GetKolm) *cobra.Command {
	var opts Options

	cmd := &cobra.Command{
		Args: cobra.MinimumNArgs(1),
		Use:  "apiservices <paths...>",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			k, err := getKolm()
			if err != nil {
				return err
			}

			return Run(ctx, k, args, opts)
		},
	}

	opts.AddFlags(cmd.Flags())

	return cmd
}

func Run(ctx context.Context, k kolm.Kolm, paths []string, opts Options) error {
	apiServices, err := apiservices.Render(apiservices.RenderOptions{
		Paths:              paths,
		ErrorIfPathMissing: false,
	})
	if err != nil {
		return fmt.Errorf("error rendering api services: %w", err)
	}

	if err := k.APIs().APIServices(opts.APIName).Apply(ctx, opts.Name, opts.Host, opts.Port, apiServices); err != nil {
		return fmt.Errorf("error applying api services: %w", err)
	}

	return nil
}
