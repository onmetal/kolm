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
	"fmt"

	kolm "github.com/onmetal/kolm"
	"github.com/onmetal/kolm/cli/kolm/common"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Options struct {
	Name string
}

func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Name, "name", kolm.DefaultName, "Name of the api to delete.")
}

func Command(getKolm common.GetKolm) *cobra.Command {
	var opts Options

	cmd := &cobra.Command{
		Use:   "api",
		Short: "Delete a local Kubernetes API.",
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

func Run(ctx context.Context, l kolm.Kolm, opts Options) error {
	log := ctrl.LoggerFrom(ctx)

	if err := l.Delete(ctx, opts.Name); err != nil {
		return fmt.Errorf("error deleting %s: %w", opts.Name, err)
	}

	log.Info("Successfully deleted", "Name", opts.Name)
	return nil
}
