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

package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	kolm "github.com/onmetal/kolm"
	"github.com/onmetal/kolm/api/v1alpha1/helper"
	"github.com/onmetal/kolm/cli/kolm/common"
	"github.com/onmetal/kolm/tableconvertor"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/printers"
)

type Options struct {
	Output outputFormat
}

type outputFormat string

const (
	outputFormatJSON    outputFormat = "json"
	outputFormatYAML    outputFormat = "yaml"
	outputFormatDefault outputFormat = ""
)

func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVarP((*string)(&o.Output), "format", "o", string(outputFormatDefault), "Output format to print the items in. One of json, yaml or \"\" (default format).")
}

func Command(getKolm common.GetKolm) *cobra.Command {
	var opts Options

	cmd := &cobra.Command{
		Use:   "apis",
		Short: "List existing local Kubernetes apis by their name.",
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

var tablePrinter = printers.NewTablePrinter(printers.PrintOptions{})

func Run(ctx context.Context, l kolm.Kolm, opts Options) error {
	res, err := l.List(ctx)
	if err != nil {
		return fmt.Errorf("error listing: %w", err)
	}

	switch opts.Output {
	case outputFormatDefault:
		tab, err := tableconvertor.ConvertAPIToTable(res)
		if err != nil {
			return err
		}
		return tablePrinter.PrintObj(tab, os.Stdout)
	case outputFormatJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	case outputFormatYAML:
		return helper.Codec.Encode(res, os.Stdout)
	default:
		return fmt.Errorf("invalid format %q", opts.Output)
	}
}
