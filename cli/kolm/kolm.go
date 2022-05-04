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
	"fmt"
	"os"
	"path/filepath"

	kolm "github.com/onmetal/kolm"
	"github.com/onmetal/kolm/cli/kolm/apply"
	"github.com/onmetal/kolm/cli/kolm/common"
	"github.com/onmetal/kolm/cli/kolm/create"
	"github.com/onmetal/kolm/cli/kolm/delete"
	"github.com/onmetal/kolm/cli/kolm/export"
	"github.com/onmetal/kolm/cli/kolm/get"
	"github.com/onmetal/kolm/cli/kolm/run"
	"github.com/onmetal/kolm/cli/kolm/start"
	"github.com/spf13/cobra"
)

var (
	defaultKolmRootDir string
)

func init() {
	if kolmRootDir := os.Getenv("KOLM_ROOT_DIR"); kolmRootDir != "" {
		defaultKolmRootDir = kolmRootDir
	} else {
		dirname, err := os.UserHomeDir()
		if err == nil {
			defaultKolmRootDir = filepath.Join(dirname, ".kolm")
		}
	}
}

func Command() *cobra.Command {
	var kolmRootDir string

	cmd := &cobra.Command{
		Use: "kolm",
	}

	getKolm := newGetKolm(&kolmRootDir)

	cmd.AddCommand(
		apply.Command(getKolm),
		create.Command(getKolm),
		delete.Command(getKolm),
		get.Command(getKolm),
		start.Command(getKolm),
		run.Command(getKolm),
		export.Command(getKolm),
	)

	cmd.PersistentFlags().StringVar(&kolmRootDir, "kolm-root-dir", defaultKolmRootDir, "Root directory for kolm storage")

	return cmd
}

func newGetKolm(kolmRootDir *string) common.GetKolm {
	return func() (kolm.Kolm, error) {
		dir := *kolmRootDir
		if dir == "" {
			return nil, fmt.Errorf("must specify kolm-root-dir")
		}

		return kolm.New(dir)
	}
}
