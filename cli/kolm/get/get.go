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

package get

import (
	"fmt"

	"github.com/onmetal/kolm/cli/kolm/common"
	"github.com/onmetal/kolm/cli/kolm/get/apis"
	"github.com/onmetal/kolm/cli/kolm/get/kubeconfig"
	"github.com/spf13/cobra"
)

func Command(getKolm common.GetKolm) *cobra.Command {
	cmd := &cobra.Command{
		Use: "get",
	}

	subCommands := []*cobra.Command{
		apis.Command(getKolm),
		kubeconfig.Command(getKolm),
	}
	names := make([]string, 0, len(subCommands))
	for _, subCommand := range subCommands {
		cmd.AddCommand(subCommand)
		names = append(names, subCommand.Name())
	}

	cmd.Short = fmt.Sprintf("Gets one of %v", names)

	return cmd
}
