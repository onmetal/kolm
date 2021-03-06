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

package main

import (
	"fmt"
	"os"

	kolm "github.com/onmetal/kolm/cli/kolm"
	"github.com/onmetal/kolm/logger"
	ctrl "sigs.k8s.io/controller-runtime"
)

func main() {
	log := logger.NewLogger(os.Stderr, 10)
	ctx := ctrl.LoggerInto(ctrl.SetupSignalHandler(), log)

	cmd := kolm.Command()
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Println("Error running", cmd.Name())
		fmt.Println(err)
		os.Exit(1)
	}
}
