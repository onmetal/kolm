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

package common

import (
	"os"
	"path/filepath"

	kolm "github.com/onmetal/kolm"
	"k8s.io/client-go/tools/clientcmd"
)

type GetKolm = func() (kolm.Kolm, error)

func DetermineKubeconfig(kubeconfig string) string {
	if kubeconfig == "" {
		if envVar := os.Getenv(clientcmd.RecommendedConfigPathEnvVar); envVar != "" {
			kubeconfig = envVar
		} else if homeDir, _ := os.UserHomeDir(); homeDir != "" {
			kubeconfig = filepath.Join(homeDir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
		}
	}
	return kubeconfig
}
