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

package apiserver

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/onmetal/kolm/process"
)

type Options struct {
	Command []string
	Dir     string

	ETCDServers                []string
	ServerCertPairName         string
	CAPairName                 string
	ServiceAccountCertPairName string
	ProxyCAPairName            string
	ProxyClientPairName        string

	Host string
	Port int32

	Stdout io.Writer
	Stderr io.Writer

	ReadyTimeout time.Duration
	StopTimeout  time.Duration
}

func setOptionsDefaults(o *Options) {
	if len(o.Command) == 0 {
		o.Command = []string{"kube-apiserver"}
	}
}

type APIServer struct {
	*process.Process
}

func Start(opts Options) (*APIServer, error) {
	setOptionsDefaults(&opts)

	cmd, err := createCommand(opts)
	if err != nil {
		return nil, err
	}

	p, err := process.Start(cmd, createReadyFunc(opts), process.Options{
		ReadyTimeout: opts.ReadyTimeout,
		StopTimeout:  opts.StopTimeout,
	})
	if err != nil {
		return nil, err
	}

	return &APIServer{p}, nil
}

func createCommand(opts Options) (*exec.Cmd, error) {
	cmd, err := process.Command(opts.Command,
		"--etcd-servers", strings.Join(opts.ETCDServers, ","),

		"--client-ca-file", opts.CAPairName+".crt",

		"--tls-cert-file", opts.ServerCertPairName+".crt",
		"--tls-private-key-file", opts.ServerCertPairName+".key",

		"--service-account-key-file", opts.ServiceAccountCertPairName+".crt",
		"--service-account-signing-key-file", opts.ServiceAccountCertPairName+".key",
		"--service-account-issuer", fmt.Sprintf("https://%s:%d", opts.Host, opts.Port),

		fmt.Sprintf("--secure-port=%d", opts.Port),

		"--authorization-mode", "RBAC",

		"--service-cluster-ip-range", "10.0.0.0/24",
		"--allow-privileged",
		"--disable-admission-plugins", "ServiceAccount",

		"--proxy-client-key-file", opts.ProxyClientPairName+".key",
		"--proxy-client-cert-file", opts.ProxyClientPairName+".crt",

		"--requestheader-client-ca-file", opts.ProxyCAPairName+".crt",
		"--requestheader-allowed-names", "kolm,localhost",
		"--requestheader-extra-headers-prefix", "X-Remote-Extra-",
		"--requestheader-group-headers", "X-Remote-Group",
		"--requestheader-username-headers", "X-Remote-User",
	)
	if err != nil {
		return nil, err
	}

	cmd.Dir = opts.Dir
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	return cmd, nil
}

func createReadyFunc(opts Options) process.ReadyFunc {
	return process.InsecureHTTPGetOKReadyCheck(fmt.Sprintf("https://%s:%d/readyz", opts.Host, opts.Port))
}
