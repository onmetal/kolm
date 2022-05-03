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

package etcd

import (
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/onmetal/kolm/process"
)

type ETCD struct {
	*process.Process
}

type Options struct {
	Command []string
	Dir     string

	Host string
	Port int32

	PeerHost string
	PeerPort int32

	Stdout io.Writer
	Stderr io.Writer

	ReadyTimeout       time.Duration
	ReadyCheckInterval time.Duration
	StopTimeout        time.Duration
}

func setOptionsDefaults(o *Options) {
	if len(o.Command) == 0 {
		o.Command = []string{"etcd"}
	}
}

func Start(opts Options) (*ETCD, error) {
	setOptionsDefaults(&opts)

	cmd, err := createCmd(opts)
	if err != nil {
		return nil, err
	}

	p, err := process.Start(cmd, createReadyFunc(opts), process.Options{
		ReadyTimeout:       opts.ReadyTimeout,
		ReadyCheckInterval: opts.ReadyCheckInterval,
		StopTimeout:        opts.StopTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &ETCD{p}, nil
}

func createCmd(opts Options) (*exec.Cmd, error) {
	address := fmt.Sprintf("http://%s:%d", opts.Host, opts.Port)
	peerAddress := fmt.Sprintf("http://%s:%d", opts.PeerHost, opts.PeerPort)
	cmd, err := process.Command(opts.Command,
		"--logger", "zap",
		"--advertise-client-urls", address,
		"--listen-client-urls", address,
		"--initial-cluster", fmt.Sprintf("default=%s", peerAddress),
		"--initial-advertise-peer-urls", peerAddress,
		"--listen-peer-urls", peerAddress,
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
	return process.InsecureHTTPGetOKReadyCheck(fmt.Sprintf("http://%s:%d/health", opts.Host, opts.Port))
}
