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

package process

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

func Command(command []string, args ...string) (*exec.Cmd, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("must specify at least 1 command")
	}

	actualCommand := command[0]

	var actualArgs []string
	if len(command) > 1 {
		actualArgs = append(args, command[1:]...)
	}
	actualArgs = append(actualArgs, args...)

	return exec.Command(actualCommand, actualArgs...), nil
}

type Options struct {
	ReadyTimeout       time.Duration
	ReadyCheckInterval time.Duration
	StopTimeout        time.Duration
}

func setOptionsDefaults(o *Options) {
	if o.ReadyTimeout <= 0 {
		o.ReadyTimeout = 20 * time.Second
	}
	if o.ReadyCheckInterval <= 0 {
		o.ReadyCheckInterval = 100 * time.Millisecond
	}
	if o.StopTimeout <= 0 {
		o.StopTimeout = 20 * time.Second
	}
}

type ReadyFunc = func(ctx context.Context) bool

type Process struct {
	exitMu sync.Mutex

	cmd         *exec.Cmd
	waitDone    chan struct{}
	exited      bool
	exitErr     error
	stopTimeout time.Duration
}

func (a *Process) Wait() error {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.waitDone:
			return a.exitErr
		case <-t.C:
			if ok, err := a.Exited(); ok {
				return err
			}
		}
	}
}

func (a *Process) Exited() (bool, error) {
	a.exitMu.Lock()
	defer a.exitMu.Unlock()
	return a.exited, a.exitErr
}

func (a *Process) Stop() error {
	if exited, _ := a.Exited(); exited {
		return nil
	}

	if err := a.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("error signaling process to stop: %w", err)
	}

	timeout := time.NewTimer(a.stopTimeout)
	defer timeout.Stop()

	select {
	case <-a.waitDone:
		return nil
	case <-timeout.C:
		return fmt.Errorf("timeout waiting for process to stop")
	}
}

func Start(cmd *exec.Cmd, readyFunc ReadyFunc, opts Options) (*Process, error) {
	setOptionsDefaults(&opts)
	if cmd == nil {
		return nil, fmt.Errorf("must specify cmd")
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error running command: %w", err)
	}

	srv := &Process{
		cmd:         cmd,
		waitDone:    make(chan struct{}),
		stopTimeout: opts.StopTimeout,
	}
	go func() {
		defer close(srv.waitDone)

		err := cmd.Wait()

		srv.exitMu.Lock()
		defer srv.exitMu.Unlock()

		srv.exitErr = err
		srv.exited = true
	}()
	var (
		ready               = make(chan struct{})
		pollCtx, cancelPoll = context.WithCancel(context.Background())
	)
	defer cancelPoll()
	go func() {
		ok := pollUntilReady(pollCtx, readyFunc, 100*time.Millisecond)
		if ok {
			close(ready)
		}
	}()

	timeout := time.NewTimer(opts.ReadyTimeout)
	defer timeout.Stop()

	select {
	case <-srv.waitDone:
		cancelPoll()
		if srv.exitErr != nil {
			return nil, fmt.Errorf("process exited early with error: %w", srv.exitErr)
		}
		return nil, fmt.Errorf("process exited early without error")
	case <-timeout.C:
		cancelPoll()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		return nil, fmt.Errorf("timed out waiting for process to become ready")
	case <-ready:
		return srv, nil
	}
}

func pollUntilReady(ctx context.Context, readyFunc ReadyFunc, interval time.Duration) bool {
	for {
		ready, done := func() (ready, done bool) {
			if readyFunc(ctx) {
				return true, true
			}

			interval := time.NewTicker(interval)
			defer interval.Stop()

			select {
			case <-ctx.Done():
				return false, true
			case <-interval.C:
				return false, false
			}
		}()
		if done {
			return ready
		}
	}
}

func CheckHTTPDo(expectedStatusCode int) func(res *http.Response, err error) bool {
	return func(res *http.Response, err error) bool {
		if err != nil {
			return false
		}
		_ = res.Body.Close()
		return res.StatusCode == expectedStatusCode
	}
}

func HTTPGetOKReadyCheck(address string) ReadyFunc {
	check := CheckHTTPDo(http.StatusOK)
	return func(ctx context.Context) bool {
		return check(http.Get(address))
	}
}

var insecureHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func InsecureHTTPGetOKReadyCheck(address string) ReadyFunc {
	check := CheckHTTPDo(http.StatusOK)
	return func(ctx context.Context) bool {
		return check(insecureHTTPClient.Get(address))
	}
}
