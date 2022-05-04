/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package addr

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type PortCache struct {
	mu      sync.Mutex
	wg      sync.WaitGroup
	started bool

	entries map[int32]struct{}

	done     chan struct{}
	requests chan request
	releases chan release
}

func (p *PortCache) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return fmt.Errorf("already started")
	}

	p.started = true

	p.entries = make(map[int32]struct{})

	p.done = make(chan struct{})
	p.requests = make(chan request)
	p.releases = make(chan release)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.loop()
	}()
	return nil
}

func (p *PortCache) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return fmt.Errorf("not started")
	}

	p.started = false

	// Signal loop to stop and wait for its termination
	close(p.done)
	p.wg.Wait()

	p.entries = nil

DrainRequests:
	for {
		select {
		case req := <-p.requests:
			select {
			case req.result <- result{err: fmt.Errorf("stopped")}:
			default:
			}
		default:
			break DrainRequests
		}
	}
	close(p.requests)

DrainReleases:
	for {
		select {
		case rel := <-p.releases:
			close(rel.released)
		default:
			break DrainReleases
		}
	}
	close(p.releases)

	return nil
}

func (p *PortCache) loop() {
	for {
		select {
		case <-p.done:
			return
		case release := <-p.releases:
			delete(p.entries, release.port)
			close(release.released)
		case req := <-p.requests:
			if res := p.tryRequest(req); res != nil {
				req.result <- *res
			}
		}
	}
}

const maxPortRetry = 100

func (p *PortCache) tryRequest(req request) *result {
	var i int
	for {
		select {
		case <-req.done:
			return nil
		default:
			if i >= maxPortRetry {
				return &result{
					err: fmt.Errorf("maximum port tries exceeded"),
				}
			}
			i++

			listener, port, ip, err := suggest(req.listenHost)
			if err != nil {
				return &result{err: err}
			}
			// We intentionally defer in the for loop to keep the listeners
			// until we find a free port.
			defer func() { _ = listener.Close() }()

			if _, ok := p.entries[port]; ok {
				continue
			}

			p.entries[port] = struct{}{}
			return &result{
				port:    port,
				ip:      ip,
				release: p.releaseFor(port),
			}
		}
	}
}

func (p *PortCache) releaseFor(port int32) func() error {
	return func() error {
		p.mu.Lock()
		defer p.mu.Unlock()

		if !p.started {
			return nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		released := make(chan struct{})

		p.releases <- release{ctx.Done(), port, released}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-released:
			return nil
		}
	}
}

type release struct {
	done     <-chan struct{}
	port     int32
	released chan<- struct{}
}

type Port struct {
	Port    int32
	IP      string
	release func() error
}

func (p *Port) Release() error {
	return p.release()
}

func (p *PortCache) trySendRequest(ctx context.Context, listenHost string) (chan result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return nil, fmt.Errorf("not started")
	}

	result := make(chan result, 1)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case p.requests <- request{ctx.Done(), listenHost, result}:
		return result, nil
	}
}

func (p *PortCache) Suggest(listenHost string) (*Port, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	result, err := p.trySendRequest(ctx, listenHost)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout suggesting: %w", ctx.Err())
	case res := <-result:
		if err := res.err; err != nil {
			return nil, fmt.Errorf("error suggesting: %w", err)
		}

		return &Port{res.port, res.ip, res.release}, nil
	}
}

type request struct {
	done       <-chan struct{}
	listenHost string
	result     chan<- result
}

type result struct {
	port    int32
	ip      string
	release func() error

	err error
}

func suggest(listenHost string) (*net.TCPListener, int32, string, error) {
	if listenHost == "" {
		listenHost = "localhost"
	}
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(listenHost, "0"))
	if err != nil {
		return nil, -1, "", err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, -1, "", err
	}
	return l, int32(l.Addr().(*net.TCPAddr).Port),
		addr.IP.String(),
		nil
}

func NewPortCache() *PortCache {
	return &PortCache{}
}
