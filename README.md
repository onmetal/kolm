# kolm - Kubernetes on your local machine

[![Pull Request Code test](https://github.com/onmetal/kolm/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/onmetal/kolm/actions/workflows/test.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com)
[![GitHub License](https://img.shields.io/static/v1?label=License&message=Apache-2.0&color=blue&style=flat-square)](LICENSE)

kolm is a tool for running a Kubernetes 'cluster' consisting of an `etcd` and a `kube-apiserver` on your local
machine. The primary use of kolm is for testing aggregated api servers, as debugging aggregated api servers
in-cluster is a complex and troublesome task.

> ⚠️ kolm is a *testing-only* tool. Practices employed in this tool are inherently unsafe and should
> never be used in production and is plumbing-only.

## Installation

To install kolm, simply run

```shell
go install github.com/onmetal/kolm/cmd/kolm@latest
```

> 👆 For now, kolm also requires `etcd` and `kube-apiserver` to be on your path.
> This will change in the future with automated binary management but wasn't implemented
> in the initial scope.

## Usage

### Controlling your `api`s

kolm has the primary type called `api`. An `api` is the previously mentioned 'cluster' with only a
`kube-apiserver` and `etcd`.

The create such an `api`, simply run

```shell
kolm create api
```

This will create an `api` called `kolm`. Your kubeconfig will be modified to contain an entry pointing
towards the new `kolm` cluster.

Once created, you can now start the `api`:

```shell
kolm start api
```

This runs the `etcd` and `kube-apiserver`. Both are running until terminated or the user interrupts via
`ctrl-c`.

To remove an `api`, simply run

```shell
kolm delete api
```

All the previously described steps can also be done in a one-shot manner with:

```shell
kolm run api --rm
```

### Using your `api` with an aggregated api server

If you have an aggregated api server & its `APIService`s at hand, you can let them 'join' your `api`.
To do so, in a new terminal, first install your `APIService`s:

```shell
kolm apply apiservices <path-to-apiservices-directory>
```

Then, start your api server with flags similar to the following:

```shell
<my-server> \
  --etcd-servers=$(kolm get etcd-address) \
  --kubeconfig=$HOME/.kube/config \
  --authentication-kubeconfig=$HOME/.kube/config \
  --authorization-kubeconfig=$HOME/.kube/config \
  --tls-private-key-file $(kolm get host-key) \
  --tls-cert-file $(kolm get host-cert) \
  --secure-port=6443 \
  --feature-gates=APIPriorityAndFairness=false
```

After a short while, your api server should have joined the `api`.
