# vault-kube-cloud-credentials

[![Build Status](https://drone.prod.merit.uw.systems/api/badges/utilitywarehouse/vault-kube-cloud-credentials/status.svg)](https://drone.prod.merit.uw.systems/utilitywarehouse/vault-kube-cloud-credentials)

This is a system for retrieving cloud IAM credentials from Vault for use in
Kubernetes.

It's comprised of two parts:

- An operator which will create a login role and a secret in Vault based on
  service account annotations
- A sidecar which retrieves the credentials from vault and serves them over
  http, acting as a metadata endpoint for the given cloud provider

## Operator

### Requirements

- A Vault server with:
  - Kubernetes auth method, enabled and configured
  - One of, or both:
    - AWS secrets engine, enabled and configured
    - GCP secrets engine, enabled and configured

### Usage

Refer to the [example](manifests/operator/) for a reference Kubernetes deployment.

Annotate your service accounts and the operator will create the corresponding
login role and a role under the corresponding secret backend.

#### AWS

Associate a service account with an AWS IAM role.

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: foobar
  annotations:
    vault.uw.systems/aws-role: "arn:aws:iam::000000000000:role/some-role-name"
```

#### GCP

Attach roleset bindings to a service account in a particular project. Refer to
the [Vault docs] (https://www.vaultproject.io/docs/secrets/gcp#roleset-bindings)
for examples of valid bindings.

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: foobar
  annotations:
    vault.uw.systems/gcp-project: "my-project"
    vault.uw.systems/gcp-bindings: |
      "//cloudresourcemanager.googleapis.com/projects/my-project":
        - "roles/dns.admin"
        - "roles/storage.admin"
```

### Config file

The operator is configured by a yaml file passed to the operator with the
flag `-config-file`.

Any omitted fields will inherit from the defaults below. At least one backend
(`aws`, `gcp`) must be enabled.

```
# The mount path of the kubernetes auth backend
kubernetesAuthBackend: "kubernetes"

# The address that operator metrics will be served on
metricsAddress: ":8080"

# The prefix that will be appended to objects created in Vault by the operator
prefix: "vkcc"

# Configuration for the AWS secret backend
aws:
  # Enable the AWS backend
  enabled: false

  # The default TTL of the credentials issued for a role
  defaultTTL: 15m

  # The mount path of the AWS secret backend
  path: "aws"

  # Rules that govern which service accounts can assume which roles
  rules: []

# Configuration for the GCP secret backend
gcp:
  # Enable the GCP backend
  enabled: false

  # The mount path of the GCP secret backend
  path: "gcp"

  # Rules that govern which service accounts can create bindings in which
  # projects
  rules: []
```

#### AWS Rules

The following configuration allows service accounts in `kube-system`
and namespaces prefixed with `system-` to assume roles under the `sysadmin/*` path,
roles that begin with `sysadmin-` or a specific `org/s3-admin` role in the accounts
`000000000000` and `111111111111`.

```
aws:
  rules:
    - namespacePatterns:
        - kube-system
        - system-*
      roleNamePatterns:
       - sysadmin-*
       - sysadmin/*
       - org/s3-admin
      accountIDs:
        - 000000000000
        - 111111111111
```

If `accountIDs` is omitted or empty then any account is permitted. The other two
parameters are required.

The pattern matching supports [shell file name
patterns](https://golang.org/pkg/path/filepath/#Match).

#### GCP Rules

The following configuration allows service accounts in `kube-system` and
namespaces prefixed with `system-` to create bindings in the project
`my-project`.

```
gcp:
  rules:
    - namespacePatterns:
        - kube-system
        - system-*
      projects:
        - my-project
```


The pattern matching supports [shell file name
patterns](https://golang.org/pkg/path/filepath/#Match).

## Sidecars

### Usage

Refer to the [examples](manifests/examples/) for reference Kubernetes deployments.

Supported providers (secret engines):

- `aws`
- `gcp`

For `aws`:

```
./vault-kube-cloud-credentials aws-sidecar
```

And `gcp`:

```
./vault-kube-cloud-credentials gcp-sidecar
```

Refer to the usage for more options:

```
./vault-kube-cloud-credentials -h
```

Additionally, you can use any of the [environment variables supported by the Vault
client](https://www.vaultproject.io/docs/commands/#environment-variables), most
applicably:

- `VAULT_ADDR`: the address of the Vault server (default: `https://127.0.0.1:8200`)
- `VAULT_CACERT`: path to a CA certificate file used to verify the Vault server's certificate

### Renewal

The sidecar will retrieve new credentials after 1/3 of the current TTL has
elapsed. So, if the credentials are valid for an hour then the sidecar will
attempt to fetch a new set after about 20 minutes. A random jitter is applied
to the refresh period to avoid tight synchronisation between multiple sidecar 
instances.

If the refresh fails then the sidecar will continue to make attempts at renewal,
with an exponential backoff.
