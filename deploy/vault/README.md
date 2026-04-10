# Vault Integration for OpenRange

Optional HashiCorp Vault integration for managing secrets (LLM API keys,
database passwords, LDAP credentials) instead of storing them as plaintext
environment variables.

OpenRange works without Vault. When Vault is not configured, the system
falls back to environment variables and built-in defaults.

## Quick Start (Local Development)

### 1. Start Vault in dev mode

Using the bootstrap script (requires the `vault` CLI):

```bash
VAULT_DEV_MODE=true ./deploy/vault/bootstrap-vault.sh
```

Or manually:

```bash
vault server -dev -dev-root-token-id=dev-root-token &
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token
./deploy/vault/bootstrap-vault.sh
```

### 2. Seed an LLM API key (optional)

```bash
export OPENRANGE_LLM_API_KEY="sk-your-key-here"
export OPENRANGE_LLM_API_KEY_NAME="OPENAI_API_KEY"   # default
./deploy/vault/bootstrap-vault.sh
```

Or write directly:

```bash
vault kv put secret/openrange/llm-api-keys OPENAI_API_KEY="sk-..." ANTHROPIC_API_KEY="sk-ant-..."
```

### 3. Configure OpenRange to use Vault

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token
openrange serve
```

## Kubernetes Deployment

### Install Vault via Helm

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install vault hashicorp/vault \
  -n vault --create-namespace \
  -f deploy/vault/values.yaml
```

### Bootstrap Vault

```bash
kubectl port-forward svc/vault -n vault 8200:8200 &
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token
./deploy/vault/bootstrap-vault.sh
```

### Kubernetes Auth (production)

For pods running in Kubernetes, configure Vault Kubernetes auth instead of
using a static token:

```bash
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443"
vault write auth/kubernetes/role/openrange \
  bound_service_account_names=openrange \
  bound_service_account_namespaces=default \
  policies=openrange \
  ttl=1h
```

Then set in the OpenRange pod:

```bash
export VAULT_ADDR=http://vault.vault.svc.cluster.local:8200
export OPENRANGE_VAULT_K8S_ROLE=openrange
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | _(none)_ | Vault server address |
| `VAULT_TOKEN` | _(none)_ | Static Vault token |
| `VAULT_NAMESPACE` | _(none)_ | Vault namespace (enterprise) |
| `VAULT_CACERT` | _(none)_ | CA cert path for TLS |
| `VAULT_SKIP_VERIFY` | `false` | Skip TLS verification |
| `OPENRANGE_VAULT_KV_MOUNT` | `secret` | KV v2 mount path |
| `OPENRANGE_VAULT_TRANSIT_MOUNT` | `transit` | Transit mount path |
| `OPENRANGE_VAULT_TRANSIT_KEY` | `openrange/credentials` | Transit key name |
| `OPENRANGE_VAULT_K8S_ROLE` | _(none)_ | Kubernetes auth role |
| `OPENRANGE_VAULT_K8S_MOUNT` | `kubernetes` | Kubernetes auth mount |
| `OPENRANGE_VAULT_TIMEOUT` | `10` | HTTP timeout (seconds) |

## Secret Paths

| Path | Contents |
|---|---|
| `secret/data/openrange/llm-api-keys` | LLM provider API keys (OPENAI_API_KEY, etc.) |
| `secret/data/openrange/range-credentials` | Range infrastructure credentials (MySQL, LDAP) |

## Python API

```python
from open_range.vault_client import VaultCredentialProvider

provider = VaultCredentialProvider.from_env()

# LLM keys (falls back to env vars)
key = provider.get_llm_api_key("OPENAI_API_KEY")

# Range credentials (falls back to defaults)
mysql_pw = provider.get_mysql_root_password()

# Direct Vault client access
from open_range.vault_client import get_vault_client

client = get_vault_client()  # None if Vault is not configured
if client:
    client.write_secret("openrange/my-secret", {"key": "value"})
    ciphertext = client.encrypt("sensitive data")
```
