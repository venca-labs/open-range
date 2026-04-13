# Vault policy for the OpenRange cybersecurity gymnasium.
#
# Grants:
# - KV v2 read/write on the openrange secret namespace
# - Transit encrypt/decrypt using the openrange/credentials key
#
# Adapted from k3s-istio-vault-platform secret-store-transit.hcl.

# ---------------------------------------------------------------------------
# Token introspection (required for token renewal / lease management)
# ---------------------------------------------------------------------------

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

# ---------------------------------------------------------------------------
# KV v2 -- openrange secret namespace
# ---------------------------------------------------------------------------

# Read and write secrets under secret/data/openrange/*
path "secret/data/openrange/*" {
  capabilities = ["create", "update", "read"]
}

# Allow listing secrets under the openrange namespace
path "secret/metadata/openrange/*" {
  capabilities = ["list", "read"]
}

# Allow deleting secrets (optional -- useful for credential rotation)
path "secret/delete/openrange/*" {
  capabilities = ["update"]
}

# ---------------------------------------------------------------------------
# Transit -- encrypt / decrypt with the openrange/credentials key
# ---------------------------------------------------------------------------

# Encrypt data
path "transit/encrypt/openrange/credentials" {
  capabilities = ["update"]
}

# Decrypt data
path "transit/decrypt/openrange/credentials" {
  capabilities = ["update"]
}

# Generate data keys for envelope encryption
path "transit/datakey/plaintext/openrange/credentials" {
  capabilities = ["update"]
}

# Read key metadata (e.g. current key version)
path "transit/keys/openrange/credentials" {
  capabilities = ["read"]
}
