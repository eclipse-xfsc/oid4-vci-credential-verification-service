#!/bin/sh
set -eu
base="${VAULT_ADDR:-http://openbao:8200}"
token="${VAULT_TOKEN:-test}"
# OpenBao development instance only; 204/400 if transit already exists.
curl -fsS -H "X-Vault-Token: $token" -H 'Content-Type: application/json' -X POST -d '{"type":"transit"}' "$base/v1/sys/mounts/transit" || true
for key in eckey edkey; do
  if [ "$key" = eckey ]; then kind=ecdsa-p256; else kind=ed25519; fi
  curl -fsS -H "X-Vault-Token: $token" -H 'Content-Type: application/json' -X POST -d "{"type":"$kind"}" "$base/v1/transit/keys/$key" || true
done
echo 'OpenBao transit initialized'
