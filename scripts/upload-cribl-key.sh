#!/usr/bin/env bash
# Upload a Cribl encryption key into Azure Key Vault for the decrypt Function.
#
# The Function looks up secrets named `cribl-key-<keyId>` whose value is JSON:
#   {"keyHex": "...", "algorithm": "aes-256-cbc", "useIV": false}
#
# Get the raw hex once at key creation: the Cribl `POST /m/<group>/system/keys`
# response includes `plainKey` (also shown once in the UI under
# Group Settings -> Security -> Encryption Keys).
#
# Usage:
#   ./upload-cribl-key.sh <vaultName> <keyId> <keyHex> [algorithm] [useIV]
# Example:
#   ./upload-cribl-key.sh cribldeckv8x smSLT3 0a31961c...43f aes-256-cbc false
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <vaultName> <keyId> <keyHex> [algorithm=aes-256-cbc] [useIV=false]" >&2
  exit 1
fi

vault="$1"
key_id="$2"
key_hex="$3"
algorithm="${4:-aes-256-cbc}"
use_iv="${5:-false}"

# Validate: 64 hex chars (32-byte AES-256 key).
if [[ ! "$key_hex" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "error: keyHex must be 64 hex chars (32-byte AES-256 key)" >&2
  exit 1
fi

value=$(jq -nc --arg h "$key_hex" --arg a "$algorithm" --argjson iv "$use_iv" \
  '{keyHex:$h, algorithm:$a, useIV:$iv}')

az keyvault secret set \
  --vault-name "$vault" \
  --name "cribl-key-${key_id}" \
  --value "$value" \
  --output none

echo "uploaded cribl-key-${key_id} to $vault (algorithm=$algorithm useIV=$use_iv)"
