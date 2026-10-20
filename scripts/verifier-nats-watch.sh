#!/usr/bin/env bash
set -euo pipefail
# Notification events contain status and IDs, not the credential payload.
nats sub --server "${NATS_URL:-nats://127.0.0.1:4222}" --raw "${PROOF_NOTIFY_SUBJECT:-presentation.proof.notify}"
