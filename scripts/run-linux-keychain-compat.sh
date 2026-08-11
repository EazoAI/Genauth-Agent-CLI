#!/bin/sh

set -eu

keyring_runtime_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
keyring_runtime_dir="$keyring_runtime_root/agent-identity-keyring-runtime"
mkdir -p "$keyring_runtime_dir"
chmod 700 "$keyring_runtime_dir"
export XDG_RUNTIME_DIR="$keyring_runtime_dir"

unlock_environment=$(printf '%s' 'agent-identity-ci-keyring' | gnome-keyring-daemon --unlock)
eval "$unlock_environment"

npm run test:keychain-compat
