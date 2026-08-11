#!/bin/sh

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 0 ]; then
  EXPECTED_VERSION=$1
  shift
else
  EXPECTED_VERSION=$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")
fi
EXPECTED_VERSION=${EXPECTED_VERSION#v}

ACTUAL_VERSION=$(node -p "require('$REPO_ROOT/npm/agent-identity-cli/package.json').version")
if [ "$ACTUAL_VERSION" != "$EXPECTED_VERSION" ]; then
  echo "npm package version $ACTUAL_VERSION does not match release $EXPECTED_VERSION" >&2
  exit 1
fi

for PLATFORM in darwin-arm64 darwin-x64 linux-arm64 linux-x64 win32-x64; do
  npm publish "$REPO_ROOT/npm/platforms/$PLATFORM" --access public "$@"
done
npm publish "$REPO_ROOT/npm/agent-identity-cli" --access public "$@"
