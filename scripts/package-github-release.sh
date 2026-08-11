#!/bin/sh

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RELEASE_DIR="$REPO_ROOT/dist/release"

mkdir -p "$RELEASE_DIR"
npm pack "$REPO_ROOT" --pack-destination "$RELEASE_DIR" --silent

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$RELEASE_DIR" && sha256sum ./*.tgz > SHA256SUMS)
else
  (cd "$RELEASE_DIR" && shasum -a 256 ./*.tgz > SHA256SUMS)
fi

echo "GitHub release artifacts are in $RELEASE_DIR"
