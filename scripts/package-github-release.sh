#!/bin/sh

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RELEASE_VERSION=${1:-$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")}
RELEASE_VERSION=${RELEASE_VERSION#v}
RELEASE_DIR="$REPO_ROOT/dist/release"

mkdir -p "$RELEASE_DIR"

package_unix() {
  PLATFORM=$1
  ARCHIVE="agent-identity_${RELEASE_VERSION}_${PLATFORM}.tar.gz"
  tar -C "$REPO_ROOT/dist/$PLATFORM" -czf "$RELEASE_DIR/$ARCHIVE" agent-identity
}

package_unix darwin-arm64
package_unix darwin-x64
package_unix linux-arm64
package_unix linux-x64

(cd "$REPO_ROOT/dist/win32-x64" && zip -q "$RELEASE_DIR/agent-identity_${RELEASE_VERSION}_win32-x64.zip" agent-identity.exe)

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$RELEASE_DIR" && sha256sum ./*.tar.gz ./*.zip > SHA256SUMS)
else
  (cd "$RELEASE_DIR" && shasum -a 256 ./*.tar.gz ./*.zip > SHA256SUMS)
fi

echo "GitHub release artifacts are in $RELEASE_DIR"
