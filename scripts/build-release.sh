#!/bin/sh

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RELEASE_VERSION=${1:-$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")}
RELEASE_VERSION=${RELEASE_VERSION#v}

case "$RELEASE_VERSION" in
  ''|*[!0-9A-Za-z.+-]*)
    echo "invalid release version: $RELEASE_VERSION" >&2
    exit 1
    ;;
esac

build_target() {
  TARGET_OS=$1
  TARGET_ARCH=$2
  NPM_PLATFORM=$3
  TARGET_NAME=agent-identity
  if [ "$TARGET_OS" = "windows" ]; then
    TARGET_NAME=agent-identity.exe
  fi
  TARGET_DIR="$REPO_ROOT/dist/$NPM_PLATFORM"
  mkdir -p "$TARGET_DIR"
  echo "building $NPM_PLATFORM"
  (
    cd "$REPO_ROOT"
    CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" go build \
      -trimpath \
      -ldflags "-s -w -X github.com/Authing/genauth-agent-cli/internal/cli/command.Version=$RELEASE_VERSION" \
      -o "$TARGET_DIR/$TARGET_NAME" \
      ./cmd/agent-identity
  )
}

build_target darwin arm64 darwin-arm64
build_target darwin amd64 darwin-x64
build_target linux arm64 linux-arm64
build_target linux amd64 linux-x64
build_target windows amd64 win32-x64
