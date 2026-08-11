#!/bin/sh

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ACTUAL_VERSION=$(node -p "require('$REPO_ROOT/package.json').version")
if [ "$#" -gt 0 ]; then
  EXPECTED_VERSION=$1
  shift
else
  EXPECTED_VERSION=$ACTUAL_VERSION
fi
EXPECTED_VERSION=${EXPECTED_VERSION#v}

if [ "$ACTUAL_VERSION" != "$EXPECTED_VERSION" ]; then
  echo "npm package version $ACTUAL_VERSION does not match release $EXPECTED_VERSION" >&2
  exit 1
fi

npm publish "$REPO_ROOT" --access public "$@"
