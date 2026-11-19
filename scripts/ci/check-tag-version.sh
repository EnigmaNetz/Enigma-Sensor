#!/bin/bash
# Fails unless <tag> equals the version in internal/version/version.go. Both
# tag-triggered workflows (go-build-release.yml, docker-publish.yml) run it
# before publishing anything, so a mistyped tag publishes nothing.
#
# Usage: scripts/ci/check-tag-version.sh <tag>
set -euo pipefail

[ $# -eq 1 ] || { echo "Usage: $0 <tag>" >&2; exit 1; }
TAG="$1"
VERSION=$(sed -n -E 's/^const Version = "(.*)"$/\1/p' internal/version/version.go)

if [ -z "$VERSION" ]; then
  echo "::error::Could not read const Version from internal/version/version.go"
  exit 1
fi
if [ "$TAG" != "$VERSION" ]; then
  echo "::error::Tag $TAG does not match internal/version/version.go ($VERSION). Delete the tag and push one that matches."
  exit 1
fi
echo "Tag $TAG matches version.go"
