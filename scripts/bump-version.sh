#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

[ "$1" = "patch" ] || [ "$1" = "minor" ] || [ "$1" = "major" ] || { echo "Usage: $0 {patch|minor|major}"; exit 1; }
cd "$REPO_ROOT"
git diff-index --quiet HEAD -- || { echo "Working directory not clean"; exit 1; }

CURRENT=$(grep 'const Version =' internal/version/version.go | sed 's/.*"v\([0-9]*\.[0-9]*\.[0-9]*\)".*/\1/')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$1" in
  patch) PATCH=$((PATCH + 1)) ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
esac

NEW="$MAJOR.$MINOR.$PATCH"
sed -i "s/const Version = \"v[0-9]*\.[0-9]*\.[0-9]*\"/const Version = \"v$NEW\"/" internal/version/version.go
sed -i "s/^Version: [0-9]*\.[0-9]*\.[0-9]*/Version: $NEW/" installer/debian/DEBIAN/control
sed -i "s/^AppVersion=[0-9]*\.[0-9]*\.[0-9]*/AppVersion=$NEW/" installer/windows/enigma-sensor-installer.iss

git add internal/version/version.go installer/debian/DEBIAN/control installer/windows/enigma-sensor-installer.iss
git commit -m "Version bump to v$NEW"

# Removing Git Tagging from this action.
# We now have to create a PR to bump the version number
# so after that PR is merged in we would then push a new git tag
# git tag "v$NEW"
