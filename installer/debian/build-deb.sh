#!/bin/bash
set -e
umask 022

AGENT_BIN=../../bin/enigma-agent-linux
VERSION=$(awk '/^Version: /{print $2}' DEBIAN/control)
PKG_DIR=./enigma-agent_${VERSION}_amd64
GO_BUILD_SRC=../../cmd/enigma-agent

# Clean up any previous build
rm -rf $PKG_DIR

# Ensure binary exists, build if missing
if [ ! -f "$AGENT_BIN" ]; then
  echo "[INFO] $AGENT_BIN not found. Building Go binary..."
  (cd ../.. && GOOS=linux GOARCH=amd64 go build -o bin/enigma-agent-linux ./cmd/enigma-agent)
  if [ ! -f "$AGENT_BIN" ]; then
    echo "[ERROR] Failed to build $AGENT_BIN. Aborting."
    exit 1
  fi
fi

# Create directory structure
mkdir -p $PKG_DIR/DEBIAN
mkdir -p $PKG_DIR/usr/local/bin
mkdir -p $PKG_DIR/etc/systemd/system
mkdir -p $PKG_DIR/etc/enigma-agent

# Copy control files
cp DEBIAN/control $PKG_DIR/DEBIAN/
cp DEBIAN/postinst $PKG_DIR/DEBIAN/
cp DEBIAN/prerm $PKG_DIR/DEBIAN/

# Ensure maintainer scripts have Unix line endings
for script in $PKG_DIR/DEBIAN/*; do
  dos2unix "$script"
done

# Copy binary (rename to enigma-agent for install)
cp $AGENT_BIN $PKG_DIR/usr/local/bin/enigma-agent

# Copy systemd service
cp etc/systemd/system/enigma-agent.service $PKG_DIR/etc/systemd/system/

# Set permissions for all directories
find $PKG_DIR -type d -exec chmod 755 {} +

# Set permissions for all files
find $PKG_DIR -type f -exec chmod 644 {} +

# Set permissions for executables and maintainer scripts
chmod 755 $PKG_DIR/usr/local/bin/enigma-agent
chmod 755 $PKG_DIR/DEBIAN/postinst $PKG_DIR/DEBIAN/prerm

# Force DEBIAN directory permissions last
chmod 755 $PKG_DIR/DEBIAN

# Build the .deb
mkdir -p ../../bin
fakeroot dpkg-deb --build $PKG_DIR ../../bin/enigma-agent_${VERSION}_amd64.deb

echo "Debian package built: ../../bin/enigma-agent_${VERSION}_amd64.deb"