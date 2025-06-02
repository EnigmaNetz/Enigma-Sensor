#!/bin/bash
set -e
umask 022

SENSOR_BIN=../../bin/enigma-sensor-linux
VERSION=$(awk '/^Version: /{print $2}' DEBIAN/control)
PKG_DIR=./enigma-sensor_${VERSION}_amd64
GO_BUILD_SRC=../../cmd/enigma-sensor

# Clean up any previous build
rm -rf $PKG_DIR

# Ensure binary exists, build if missing
if [ ! -f "$SENSOR_BIN" ]; then
  echo "[INFO] $SENSOR_BIN not found. Building Go binary..."
  (cd ../.. && GOOS=linux GOARCH=amd64 go build -o bin/enigma-sensor-linux ./cmd/enigma-sensor)
  if [ ! -f "$SENSOR_BIN" ]; then
    echo "[ERROR] Failed to build $SENSOR_BIN. Aborting."
    exit 1
  fi
fi

# Create directory structure
mkdir -p $PKG_DIR/DEBIAN
mkdir -p $PKG_DIR/usr/local/bin
mkdir -p $PKG_DIR/etc/systemd/system
mkdir -p $PKG_DIR/etc/enigma-sensor

# Copy control files
cp DEBIAN/control $PKG_DIR/DEBIAN/
cp DEBIAN/postinst $PKG_DIR/DEBIAN/
cp DEBIAN/prerm $PKG_DIR/DEBIAN/

# Ensure maintainer scripts have Unix line endings
for script in $PKG_DIR/DEBIAN/*; do
  dos2unix "$script"
done

# Copy binary (rename to enigma-sensor for install)
cp $SENSOR_BIN $PKG_DIR/usr/local/bin/enigma-sensor

# Copy systemd service
cp etc/systemd/system/enigma-sensor.service $PKG_DIR/etc/systemd/system/

# Set permissions for all directories
find $PKG_DIR -type d -exec chmod 755 {} +

# Set permissions for all files
find $PKG_DIR -type f -exec chmod 644 {} +

# Set permissions for executables and maintainer scripts
chmod 755 $PKG_DIR/usr/local/bin/enigma-sensor
chmod 755 $PKG_DIR/DEBIAN/postinst $PKG_DIR/DEBIAN/prerm

# Force DEBIAN directory permissions last
chmod 755 $PKG_DIR/DEBIAN

# Build the .deb
mkdir -p ../../bin
fakeroot dpkg-deb --build $PKG_DIR ../../bin/enigma-sensor_${VERSION}_amd64.deb

echo "Debian package built: ../../bin/enigma-sensor_${VERSION}_amd64.deb"