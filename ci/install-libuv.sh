#!/bin/sh

VERSION=1.25.0
ARCHIVE="https://github.com/libuv/libuv/archive/v${VERSION}.tar.gz"

set -ex

cd /tmp
wget -O "libuv-${VERSION}.tar.gz" "$ARCHIVE"
tar -xf "libuv-${VERSION}.tar.gz"
cd "libuv-${VERSION}"

./autogen.sh
./configure
make
sudo make install
sudo ldconfig
