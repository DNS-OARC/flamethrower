#!/bin/sh

VERSION=1.7.0
ARCHIVE="https://www.nlnetlabs.nl/downloads/ldns/ldns-${VERSION}.tar.gz"

set -ex

cd /tmp
wget -O "ldns-${VERSION}.tar.gz" "$ARCHIVE"
tar -xf "ldns-${VERSION}.tar.gz"
cd "ldns-${VERSION}"

./configure --disable-dane
make
sudo make install
sudo ldconfig
sudo mkdir -p /usr/local/lib/pkgconfig
sudo cp packaging/libldns.pc /usr/local/lib/pkgconfig/
