#!/bin/sh

SUDO=sudo

if [[ ${1} == "container" ]]; then
    SUDO=""
fi

VERSION=1.7.0
ARCHIVE="https://www.nlnetlabs.nl/downloads/ldns/ldns-${VERSION}.tar.gz"

set -ex

cd /tmp
wget -O "ldns-${VERSION}.tar.gz" "$ARCHIVE"
tar -xf "ldns-${VERSION}.tar.gz"
cd "ldns-${VERSION}"

./configure --disable-dane
make
${SUDO} make install
${SUDO} ldconfig
${SUDO} mkdir -p /usr/local/lib/pkgconfig
${SUDO} cp packaging/libldns.pc /usr/local/lib/pkgconfig/
