#!/bin/sh

SUDO=sudo

if [[ ${1} == "container" ]]; then
    SUDO=""
fi

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
${SUDO} make install
${SUDO} ldconfig
