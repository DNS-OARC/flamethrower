#!/bin/sh

GITREPO="https://github.com/h2o/quicly"

set -ex

cd /tmp
git clone "$GITREPO"
cd quicly

# instructions from quicly README
git submodule update --init --recursive
if ["$TRAVIS_OS_NAME" == "osx"]
then
    export PKG_CONFIG_PATH=/usr/local/opt/openssl@1.1/lib/pkgconfig
fi
cmake .
make

