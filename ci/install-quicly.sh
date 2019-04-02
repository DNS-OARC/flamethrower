#!/bin/sh

GITREPO="https://github.com/h2o/quicly"

set -ex

cd /tmp
git clone "$GITREPO"
cd quicly

# instructions from quicly README
git submodule update --init --recursive
cmake .
make

