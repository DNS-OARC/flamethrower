#!/bin/bash

set -xe

SRC_REPO=${SRC_REPO:-https://github.com/skypjack/uvw}
DESTDIR=${DESTDDIR:-$(dirname "$0")/uvw}
REVISION=${REVISION:-v3.4.0_libuv_v1.48}

SRCDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf \"$SRCDIR\"" SIGINT SIGTERM EXIT

git clone --depth=1 --branch="$REVISION" -- "$SRC_REPO" "$SRCDIR"

rm -rf "$DESTDIR"
install -m 0755 -d "$DESTDIR"
install -m 0644 "$SRCDIR"/LICENSE "$DESTDIR"
install -m 0755 -d "$DESTDIR/src"
install -m 0644 "$SRCDIR"/src/uvw/*.cpp "$DESTDIR/src"
install -m 0755 -d "$DESTDIR/include/uvw"
install -m 0644 "$SRCDIR"/src/uvw.hpp "$DESTDIR/include"
install -m 0644 "$SRCDIR"/src/uvw/*.{h,hpp} "$DESTDIR/include/uvw"

printf "%s %s\n" "$(git --git-dir "$SRCDIR/.git" --work-tree "$SRCDIR" rev-parse HEAD)" "$REVISION" | tee "$DESTDIR/VERSION"
