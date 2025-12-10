#!/bin/bash

set -xe

SRC_REPO=${SRC_REPO:-https://github.com/ngtcp2/urlparse.git}
DESTDIR=${DESTDDIR:-$(dirname "$0")/urlparse}
REVISION=${REVISION:-main}

SRCDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf \"$SRCDIR\"" SIGINT SIGTERM EXIT

git clone --depth=1 --branch="$REVISION" -- "$SRC_REPO" "$SRCDIR"

rm -rf "$DESTDIR"
install -m 0755 -d "$DESTDIR"
install -m 0644 "$SRCDIR"/COPYING "$DESTDIR"
install -m 0755 -d "$DESTDIR/src"
install -m 0644 "$SRCDIR"/urlparse.c "$DESTDIR/src"
install -m 0755 -d "$DESTDIR/include"
install -m 0644 "$SRCDIR"/urlparse.h "$DESTDIR/include"

printf "%s %s\n" "$(git --git-dir "$SRCDIR/.git" --work-tree "$SRCDIR" rev-parse HEAD)" "$REVISION" | tee "$DESTDIR/VERSION"
