#!/bin/bash

set -xe

SRC_REPO=${SRC_REPO:-https://github.com/ReneNyffenegger/cpp-base64.git}
DESTDIR=${DESTDDIR:-$(dirname "$0")/cpp-base64}
REVISION=${REVISION:-master}

SRCDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf \"$SRCDIR\"" SIGINT SIGTERM EXIT

git clone --depth=1 --branch="$REVISION" -- "$SRC_REPO" "$SRCDIR"

rm -rf "$DESTDIR"
install -m 0755 -d "$DESTDIR"
install -m 0644 "$SRCDIR/LICENSE" "$DESTDIR"
install -m 0755 -d "$DESTDIR/src"
install -m 0644 "$SRCDIR/base64.cpp" "$DESTDIR/src/"
install -m 0755 -d "$DESTDIR/include"
install -m 0644 "$SRCDIR/base64.h" "$DESTDIR/include/"

printf "%s %s\n" "$(git --git-dir "$SRCDIR/.git" --work-tree "$SRCDIR" rev-parse HEAD)" "$REVISION" | tee "$DESTDIR/VERSION"
