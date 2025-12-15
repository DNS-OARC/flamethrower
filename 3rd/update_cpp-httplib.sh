#!/bin/bash

set -xe

SRC_REPO=${SRC_REPO:-https://github.com/yhirose/cpp-httplib.git}
DESTDIR=${DESTDDIR:-$(dirname "$0")/cpp-httplib}
REVISION=${REVISION:-v0.28.0}

SRCDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf \"$SRCDIR\"" SIGINT SIGTERM EXIT

git clone --depth=1 --branch="$REVISION" -- "$SRC_REPO" "$SRCDIR"

rm -rf "$DESTDIR"
install -m 0755 -d "$DESTDIR"
install -m 0644 "$SRCDIR/LICENSE" "$DESTDIR"
install -m 0755 -d "$DESTDIR/include"
install -m 0644 "$SRCDIR/httplib.h" "$DESTDIR/include"

printf "%s %s\n" "$(git --git-dir "$SRCDIR/.git" --work-tree "$SRCDIR" rev-parse HEAD)" "$REVISION" | tee "$DESTDIR/VERSION"
