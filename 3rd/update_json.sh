#!/bin/bash

set -xe

SRC_REPO=${SRC_REPO:-https://github.com/nlohmann/json.git}
DESTDIR=${DESTDDIR:-$(dirname "$0")/json}
REVISION=${REVISION:-v3.12.0}

SRCDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf \"$SRCDIR\"" SIGINT SIGTERM EXIT

git clone --depth=1 --branch="$REVISION" -- "$SRC_REPO" "$SRCDIR"

rm -rf "$DESTDIR"
install -m 0755 -d "$DESTDIR"
install -m 0644 "$SRCDIR/LICENSE.MIT" "$DESTDIR"
install -m 0755 -d "$DESTDIR/include/nlohmann"
install -m 0644 "$SRCDIR/single_include/nlohmann/json.hpp" "$DESTDIR/include/nlohmann/"

printf "%s %s\n" "$(git --git-dir "$SRCDIR/.git" --work-tree "$SRCDIR" rev-parse HEAD)" "$REVISION" | tee "$DESTDIR/VERSION"
