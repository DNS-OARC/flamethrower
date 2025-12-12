#!/bin/bash

set -xe

SRC_REPO=${SRC_REPO:-https://github.com/docopt/docopt.cpp}
DESTDIR=${DESTDDIR:-$(dirname "$0")/docopt.cpp}
REVISION=${REVISION:-master}

SRCDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf \"$SRCDIR\"" SIGINT SIGTERM EXIT

git clone --depth=1 --branch="$REVISION" -- "$SRC_REPO" "$SRCDIR"

rm -rf "$DESTDIR"
install -m 0755 -d "$DESTDIR"
install -m 0755 -d "$DESTDIR/"{src,include}
install -m 0644 "$SRCDIR"/LICENSE* "$DESTDIR"
install -m 0644 "$SRCDIR"/docopt.cpp "$DESTDIR/src"
install -m 0644 "$SRCDIR"/docopt*.h "$DESTDIR/include"

git --git-dir "$SRCDIR/.git" --work-tree "$SRCDIR" rev-parse HEAD | tee "$DESTDIR/VERSION"

# patch to fix build with LLVM and C++23
patch -d "$DESTDIR" -p0 <<"EOF"
diff --git src/docopt.cpp src/docopt.cpp
--- src/docopt.cpp
+++ src/docopt.cpp
@@ -12,9 +12,9 @@

 #include "docopt_value.h"

+#include <algorithm>
 #include <vector>
 #include <unordered_set>
-#include <unordered_map>
 #include <map>
 #include <string>
 #include <iostream>
"EOF"
