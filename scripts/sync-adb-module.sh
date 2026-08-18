#!/bin/sh
# Sync the browser ADB module from the ya-webadb fork into web/vendor/.
# Upstream: https://github.com/tayuLuc/ya-webadb (libraries/adb-daemon-browser)
#
# Network is needed only here (build-time); the runtime stays fully offline.
set -e

UPSTREAM="https://raw.githubusercontent.com/tayuLuc/ya-webadb/main/libraries/adb-daemon-browser/src/index.js"
DEST="$(dirname "$0")/../web/vendor/adb-daemon-browser.js"
TMP="$(mktemp)"

curl -fsSL "$UPSTREAM" -o "$TMP"
if ! diff -q "$TMP" "$DEST" >/dev/null 2>&1; then
    cp "$TMP" "$DEST"
    echo "updated $DEST"
else
    echo "$DEST is already up to date"
fi
rm -f "$TMP"
