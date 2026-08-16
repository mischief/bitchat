#!/bin/sh
# Lint man pages. The mandoc.db warnings are about the host's man index, not
# the page, so drop them.
set -eu
out=$(mandoc -Tlint -Wstyle "$@" 2>&1 | grep -v 'mandoc.db' || true)
[ -z "$out" ] || { printf '%s\n' "$out"; exit 1; }
