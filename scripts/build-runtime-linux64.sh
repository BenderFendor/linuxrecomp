#!/usr/bin/env bash
# Build the linux64 runtime C helpers (image loader and reference executor).
#
# Usage: ./scripts/build-runtime-linux64.sh
# Output: work/linux64/bin/{refexec,pe_map_probe}
#
# The reference executor maps a PE32+ image at its preferred base and calls one
# guest function on the real CPU. It is how differential tests get an oracle
# without an emulator: the guest's .text is already x86-64.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/runtime/linux64"
OUT="$ROOT/work/linux64/bin"
CC="${CC:-clang}"
CFLAGS="${CFLAGS:--O2 -g -Wall -Wextra -Werror}"

mkdir -p "$OUT"

# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c11 -o "$OUT/refexec" "$SRC/refexec.c" "$SRC/image_pe64.c"

echo "built: $OUT/refexec"
