#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS="$ROOT/.deps/src"
WITH_ANALYSIS=0

if [[ "${1:-}" == "--analysis" ]]; then
  WITH_ANALYSIS=1
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--analysis]" >&2
  exit 2
fi

mkdir -p "$DEPS"

checkout() {
  local name="$1" url="$2" rev="$3"
  local dst="$DEPS/$name"
  if [[ ! -d "$dst/.git" ]]; then
    git clone --filter=blob:none "$url" "$dst"
  fi
  git -C "$dst" fetch --depth=1 origin "$rev" || git -C "$dst" fetch origin "$rev"
  git -C "$dst" checkout --detach "$rev"
  echo "$name -> $(git -C "$dst" rev-parse --short HEAD)"
}

# Required for the first lifting milestone.
checkout remill https://github.com/lifting-bits/remill.git 56918a8c2554088e93389e97d292f4035286506c

# Native runtime backends. They are not required for P1-P4 but pin them now.
checkout dxvk https://github.com/doitsujin/dxvk.git 7df3596eed49cb79f07c18869a1a9a8c067efe04
checkout FAudio https://github.com/FNA-XNA/FAudio.git 2af4f0027861f846545d322377ff3355eadf52aa

if [[ "$WITH_ANALYSIS" -eq 1 ]]; then
  checkout rellic https://github.com/lifting-bits/rellic.git 370abaad86ae5adad82f85b81aff14557462b7f2
  checkout anvill https://github.com/lifting-bits/anvill.git 9948d26cd993952d6010a59f27a198cbe3c79c1d
  checkout revng https://github.com/revng/revng.git 1e33c335935ba43286017760ff396112914d4f6b
  checkout dxvk-native-reference https://github.com/misyltoad/dxvk-native.git c8dc91fabd00cac11d697ccf07426e798393cd40
fi

cat <<'MSG'

Source checkouts are pinned under .deps/src.
Next:
  python -m tools.linux64 doctor
  ./scripts/build-win64-fixtures.sh
  ./scripts/check-winelib.sh

Building Remill/rev.ng/Anvill is intentionally separate; each has LLVM/toolchain version constraints that should be resolved explicitly rather than hidden in bootstrap.
The Win32 API layer is the installed Wine (winegcc/winebuild plus its PE DLLs), not a checkout; see docs/linux64/WINE.md.
MSG

if ! command -v winegcc >/dev/null 2>&1; then
  echo "warning: winegcc not found - the runtime's Win32 layer needs Wine's winelib toolchain" >&2
fi
