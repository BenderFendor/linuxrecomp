#!/usr/bin/env bash
# Lift until the program stops asking for functions it does not have.
#
# The recovery misses code with no unwind record, and that is common: the compiler omits it
# for leaf functions and for functions it can describe entirely in the prologue. Those are
# invisible to .pdata, so they cannot be found statically without guessing at function
# starts. The run knows them exactly, and it can name all of them at once.
#
# So a round is: one collecting run (`--skip-missing`), one lift of the whole unresolved
# set, one rebuild. Lifting a function takes about 20ms and a rebuild about 25s, which is
# why the first version of this loop - one rebuild per function - was unusable.
#
# Usage: scripts/lift-until-complete.sh IMAGE ENTRY_VA [OUT_DIR]
set -euo pipefail

IMAGE="${1:?image path required}"
ENTRY="${2:?entry virtual address required}"
LIFT_DIR="${3:-work/linux64/lift}"
HARNESS_DIR="$(dirname "$LIFT_DIR")/bin"
NAME="$(basename "$IMAGE" .exe)"
HARNESS="$HARNESS_DIR/lifted_harness-$NAME.winelib"

for round in $(seq 1 40); do
    run_log=$(mktemp)
    WINEDEBUG=-all timeout 900 "$HARNESS" "$IMAGE" "$ENTRY" --program --skip-missing \
        >"$run_log" 2>&1 || true

    addresses=$(rg -Na -o '^lifted: unresolved 0x[0-9a-f]+' "$run_log" \
        | rg -No '0x[0-9a-f]+' | sort -u || true)
    entered=$(rg -Na '^lifted: entered' "$run_log" | tail -1 || true)
    stop=$(rg -Na '^lifted: stop' "$run_log" | tail -1 || true)
    count=$(printf '%s\n' "$addresses" | rg -Nc '0x' || true)
    printf 'round %d: unresolved=%s | %s | %s\n' \
        "$round" "${count:-0}" "$entered" "$stop"

    if [ -z "$addresses" ]; then
        echo "coverage complete: the run needs nothing that is not lifted"
        rm -f "$run_log"
        exit 0
    fi

    for address in $addresses; do
        timeout 300 python3 -m tools.linux64 lift "$IMAGE" --function "$address" \
            --extend-to-next --out "$LIFT_DIR" >/dev/null 2>&1 || true
    done
    "$(dirname "$0")/build-lifted-harness.sh" "$IMAGE" "$LIFT_DIR" "$HARNESS_DIR" >/dev/null
    rm -f "$run_log"
done

echo "gave up after 40 rounds" >&2
exit 1
