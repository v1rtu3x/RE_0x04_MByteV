#!/usr/bin/env bash

set -euo pipefail

BINARY="../build/mbytev"
TESTDIR="$(pwd)"

if [ ! -x "$BINARY" ]; then
    echo "Binary not found or not executable: $BINARY"
    echo "Build it first"
    exit 1
fi

SUCCESS="$TESTDIR/success.bin"
FAIL_SEL="$TESTDIR/fail_sel.bin"
FAIL_R0="$TESTDIR/fail_r0.bin"

# success: PUSH_IMM 0x7A; POP_REG 0; CALL 0x42; HALT
printf '\x01\x7A\x02\x00\x09\x42\xF9' > "$SUCCESS"

# fail: correct R0 but wrong selector (0x41)
printf '\x01\x7A\x02\x00\x09\x41\xF9' > "$FAIL_SEL"

# fail: wrong R0 (0x00) but correct selector (0x42)
printf '\x01\x00\x02\x00\x09\x42\xF9' > "$FAIL_R0"

echo "Test Success Path"
OUT=$("$BINARY" "$SUCCESS" 2>&1 || true)
echo "$OUT"
echo "$OUT" | grep -q "SUCCESS" || { echo "Failed success path"; exit 1; }

echo "Test: Fail (Wrong Selector)"
OUT=$("$BINARY" "$FAIL_SEL" 2>&1 || true)
echo "$OUT"
echo "$OUT" | grep -q "^FAIL$" || { echo "Failed selector test"; exit 1; }

echo "Test: Fail (Wrong R0)"
OUT=$("$BINARY" "$FAIL_R0" 2>&1 || true)
echo "$OUT"
echo "$OUT" | grep -q "^FAIL$" || { echo "Failed R0 test"; exit 1; }

echo "All tests passed!"
exit 0
