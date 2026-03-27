#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/zig-out/demo/pattern_terminal_branch"
REMOTE_DIR="/tmp/zrwrite_pattern_terminal_branch_demo"
UNSTRIPPED_BIN="$WORK_DIR/terminal_branch_o2.unstripped"
STRIPPED_BIN="$WORK_DIR/terminal_branch_o2.stripped"
PATCHED_BIN="$WORK_DIR/terminal_branch_o2.stripped.pattern.patched"
INSPECT_TXT="$WORK_DIR/inspect.txt"

mkdir -p "$WORK_DIR"
rm -f \
  "$UNSTRIPPED_BIN" \
  "$STRIPPED_BIN" \
  "$PATCHED_BIN" \
  "$WORK_DIR/noop_payload.o" \
  "$WORK_DIR/terminal_branch_pattern_payload.zrpb" \
  "$INSPECT_TXT"

echo "[1/8] building host zrwrite cli"
zig build -Doptimize=ReleaseSafe

echo "[2/8] building O2 target and noop payload"
zig cc \
  -target aarch64-linux-musl \
  -O2 \
  -g0 \
  -static \
  -fno-stack-protector \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  "$ROOT_DIR/tests/fixtures/elf/replay/terminal_branch_o2.c" \
  -o "$UNSTRIPPED_BIN"

zig cc \
  -target aarch64-linux-musl \
  -c \
  -fPIC \
  -g0 \
  -fno-stack-protector \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  -I "$ROOT_DIR/include" \
  "$ROOT_DIR/tests/fixtures/shared/noop_payload.c" \
  -o "$WORK_DIR/noop_payload.o"

echo "[3/8] using inspect to generate an exact pattern snippet"
"$ROOT_DIR/zig-out/bin/zrwrite" inspect \
  --input "$UNSTRIPPED_BIN" \
  --symbol stripped_terminal_branch \
  --pattern-bytes 8 2>&1 | tee "$INSPECT_TXT"

PATTERN_HEX="$(awk -F= '/^pattern_exact=/{print $2; exit}' "$INSPECT_TXT")"
EXPECTED_HEX="$(awk -F= '/^expected_bytes=/{print $2; exit}' "$INSPECT_TXT")"
if [[ -z "${PATTERN_HEX}" || -z "${EXPECTED_HEX}" ]]; then
  echo "failed to parse inspect output" >&2
  exit 1
fi

echo "[4/8] stripping the binary on orb"
ssh ubuntu@orb "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp "$UNSTRIPPED_BIN" "ubuntu@orb:$REMOTE_DIR/terminal_branch_o2.unstripped"
ssh ubuntu@orb "
  set -euo pipefail
  cp '$REMOTE_DIR/terminal_branch_o2.unstripped' '$REMOTE_DIR/terminal_branch_o2.stripped'
  strip -s '$REMOTE_DIR/terminal_branch_o2.stripped'
"
scp "ubuntu@orb:$REMOTE_DIR/terminal_branch_o2.stripped" "$STRIPPED_BIN"

echo "[5/8] building pattern-locator bundle for the stripped binary"
"$ROOT_DIR/zig-out/bin/zrwrite" bundle \
  --output "$WORK_DIR/terminal_branch_pattern_payload.zrpb" \
  --payload "$WORK_DIR/noop_payload.o" \
  --hook-kind instrument \
  --target-pattern "$PATTERN_HEX" \
  --expected-bytes "$EXPECTED_HEX" \
  --handler-symbol on_hit \
  --stolen-instructions 2 \
  --log-message $'zrwrite stripped pattern terminal branch hit\n'

echo "[6/8] applying the bundle locally"
"$ROOT_DIR/zig-out/bin/zrwrite" apply \
  --bundle "$WORK_DIR/terminal_branch_pattern_payload.zrpb" \
  --input "$STRIPPED_BIN" \
  --output "$PATCHED_BIN"

echo "[7/8] uploading stripped original and patched binaries to orb"
scp \
  "$STRIPPED_BIN" \
  "$PATCHED_BIN" \
  "ubuntu@orb:$REMOTE_DIR/"

echo "[8/8] running stripped original and patched binaries on orb"
ssh ubuntu@orb "
  set -euo pipefail
  cd '$REMOTE_DIR'
  chmod +x terminal_branch_o2.stripped terminal_branch_o2.stripped.pattern.patched
  set +e
  ./terminal_branch_o2.stripped > original.stdout 2>&1
  original_status=\$?
  ./terminal_branch_o2.stripped.pattern.patched > patched.stdout 2>&1
  patched_status=\$?
  set -e

  echo original_exit=\$original_status
  echo patched_exit=\$patched_status
  echo '--- patched stdout ---'
  cat patched.stdout

  test \$original_status -eq 0
  test \$patched_status -eq 0
  grep -q 'zrwrite stripped pattern terminal branch hit' patched.stdout
"

echo "pattern terminal-branch demo completed successfully"
