#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/zig-out/demo/stripped_o2_terminal_branch"
REMOTE_DIR="/tmp/zrwrite_stripped_o2_terminal_branch_demo"
UNSTRIPPED_BIN="$WORK_DIR/terminal_branch_o2.unstripped"
STRIPPED_BIN="$WORK_DIR/terminal_branch_o2.stripped"
PATCHED_BIN="$WORK_DIR/terminal_branch_o2.stripped.patched"

mkdir -p "$WORK_DIR"
rm -f \
  "$UNSTRIPPED_BIN" \
  "$STRIPPED_BIN" \
  "$PATCHED_BIN" \
  "$WORK_DIR/noop_payload.o" \
  "$WORK_DIR/terminal_branch_o2_payload.zrpb"

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
  "$ROOT_DIR/tests/fixtures/terminal_branch_o2.c" \
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
  "$ROOT_DIR/tests/fixtures/noop_payload.c" \
  -o "$WORK_DIR/noop_payload.o"

TARGET_VADDR_HEX="$(nm -n "$UNSTRIPPED_BIN" | awk '/ stripped_terminal_branch$/ { print $1; exit }')"
if [[ -z "${TARGET_VADDR_HEX}" ]]; then
  echo "failed to locate stripped_terminal_branch in $UNSTRIPPED_BIN" >&2
  exit 1
fi
TARGET_VADDR="0x${TARGET_VADDR_HEX}"
echo "target_vaddr=$TARGET_VADDR"

echo "[3/8] stripping the binary on orb for a realistic no-symbol input"
ssh ubuntu@orb "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp "$UNSTRIPPED_BIN" "ubuntu@orb:$REMOTE_DIR/terminal_branch_o2.unstripped"
ssh ubuntu@orb "
  set -euo pipefail
  cp '$REMOTE_DIR/terminal_branch_o2.unstripped' '$REMOTE_DIR/terminal_branch_o2.stripped'
  strip -s '$REMOTE_DIR/terminal_branch_o2.stripped'
"
scp "ubuntu@orb:$REMOTE_DIR/terminal_branch_o2.stripped" "$STRIPPED_BIN"

echo "[4/8] building virtual-address bundle for the stripped input"
"$ROOT_DIR/zig-out/bin/zrwrite" bundle \
  --output "$WORK_DIR/terminal_branch_o2_payload.zrpb" \
  --payload "$WORK_DIR/noop_payload.o" \
  --hook-kind instrument \
  --target-vaddr "$TARGET_VADDR" \
  --handler-symbol on_hit \
  --stolen-instructions 2 \
  --log-message $'zrwrite stripped O2 terminal branch replay hit\n'

echo "[5/8] applying the bundle to the stripped binary locally"
"$ROOT_DIR/zig-out/bin/zrwrite" apply \
  --bundle "$WORK_DIR/terminal_branch_o2_payload.zrpb" \
  --input "$STRIPPED_BIN" \
  --output "$PATCHED_BIN"

echo "[6/8] uploading stripped original and patched binaries to orb"
scp \
  "$STRIPPED_BIN" \
  "$PATCHED_BIN" \
  "ubuntu@orb:$REMOTE_DIR/"

echo "[7/8] running stripped original and patched binaries on orb"
ssh ubuntu@orb "
  set -euo pipefail
  cd '$REMOTE_DIR'
  chmod +x terminal_branch_o2.stripped terminal_branch_o2.stripped.patched
  set +e
  ./terminal_branch_o2.stripped > original.stdout 2>&1
  original_status=\$?
  ./terminal_branch_o2.stripped.patched > patched.stdout 2>&1
  patched_status=\$?
  set -e

  echo original_exit=\$original_status
  echo patched_exit=\$patched_status
  echo '--- patched stdout ---'
  cat patched.stdout

  test \$original_status -eq 0
  test \$patched_status -eq 0
  grep -q 'zrwrite stripped O2 terminal branch replay hit' patched.stdout
"

echo "[8/8] stripped O2 terminal-branch demo completed successfully"
