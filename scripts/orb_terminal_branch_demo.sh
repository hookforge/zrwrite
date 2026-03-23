#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/zig-out/demo/terminal_branch"
REMOTE_DIR="/tmp/zrwrite_terminal_branch_demo"

mkdir -p "$WORK_DIR"
rm -f \
  "$WORK_DIR/terminal_branch_target" \
  "$WORK_DIR/terminal_branch_target.patched" \
  "$WORK_DIR/noop_payload.o" \
  "$WORK_DIR/terminal_branch_payload.zrpb"

echo "[1/6] building host zrwrite cli"
zig build -Doptimize=ReleaseSafe

echo "[2/6] building widened terminal-branch smoke target and noop payload"
zig cc \
  -target aarch64-linux-musl \
  -O0 \
  -g0 \
  -static \
  -fno-pic \
  -no-pie \
  -fno-stack-protector \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  "$ROOT_DIR/tests/fixtures/terminal_branch_target.S" \
  "$ROOT_DIR/tests/fixtures/terminal_branch_main.c" \
  -o "$WORK_DIR/terminal_branch_target"

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

echo "[3/6] building widened terminal-branch bundle"
"$ROOT_DIR/zig-out/bin/zrwrite" bundle \
  --output "$WORK_DIR/terminal_branch_payload.zrpb" \
  --payload "$WORK_DIR/noop_payload.o" \
  --hook-kind instrument \
  --target-symbol terminal_branch_patchpoint \
  --handler-symbol on_hit \
  --stolen-instructions 2 \
  --log-message $'zrwrite terminal branch replay hit\n'

echo "[4/6] applying bundle locally"
"$ROOT_DIR/zig-out/bin/zrwrite" apply \
  --bundle "$WORK_DIR/terminal_branch_payload.zrpb" \
  --input "$WORK_DIR/terminal_branch_target" \
  --output "$WORK_DIR/terminal_branch_target.patched"

echo "[5/6] uploading artifacts to orb"
ssh ubuntu@orb "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp \
  "$WORK_DIR/terminal_branch_target" \
  "$WORK_DIR/terminal_branch_target.patched" \
  "ubuntu@orb:$REMOTE_DIR/"

echo "[6/6] running original and patched binaries on orb"
ssh ubuntu@orb "
  set -euo pipefail
  chmod +x '$REMOTE_DIR/terminal_branch_target' '$REMOTE_DIR/terminal_branch_target.patched'
  set +e
  '$REMOTE_DIR/terminal_branch_target' > '$REMOTE_DIR/original.stdout' 2>&1
  original_status=\$?
  '$REMOTE_DIR/terminal_branch_target.patched' > '$REMOTE_DIR/patched.stdout' 2>&1
  patched_status=\$?
  set -e

  echo 'original exit:' \$original_status
  echo 'patched exit:' \$patched_status
  echo '--- patched stdout ---'
  cat '$REMOTE_DIR/patched.stdout'

  test \$original_status -eq 0
  test \$patched_status -eq 0
  grep -q 'zrwrite terminal branch replay hit' '$REMOTE_DIR/patched.stdout'
"

echo "terminal branch replay demo completed successfully"
