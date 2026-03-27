#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/zig-out/demo/zig_payload"
REMOTE_DIR="/tmp/zrwrite_zig_payload_demo"

mkdir -p "$WORK_DIR"
rm -f \
  "$WORK_DIR/zig_payload_target" \
  "$WORK_DIR/zig_payload_target.patched" \
  "$WORK_DIR/zig_payload_runtime.o" \
  "$WORK_DIR/zig_payload_runtime.zrpb"

echo "[1/6] building host zrwrite cli"
zig build -Doptimize=ReleaseSafe

echo "[2/6] building aarch64 target binary and Zig payload object"
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
  "$ROOT_DIR/tests/fixtures/elf/zig/zig_payload_target.S" \
  "$ROOT_DIR/tests/fixtures/elf/zig/zig_payload_main.c" \
  -o "$WORK_DIR/zig_payload_target"

zig build-obj \
  -target aarch64-linux-musl \
  -O ReleaseSmall \
  -fstrip \
  -I "$ROOT_DIR/include" \
  -femit-bin="$WORK_DIR/zig_payload_runtime.o" \
  "$ROOT_DIR/tests/fixtures/elf/zig/zig_payload_runtime.zig"

echo "[3/6] building instrument bundle from Zig payload object"
"$ROOT_DIR/zig-out/bin/zrwrite" bundle \
  --output "$WORK_DIR/zig_payload_runtime.zrpb" \
  --payload "$WORK_DIR/zig_payload_runtime.o" \
  --hook-kind instrument \
  --target-symbol zig_payload_patchpoint \
  --handler-symbol on_hit \
  --log-message $'zrwrite zig payload hit\n'

echo "[4/6] applying bundle locally"
"$ROOT_DIR/zig-out/bin/zrwrite" apply \
  --bundle "$WORK_DIR/zig_payload_runtime.zrpb" \
  --input "$WORK_DIR/zig_payload_target" \
  --output "$WORK_DIR/zig_payload_target.patched"

echo "[5/6] uploading artifacts to orb"
ssh ubuntu@orb "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp \
  "$WORK_DIR/zig_payload_target" \
  "$WORK_DIR/zig_payload_target.patched" \
  "ubuntu@orb:$REMOTE_DIR/"

echo "[6/6] running original and patched binaries on orb"
ssh ubuntu@orb "
  set -euo pipefail
  chmod +x '$REMOTE_DIR/zig_payload_target' '$REMOTE_DIR/zig_payload_target.patched'
  set +e
  '$REMOTE_DIR/zig_payload_target' > '$REMOTE_DIR/original.stdout' 2>&1
  original_status=\$?
  '$REMOTE_DIR/zig_payload_target.patched' > '$REMOTE_DIR/patched.stdout' 2>&1
  patched_status=\$?
  set -e

  echo 'original exit:' \$original_status
  echo 'patched exit:' \$patched_status
  echo '--- patched stdout ---'
  cat '$REMOTE_DIR/patched.stdout'

  test \$original_status -eq 1
  test \$patched_status -eq 0
  grep -q 'zrwrite zig payload hit' '$REMOTE_DIR/patched.stdout'
"

echo "zig payload demo completed successfully"
