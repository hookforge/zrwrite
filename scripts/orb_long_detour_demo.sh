#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/zig-out/demo/long_detour"
REMOTE_DIR="/tmp/zrwrite_long_detour_demo"

mkdir -p "$WORK_DIR"
rm -f \
  "$WORK_DIR/far_detour_target" \
  "$WORK_DIR/far_detour_target.patched" \
  "$WORK_DIR/far_detour_payload.o" \
  "$WORK_DIR/far_detour_payload.zrpb"

echo "[1/6] building host zrwrite cli"
zig build -Doptimize=ReleaseSafe

echo "[2/6] building far-detour target and payload"
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
  "$ROOT_DIR/tests/fixtures/far_detour_target.S" \
  "$ROOT_DIR/tests/fixtures/far_detour_main.c" \
  -o "$WORK_DIR/far_detour_target"

zig cc \
  -target aarch64-linux-musl \
  -c \
  -fPIC \
  -g0 \
  -fno-stack-protector \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  -I "$ROOT_DIR/include" \
  "$ROOT_DIR/tests/fixtures/payload.c" \
  -o "$WORK_DIR/far_detour_payload.o"

echo "[3/6] building long-detour instrument bundle"
"$ROOT_DIR/zig-out/bin/zrwrite" bundle \
  --output "$WORK_DIR/far_detour_payload.zrpb" \
  --payload "$WORK_DIR/far_detour_payload.o" \
  --hook-kind instrument \
  --target-symbol far_patchpoint \
  --handler-symbol on_hit \
  --stolen-instructions 4 \
  --log-message $'zrwrite long detour hit\n'

echo "[4/6] applying bundle locally"
"$ROOT_DIR/zig-out/bin/zrwrite" apply \
  --bundle "$WORK_DIR/far_detour_payload.zrpb" \
  --input "$WORK_DIR/far_detour_target" \
  --output "$WORK_DIR/far_detour_target.patched"

echo "[5/6] uploading artifacts to orb"
ssh ubuntu@orb "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp \
  "$WORK_DIR/far_detour_target" \
  "$WORK_DIR/far_detour_target.patched" \
  "ubuntu@orb:$REMOTE_DIR/"

echo "[6/6] running original and patched binaries on orb"
ssh ubuntu@orb "
  set -euo pipefail
  chmod +x '$REMOTE_DIR/far_detour_target' '$REMOTE_DIR/far_detour_target.patched'
  set +e
  '$REMOTE_DIR/far_detour_target' > '$REMOTE_DIR/original.stdout' 2>&1
  original_status=\$?
  '$REMOTE_DIR/far_detour_target.patched' > '$REMOTE_DIR/patched.stdout' 2>&1
  patched_status=\$?
  set -e

  echo 'original exit:' \$original_status
  echo 'patched exit:' \$patched_status
  echo '--- patched stdout ---'
  cat '$REMOTE_DIR/patched.stdout'

  test \$original_status -eq 1
  test \$patched_status -eq 0
  grep -q 'zrwrite long detour hit' '$REMOTE_DIR/patched.stdout'
"

echo "long detour demo completed successfully"
