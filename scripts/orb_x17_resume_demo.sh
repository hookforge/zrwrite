#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/zig-out/demo/x17_resume"
REMOTE_DIR="/tmp/zrwrite_x17_resume_demo"

mkdir -p "$WORK_DIR"
rm -f \
  "$WORK_DIR/x17_resume" \
  "$WORK_DIR/x17_resume.patched" \
  "$WORK_DIR/x17_resume_payload.o" \
  "$WORK_DIR/x17_resume.zrpb"

echo "[1/6] building host zrwrite cli"
zig build -Doptimize=ReleaseSafe

echo "[2/6] building aarch64 x17 resume smoke target and payload"
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
  "$ROOT_DIR/tests/fixtures/elf/replay/x17_resume_target.S" \
  "$ROOT_DIR/tests/fixtures/elf/replay/x17_resume_main.c" \
  -o "$WORK_DIR/x17_resume"

zig cc \
  -target aarch64-linux-musl \
  -c \
  -fPIC \
  -g0 \
  -fno-stack-protector \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  -I "$ROOT_DIR/include" \
  "$ROOT_DIR/tests/fixtures/elf/replay/x17_resume_payload.c" \
  -o "$WORK_DIR/x17_resume_payload.o"

echo "[3/6] building x17 instrument bundle"
"$ROOT_DIR/zig-out/bin/zrwrite" bundle \
  --output "$WORK_DIR/x17_resume.zrpb" \
  --payload "$WORK_DIR/x17_resume_payload.o" \
  --hook-kind instrument \
  --target-symbol x17_patchpoint \
  --handler-symbol on_hit \
  --log-message $'zrwrite x17 resume hit\n'

echo "[4/6] applying bundle locally"
"$ROOT_DIR/zig-out/bin/zrwrite" apply \
  --bundle "$WORK_DIR/x17_resume.zrpb" \
  --input "$WORK_DIR/x17_resume" \
  --output "$WORK_DIR/x17_resume.patched"

echo "[5/6] uploading artifacts to orb"
ssh ubuntu@orb "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp \
  "$WORK_DIR/x17_resume" \
  "$WORK_DIR/x17_resume.patched" \
  "ubuntu@orb:$REMOTE_DIR/"

echo "[6/6] running original and patched binaries on orb"
ssh ubuntu@orb "
  set -euo pipefail
  chmod +x '$REMOTE_DIR/x17_resume' '$REMOTE_DIR/x17_resume.patched'
  set +e
  '$REMOTE_DIR/x17_resume' > '$REMOTE_DIR/original.stdout' 2>&1
  original_status=\$?
  '$REMOTE_DIR/x17_resume.patched' > '$REMOTE_DIR/patched.stdout' 2>&1
  patched_status=\$?
  set -e

  echo 'original exit:' \$original_status
  echo 'patched exit:' \$patched_status
  echo '--- patched stdout ---'
  cat '$REMOTE_DIR/patched.stdout'

  test \$original_status -eq 1
  test \$patched_status -eq 0
  grep -q 'zrwrite x17 resume hit' '$REMOTE_DIR/patched.stdout'
"

echo "x17 resume demo completed successfully"
