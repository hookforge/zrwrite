#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/zig-out/demo/encryptor"
REMOTE_DIR="/tmp/zrwrite_encryptor_demo"

mkdir -p "$WORK_DIR"
rm -f \
  "$WORK_DIR/encryptor.unstripped" \
  "$WORK_DIR/encryptor.stripped" \
  "$WORK_DIR/encryptor.patched" \
  "$WORK_DIR/replace_payload.o" \
  "$WORK_DIR/encryptor_replace.zrpb" \
  "$WORK_DIR/plain.txt" \
  "$WORK_DIR/original.bin" \
  "$WORK_DIR/patched.bin"

echo "[1/7] building host zrwrite cli"
zig build -Doptimize=ReleaseSafe

echo "[2/7] building aarch64 target binary and replace payload"
zig cc \
  -target aarch64-linux-musl \
  -O3 \
  -g0 \
  -static \
  -fno-pic \
  -no-pie \
  -fno-stack-protector \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  "$ROOT_DIR/examples/encryptor/encryptor.c" \
  -o "$WORK_DIR/encryptor.unstripped"

zig cc \
  -target aarch64-linux-musl \
  -O3 \
  -g0 \
  -c \
  -fno-pic \
  -fno-stack-protector \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  "$ROOT_DIR/examples/encryptor/replace_payload.c" \
  -o "$WORK_DIR/replace_payload.o"

echo "[3/7] resolving encrypt_buffer virtual address from the unstripped build"
TARGET_VADDR="$("$ROOT_DIR/zig-out/bin/zrwrite" inspect --input "$WORK_DIR/encryptor.unstripped" --symbol encrypt_buffer 2>&1 | awk -F= '/^virtual_address=/{print $2}')"
if [[ -z "$TARGET_VADDR" ]]; then
  echo "failed to resolve encrypt_buffer virtual address" >&2
  exit 1
fi
echo "resolved encrypt_buffer at $TARGET_VADDR"

echo "[4/7] using orb to strip the binary"
ssh ubuntu@orb "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR'"
scp "$WORK_DIR/encryptor.unstripped" "ubuntu@orb:$REMOTE_DIR/encryptor.unstripped"
ssh ubuntu@orb "cp '$REMOTE_DIR/encryptor.unstripped' '$REMOTE_DIR/encryptor.stripped' && strip -s '$REMOTE_DIR/encryptor.stripped'"
scp "ubuntu@orb:$REMOTE_DIR/encryptor.stripped" "$WORK_DIR/encryptor.stripped"

echo "[5/7] building the replace bundle and patching the stripped binary"
"$ROOT_DIR/zig-out/bin/zrwrite" bundle \
  --output "$WORK_DIR/encryptor_replace.zrpb" \
  --payload "$WORK_DIR/replace_payload.o" \
  --hook-kind replace \
  --target-vaddr "$TARGET_VADDR" \
  --handler-symbol replacement_encrypt_buffer

"$ROOT_DIR/zig-out/bin/zrwrite" apply \
  --bundle "$WORK_DIR/encryptor_replace.zrpb" \
  --input "$WORK_DIR/encryptor.stripped" \
  --output "$WORK_DIR/encryptor.patched"

cat > "$WORK_DIR/plain.txt" <<'EOF'
hookforge demo payload
this file should encrypt differently after zrwrite replaces encrypt_buffer.
EOF

echo "[6/7] uploading original and patched binaries to orb"
scp \
  "$WORK_DIR/encryptor.stripped" \
  "$WORK_DIR/encryptor.patched" \
  "$WORK_DIR/plain.txt" \
  "ubuntu@orb:$REMOTE_DIR/"

echo "[7/7] running both binaries on orb"
ssh ubuntu@orb "
  set -euo pipefail
  chmod +x '$REMOTE_DIR/encryptor.stripped' '$REMOTE_DIR/encryptor.patched'
  '$REMOTE_DIR/encryptor.stripped' '$REMOTE_DIR/plain.txt' '$REMOTE_DIR/original.bin'
  '$REMOTE_DIR/encryptor.patched' '$REMOTE_DIR/plain.txt' '$REMOTE_DIR/patched.bin'
  echo '--- sha256 ---'
  sha256sum '$REMOTE_DIR/original.bin' '$REMOTE_DIR/patched.bin'
  echo '--- first 64 bytes original ---'
  xxd -g1 -l 64 '$REMOTE_DIR/original.bin'
  echo '--- first 64 bytes patched ---'
  xxd -g1 -l 64 '$REMOTE_DIR/patched.bin'
"

echo "demo completed successfully"
