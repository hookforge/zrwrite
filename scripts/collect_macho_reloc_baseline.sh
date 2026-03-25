#!/usr/bin/env bash
set -euo pipefail

if [[ "${OSTYPE:-}" != darwin* ]]; then
  echo "collect_macho_reloc_baseline.sh currently expects macOS + otool" >&2
  exit 1
fi

if ! command -v otool >/dev/null 2>&1; then
  echo "otool is required" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="${1:-"$repo_root/../ar-test/macho-reloc-baseline"}"
mkdir -p "$out_dir"

sample_c="$out_dir/sample_mix.c"
cat >"$sample_c" <<'EOF'
extern int ext_global;
extern int ext_func(int);

static int local_global = 7;
static const char kMessage[] = "hello";
static int *local_ptr = &local_global;

int use_all(int x) {
    int y = local_global + ext_global + kMessage[0] + *local_ptr;
    y += ext_func(x);
    return y;
}
EOF

pushd "$repo_root" >/dev/null

zig cc -target aarch64-macos -c -O0 "$sample_c" -o "$out_dir/sample_mix_O0.o"
zig cc -target aarch64-macos -c -O2 "$sample_c" -o "$out_dir/sample_mix_O2.o"

zig build-obj \
  -target aarch64-macos \
  -O ReleaseSmall \
  -fstrip \
  -I include \
  -femit-bin="$out_dir/zig_external_data_runtime.o" \
  tests/fixtures/zig_external_data_runtime.zig

emit_bin_arg="-femit-bin=$out_dir/macho_zrstd_multi_default_runtime.o"
zig build-obj \
  -target aarch64-macos \
  -O ReleaseSmall \
  -fstrip \
  --dep zrwrite \
  --dep zrstd \
  -Mroot=tests/fixtures/macho_zrstd_multi_default_runtime.zig \
  -Mzrwrite=src/root.zig \
  -Mzrstd=src/zrstd/root.zig \
  "$emit_bin_arg"

for object in \
  "$out_dir/sample_mix_O0.o" \
  "$out_dir/sample_mix_O2.o" \
  "$out_dir/zig_external_data_runtime.o" \
  "$out_dir/macho_zrstd_multi_default_runtime.o"
do
  dump_path="${object%.o}.relocs.txt"
  otool -rv "$object" >"$dump_path"

  summary_path="${object%.o}.summary.txt"
  python3 - "$dump_path" >"$summary_path" <<'PY'
import collections
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
pattern = re.compile(
    r"^[0-9A-Fa-f]+"
    r"\s+(True|False)"
    r"\s+.+?"
    r"\s+(True|False)"
    r"\s+([A-Z][A-Z0-9_]*)(True|False)?"
    r"\s+"
)

counts = collections.Counter()
for line in path.read_text().splitlines():
    match = pattern.match(line)
    if not match:
        continue
    reloc_type = match.group(3) + (match.group(4) or "")
    counts[reloc_type] += 1

for name in sorted(counts):
    print(f"{name} {counts[name]}")
PY
done

popd >/dev/null

echo "wrote Mach-O relocation baseline outputs to: $out_dir"
