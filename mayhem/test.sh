#!/usr/bin/env bash
#
# open5gs/mayhem/test.sh — functional oracle for the two fuzzed protocol-parse paths.
#
# WHY NOT open5gs's own suite: `meson test` here boots a full EPC/5GC core (MME/SGW/SMF/AMF/...)
# on loopback sockets and drives S1AP/NGAP/GTP/Diameter between them — it is NOT runnable inside the
# build container (no network namespaces / privileged sockets / config). So instead we build and run
# mayhem/harnesses/parse_oracle.c, a self-contained golden oracle that links the REAL parse code
# (ogs_nas_emm_decode / ogs_gtp2_parse_msg) and asserts decoded field VALUES for known-good PDUs and
# rejection of malformed ones. It is a PATCH-grade oracle (asserts values, not just "doesn't crash"),
# so a no-op decoder stub fails it. This script COMPILES the oracle against the static libs that
# mayhem/build.sh already produced (in mayhem-build/), runs it, and emits a CTRF summary.
# exit 0 iff every oracle case passes.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-/mayhem}"
BD="$SRC/mayhem-build"          # the libFuzzer meson tree from build.sh
ORACLE_SRC="$SRC/mayhem/harnesses/parse_oracle.c"

: "${CC:=clang}"
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# Match build.sh: the open5gs libs are compiled with alignment UBSan OFF (benign unaligned struct
# cast in lib/nas/eps/ies.c that floods every NAS message). Keep the oracle consistent.
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment"

# emit_ctrf <tool> <passed> <failed> [skipped]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}"
  local tests=$(( passed + failed + skipped ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": { "tests": $tests, "passed": $passed, "failed": $failed, "pending": 0, "skipped": $skipped, "other": 0 }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":0,"skipped":%d,"other":0}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$skipped"
  [ "$failed" -eq 0 ]
}

if [ ! -d "$BD" ]; then
  echo "missing $BD — run mayhem/build.sh first" >&2; emit_ctrf "open5gs-parse-oracle" 0 1 0; exit 2
fi
if [ ! -f "$ORACLE_SRC" ]; then
  echo "missing $ORACLE_SRC" >&2; emit_ctrf "open5gs-parse-oracle" 0 1 0; exit 2
fi

cd "$BD"

# Reuse the EXACT -I include flags meson used for the nas fuzzer (paths are relative to $BD), then
# add the gtp/app include dirs the oracle additionally needs. The generated core-config.h etc. live
# under $BD, so we compile from here.
INCS="$(python3 - <<'PY'
import json, shlex
cc = json.load(open("compile_commands.json"))
flags = ""
for e in cc:
    if "nas-message-fuzz.c" in e.get("file", ""):
        flags = " ".join(p for p in shlex.split(e["command"]) if p.startswith("-I")); break
print(flags)
PY
)"
INCS="$INCS -I../lib/gtp -I../lib/gtp/v2 -Ilib/gtp -Ilib/gtp/v2 -I../lib/app -Ilib/app -I../lib/ipfw -I../lib/metrics"

# Link every produced static lib inside one --start-group (resolves the libs' circular references),
# plus the system shared deps the parse path pulls in (yaml via app, talloc via core).
LIBS="$(find "$BD/lib" -name '*.a' | sort | tr '\n' ' ')"

ORACLE_BIN="$SRC/mayhem-oracle"
echo "=== compiling parse_oracle ==="
# shellcheck disable=SC2086
if ! $CC $SANITIZER_FLAGS -std=gnu89 -D_FILE_OFFSET_BITS=64 \
      -Wno-compound-token-split-by-macro -Wno-format -Wno-error -fcommon -Wno-typedef-redefinition \
      $INCS "$ORACLE_SRC" \
      -Wl,--start-group $LIBS -Wl,--end-group \
      -lyaml -ltalloc -lm -pthread -o "$ORACLE_BIN"; then
  echo "oracle failed to compile" >&2; emit_ctrf "open5gs-parse-oracle" 0 1 0; exit 1
fi

echo "=== running parse_oracle ==="
# Bake-free: detect_leaks=0 so a benign one-time init alloc doesn't fail the oracle; symbolize off.
out="$(ASAN_OPTIONS=detect_leaks=0:symbolize=0 "$ORACLE_BIN" 2>&1)"; rc=$?
echo "$out"

PASSED="$(printf '%s\n' "$out" | grep -c '^PASS ')"
FAILED="$(printf '%s\n' "$out" | grep -c '^FAIL ')"
: "${PASSED:=0}" "${FAILED:=0}"

# If the binary crashed (sanitizer abort) without emitting the summary line, count it as a failure.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  echo "oracle exited $rc with no FAIL lines — treating as failure" >&2
  FAILED=1
fi

emit_ctrf "open5gs-parse-oracle" "$PASSED" "$FAILED" 0
