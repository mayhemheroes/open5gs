#!/usr/bin/env bash
#
# open5gs/mayhem/build.sh — build open5gs's two OSS-Fuzz protocol-parser harnesses as sanitized
# libFuzzer targets (+ standalone reproducers) for Mayhem.
#
# Fuzzed surface (attacker-controlled bytes off the wire, NOT files):
#   nas_message_fuzz — ogs_nas_emm_decode(): the EPS NAS / EMM+ESM message decoder. byte0 is the
#                      security-header|protocol-discriminator, byte1 the message type; the rest is the
#                      per-message IE soup (TLV/TV/LV). Links libnas_eps_dep (lib/nas/{common,eps}).
#   gtp_message_fuzz — ogs_gtp2_parse_msg(): the GTPv2-C message/IE parser used on S5/S8/S11. Header
#                      (flags|type|length|TEID|seq) + TLV IEs. Links libgtp_dep (lib/gtp + proto/core).
#
# open5gs builds with meson; the fuzzers only LINK the protocol libs (core/proto/app/ipfw + nas/gtp),
# NOT mongodb / the SBI/NF daemons. But the top-level `meson setup` CONFIGURES the whole project, so
# the apt deps in mayhem/Dockerfile must satisfy configure (gnutls/ssl/curl/microhttpd/nghttp2/mongoc/
# sctp/idn/tins/talloc/yaml). We then `ninja` ONLY the two fuzzer targets, so the heavy NF code is
# never compiled or linked. `ninja -k 0` keeps going if an unrelated target would fail.
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN.
# We pass $SANITIZER_FLAGS through meson's CFLAGS so the protocol libraries (the fuzzed code) are
# instrumented with ASan+UBSan, not just the harness.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem triage can read symbols (clang-19 defaults to DWARF-5).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# COVERAGE_FLAGS: SanitizerCoverage for the fuzzed code — REQUIRED, and easy to lose here.
# $LIB_FUZZING_ENGINE (-fsanitize=fuzzer) reaches the compiler ONLY as meson's `lib_fuzzing_engine`
# option, which meson splices into the fuzzer target's *link_args*. At link time it supplies the
# libFuzzer driver/main but instruments nothing: SanCov is a codegen pass, so it must be on the
# COMPILE line of every object we want coverage from. Without -fsanitize=fuzzer-no-link in CFLAGS
# no object carries edge counters — the binary has no __sancov_* sections, libFuzzer starts and
# warns "no interesting inputs were found so far. Is the code instrumented for coverage?", burns
# ~200k execs/s finding nothing, and every Mayhem run ends `failed=false` at edges_covered=0. That
# is a silent hard failure of the integrated gate (SPEC §6.2 item 11) that docker build, fuzz-smoke
# and a green CI job all pass. Keep this on the compile line for BOTH builds below so the
# standalone reproducer stays coverage-capable too (the callbacks come from the ASan runtime).
: "${COVERAGE_FLAGS:=-fsanitize=fuzzer-no-link}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"

SRC="${SRC:-/mayhem}"
OUT="/mayhem"
cd "$SRC"

# open5gs's headers split a macro across tokens and use printf-style logging clang -Werror trips on;
# the upstream OSS-Fuzz build.sh suppresses exactly these. -Wno-error keeps a benign upstream warning
# (it floods otherwise) from failing the build.
EXTRA_C="-Wno-compound-token-split-by-macro -Wno-format -Wno-error -fcommon"

# Sanitizer relaxation (the ONE benign-UB relaxation allowed): open5gs's NAS decoder reaches the ESM
# message container IE by casting the raw, unaligned pkbuf cursor straight to
# `ogs_nas_esm_message_container_t *` (lib/nas/eps/ies.c:810). On x86 this load is harmless, but
# UBSan's `alignment` check fires on it for essentially every NAS message that carries an ESM
# container — including upstream's OWN seed corpus (nas-message-seed.1/2.raw). Left on, it would halt
# the run on the very first interesting input and mask real bugs. Drop ONLY the `alignment` check;
# every other UBSan check and all of ASan stay halting (-fno-sanitize-recover=all is still in force).
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment"

# Second benign-UB relaxation, same character as the alignment one above and needed for the same
# reason. The vendored asn1c PER runtime opens an open-type chunk with `uint8_t *buf = 0; size_t
# bufLen = 0;` and, when the first chunk length decodes as 0, skips the REALLOC branch and calls
# `per_get_many_bits(pd, buf + bufLen, 0, 0)` (lib/asn1c/common/aper_opentype.c:43). That is a literal
# `NULL + 0`: UB by the letter of C, completely harmless in practice (0 bits are read, nothing is
# dereferenced). UBSan's `pointer-overflow` check fires on it for the all-zero 5-byte input — which is
# in upstream's OWN ngap/s1ap seed corpus — so with -fno-sanitize-recover=all the process aborts on
# seed #1 of every run. Both APER targets (ngap_message_fuzz, s1ap_message_fuzz) then die before
# covering anything, which is precisely the 0-edge integrated-gate failure this relaxation exists to
# avoid, and it masks every real ASN.1 bug behind it. Drop ONLY `pointer-overflow`; ASan and every
# other UBSan check stay halting.
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow"
export CC CXX
# $DEBUG_FLAGS (-g -gdwarf-3) after $SANITIZER_FLAGS so DWARF-3 overrides the -g inside SANITIZER_FLAGS.
export CFLAGS="$SANITIZER_FLAGS $COVERAGE_FLAGS $DEBUG_FLAGS $EXTRA_C"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="$SANITIZER_FLAGS $COVERAGE_FLAGS $DEBUG_FLAGS"

FUZZERS="gtp_message_fuzz nas_message_fuzz ngap_message_fuzz s1ap_message_fuzz pfcp_message_fuzz nas_5gs_message_fuzz sbi_nf_profile_fuzz sbi_sm_context_fuzz"

# ── 0) asan_options shim — disable LSan to prevent 0-edge "Run Failed" in Mayhem ─────────────────
# Root cause: -fsanitize=address enables LeakSanitizer (LSan) by default.  At process exit LSan
# ptrace-attaches to its own threads to scan the heap for leaks.  Mayhem already runs the target
# under ptrace for edge coverage, and a Linux process can have only ONE tracer.  LSan's attach
# fails → process exits non-zero BEFORE any edges are recorded → Mayhem sees 0-edge "Run Failed".
# Fix: compile mayhem/asan_options.c (which provides a STRONG __asan_default_options returning
# "detect_leaks=0") into a separate object, then bake it into every fuzzer via meson's c_link_args.
# Using -Dc_link_args injects the object project-wide so all three harnesses get it without
# touching the upstream tests/fuzzing/meson.build (keeping the mayhem layer purely additive).
ASAN_OBJ="$SRC/asan_options.o"
$CC $DEBUG_FLAGS -c "$SRC/mayhem/asan_options.c" -o "$ASAN_OBJ"

# ── 1) libFuzzer targets ───────────────────────────────────────────────────────────────────────
# --default-library=static so the fuzzer binaries embed the protocol libs (self-contained); talloc
# resolves transitively from libogscore's pkg-config (no need to spell it out). lib_fuzzing_engine is
# passed as a meson STRING option that becomes the fuzzer's link_args, so it must be a SINGLE clang
# argument (e.g. -fsanitize=fuzzer) — appending extra libs here makes clang treat the whole string as
# one bad '-fsanitize=' value.  Instead we inject asan_options.o via -Dc_link_args (project-wide
# link args, independent of the per-target lib_fuzzing_engine option).
BD="$SRC/mayhem-build"
rm -rf "$BD"
meson setup "$BD" --default-library=static -Dfuzzing=true \
  -Dlib_fuzzing_engine="$LIB_FUZZING_ENGINE" \
  -Dc_link_args="$ASAN_OBJ"
ninja -C "$BD" -k 0 -j"$MAYHEM_JOBS" \
  tests/fuzzing/gtp_message_fuzz tests/fuzzing/nas_message_fuzz tests/fuzzing/ngap_message_fuzz \
  tests/fuzzing/s1ap_message_fuzz tests/fuzzing/pfcp_message_fuzz tests/fuzzing/nas_5gs_message_fuzz \
  tests/fuzzing/sbi_nf_profile_fuzz tests/fuzzing/sbi_sm_context_fuzz
for f in $FUZZERS; do
  cp "$BD/tests/fuzzing/$f" "$OUT/$f"
  echo "built libFuzzer target: $OUT/$f"
done

# ── 2) standalone reproducers ────────────────────────────────────────────────────────────────────
# Re-run the SAME meson config but point lib_fuzzing_engine at the StandaloneFuzzTargetMain object
# (a run-once driver: feeds each argv file to LLVMFuzzerTestOneInput, no libFuzzer runtime).
SBD="$SRC/mayhem-standalone"
rm -rf "$SBD"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/standalone_main.o"
# Same single-token rule as above: lib_fuzzing_engine becomes the fuzzer's link_args verbatim, so
# point it at the standalone driver object alone.  asan_options.o still baked in via c_link_args.
meson setup "$SBD" --default-library=static -Dfuzzing=true \
  -Dlib_fuzzing_engine="$SRC/standalone_main.o" \
  -Dc_link_args="$ASAN_OBJ"
ninja -C "$SBD" -k 0 -j"$MAYHEM_JOBS" \
  tests/fuzzing/gtp_message_fuzz tests/fuzzing/nas_message_fuzz tests/fuzzing/ngap_message_fuzz \
  tests/fuzzing/s1ap_message_fuzz tests/fuzzing/pfcp_message_fuzz tests/fuzzing/nas_5gs_message_fuzz \
  tests/fuzzing/sbi_nf_profile_fuzz tests/fuzzing/sbi_sm_context_fuzz
for f in $FUZZERS; do
  cp "$SBD/tests/fuzzing/$f" "$OUT/$f-standalone"
  echo "built standalone reproducer: $OUT/$f-standalone"
done

# ── 3) test suite for mayhem/test.sh ───────────────────────────────────────────────────────────────
# test.sh runs a self-contained golden oracle over the parse path (mayhem/test.sh compiles + runs it
# against the libFuzzer targets' own libs). Nothing to pre-build here beyond the fuzzers above; the
# oracle reuses the libFuzzer binaries (it replays known PDUs through them in standalone form).

echo "build.sh complete:"
ls -la $(for f in $FUZZERS; do echo "$OUT/$f" "$OUT/$f-standalone"; done) 2>&1 || true
