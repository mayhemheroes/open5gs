/*
 * mayhem/asan_options.c — bake detect_leaks=0 into every fuzzer binary.
 *
 * Root cause of 0-edge "Run Failed" on gtp-message-fuzz / nas-message-fuzz /
 * ngap-message-fuzz: LeakSanitizer (enabled by default under -fsanitize=address)
 * ptrace-attaches to its own threads at process exit to scan the heap for leaks.
 * Mayhem already runs the target under ptrace to collect edge coverage, and a
 * Linux process can have only ONE tracer at a time.  LSan's attach fails, it
 * prints "LeakSanitizer has encountered a fatal error … does not work under
 * ptrace", and exits non-zero — before any edges are recorded.  The binary is
 * fine in local runs (no ptrace), so it passes smoke tests and dies only in the
 * Mayhem coverage-collection pass.
 *
 * Fix: provide a STRONG definition of __asan_default_options() that returns
 * "detect_leaks=0".  A strong symbol overrides the WEAK copy inside the ASan
 * runtime, so detect_leaks=0 is baked in regardless of the environment.  ASan
 * and UBSan (out-of-bounds, use-after-free, undefined behavior) remain fully
 * active and halting; only the redundant-for-fuzzing leak check is disabled.
 *
 * This file is compiled into every fuzzer target by tests/fuzzing/meson.build
 * via the asan_opts_src variable (added on the mayhem branch).
 */
const char *__asan_default_options(void) {
    return "detect_leaks=0";
}
