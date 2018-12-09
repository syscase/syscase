#include "afl/types.h"

#include "afl/setup/asan.h"

#include "afl/debug.h"

#include <string.h>

/* Check ASAN options. */
void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS");

  if (x) {
    if (!strstr(x, "abort_on_error=1")) {
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");
    }

    if (!strstr(x, "symbolize=0")) {
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");
    }
  }

  x = getenv("MSAN_OPTIONS");

  if (x) {
    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR))) {
      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(
          MSAN_ERROR) " - please fix!");
    }

    if (!strstr(x, "symbolize=0")) {
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");
    }
  }
}
