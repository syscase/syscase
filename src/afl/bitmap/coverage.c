#include "afl/types.h"

#include "afl/bitmap/coverage.h"

#include "afl/debug.h"
#include "afl/globals.h"

#include "afl/bitmap.h"

/* Examine map coverage. Called once, for first test case. */
void check_map_coverage(void) {
  u32 i;

  if (count_bytes(trace_bits) < 100) {
    return;
  }

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++) {
    if (trace_bits[i]) {
      return;
    }
  }

  WARNF("Recompile binary with newer version of afl to improve coverage!");
}
