#include "afl/types.h"

#include "afl/bitmap/minimize.h"

#include "afl/config.h"

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */
void minimize_bits(u8* dst, u8* src) {
  u32 i = 0;

  while (i < MAP_SIZE) {
    if (*(src++)) {
      dst[i >> 3] |= 1 << (i & 7);
    }

    i++;
  }
}
