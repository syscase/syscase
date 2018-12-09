#include "afl/types.h"

#include "afl/simplify_trace.h"

#include "afl/globals.h"

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
static const u8 simplify_lookup[256] = {
  [0]         = 1,
  [1 ... 255] = 128
};

#ifdef __x86_64__

void simplify_trace(u64* mem) {
  u32 i = MAP_SIZE >> 3;

  while (i--) {
    /* Optimize for sparse bitmaps. */
    if (unlikely(*mem)) {
      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];
    } else {
      *mem = 0x0101010101010101ULL;
    }

    mem++;
  }
}

#else

void simplify_trace(u32* mem) {
  u32 i = MAP_SIZE >> 2;

  while (i--) {
    /* Optimize for sparse bitmaps. */
    if (unlikely(*mem)) {
      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
    } else {
      *mem = 0x01010101;
    }

    mem++;
  }
}

#endif /* ^__x86_64__ */
