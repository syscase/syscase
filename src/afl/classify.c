#include "afl/types.h"

#include "afl/classify.h"

#include "afl/config.h"

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */
const u8 count_class_lookup8[256] = {
  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128
};

void init_count_class16(void) {
  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {
    for (b2 = 0; b2 < 256; b2++) {
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];
    }
  }
}

#ifdef __x86_64__

inline void classify_counts(u64* mem) {
  u32 i = MAP_SIZE >> 3;

  while (i--) {
    /* Optimize for sparse bitmaps. */
    if (unlikely(*mem)) {
      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];
    }

    mem++;
  }
}

#else

inline void classify_counts(u32* mem) {
  u32 i = MAP_SIZE >> 2;

  while (i--) {
    /* Optimize for sparse bitmaps. */
    if (unlikely(*mem)) {
      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
    }

    mem++;
  }
}

#endif /* ^__x86_64__ */

