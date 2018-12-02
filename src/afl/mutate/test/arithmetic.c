#include "afl/types.h"
#include "afl/mutate/test/arithmetic.h"

#include "afl/config.h"

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */
u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {
  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) {
    return 1;
  }

  /* See if one-byte adjustments to any byte could produce this result. */
  for (i = 0; i < blen; i++) {
    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one byte differs and the values are within range, return 1. */
  if (diffs == 1) {
    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX) {
      return 1;
    }
  }

  if (blen == 1) {
    return 0;
  }

  /* See if two-byte adjustments to any byte would produce this result. */
  diffs = 0;

  for (i = 0; i < blen / 2; i++) {
    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one word differs and the values are within range, return 1. */
  if (diffs == 1) {
    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) {
      return 1;
    }

    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) {
      return 1;
    }
  }

  /* Finally, let's do the same thing for dwords. */
  if (blen == 4) {
    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {
      return 1;
    }

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {
      return 1;
    }

  }

  return 0;
}

