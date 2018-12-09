#include "afl/types.h"

#include "afl/mutate/test/bitflip.h"

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */
u8 could_be_bitflip(u32 xor_val) {
  u32 sh = 0;

  if (!xor_val) {
    return 1;
  }

  /* Shift left until first bit set. */
  while (!(xor_val & 1)) {
    sh++;
    xor_val >>= 1;
  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */
  if (xor_val == 1 || xor_val == 3 || xor_val == 15) {
    return 1;
  }

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */
  if (sh & 7) {
    return 0;
  }

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) {
    return 1;
  }

  return 0;
}
