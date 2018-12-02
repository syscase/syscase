#include "afl/types.h"
#include "afl/mutate/test/interest.h"

#include "afl/config.h"

/* Interesting values, as per config.h */
s8  interesting_8[]  = { INTERESTING_8 };
s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* Last but not least, a similar helper to see if insertion of an 
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */
u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {
  u32 i, j;

  if (old_val == new_val) {
    return 1;
  }

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */
  for (i = 0; i < blen; i++) {
    for (j = 0; j < sizeof(interesting_8); j++) {
      u32 tval = (old_val & ~(0xff << (i * 8))) |
                 (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) {
        return 1;
      }
    }
  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */
  if (blen == 2 && !check_le) {
    return 0;
  }

  /* See if two-byte insertions over old_val could give us new_val. */
  for (i = 0; i < blen - 1; i++) {
    for (j = 0; j < sizeof(interesting_16) / 2; j++) {
      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) {
        return 1;
      }

      /* Continue here only if blen > 2. */
      if (blen > 2) {
        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) {
          return 1;
        }
      }
    }
  }

  if (blen == 4 && check_le) {
    /* See if four-byte insertions could produce the same result
       (LE only). */
    for (j = 0; j < sizeof(interesting_32) / 4; j++) {
      if (new_val == (u32)interesting_32[j]) {
        return 1;
      }
    }
  }

  return 0;
}

