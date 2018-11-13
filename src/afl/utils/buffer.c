#include "afl/types.h"
#include "afl/utils/buffer.h"

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */
void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {
  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++) {
    if (*(ptr1++) != *(ptr2++)) {
      if (f_loc == -1) {
        f_loc = pos;
      }

      l_loc = pos;
    }
  }

  *first = f_loc;
  *last = l_loc;

  return;
}

#endif /* !IGNORE_FINDS */
