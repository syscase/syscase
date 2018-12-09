#include "afl/types.h"

#include "afl/utils/math.h"

/* Find first power of two greater or equal to val (assuming val under
   2^31). */
u32 next_p2(u32 val) {
  u32 ret = 1;
  while (val > ret) {
    ret <<= 1;
  }
  return ret;
}
