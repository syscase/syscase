#include "afl/types.h"
#include "afl/mutate/stage/flip4.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/flip.h"
#include "afl/mutate/eff.h"

int stage_flip4(char** argv, u64 *orig_hit_cnt, u64 *new_hit_cnt,
    u8 *out_buf, s32 len) {
  /* Four walking bits. */
  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  *orig_hit_cnt = *new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) {
      return 0;
    }

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP4]  += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  return 1;
}

