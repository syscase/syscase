#include "afl/types.h"
#include "afl/mutate/stage/syscase1.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/flip.h"

int stage_syscase1(char** argv, u64 *orig_hit_cnt, u64 *new_hit_cnt,
    u32 *prev_cksum, u8 *out_buf, s32 len, u8 *a_collect, u32 * a_len) {
  stage_short = "sysc1";
  stage_max   = len << 3;
  stage_name  = "sycase 1";

  stage_val_type = STAGE_VAL_NONE;

  *orig_hit_cnt = queued_paths + unique_crashes;

  *prev_cksum = queue_cur->exec_cksum;

  // TODO: Implement stage here
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, 12);

    if (common_fuzz_stuff(argv, out_buf, len)) {
      return 0;
    }

    FLIP_BIT(out_buf, 12);
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_SYSCASE1]  += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_SYSCASE1] += stage_max;

  return 1;
}

