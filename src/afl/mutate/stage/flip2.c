#include "afl/types.h"

#include "afl/mutate/stage/flip2.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/flip.h"

int stage_flip2(char** argv,
                u64* orig_hit_cnt,
                u64* new_hit_cnt,
                u8* out_buf,
                s32 len) {
  s32 mutate_len;
  u8* mutate_buf = mutation_buffer_pos(out_buf, len, &mutate_len);

  /* Two walking bits. */
  stage_name = "bitflip 2/1";
  stage_short = "flip2";
  stage_max = (mutate_len << 3) - 1;

  *orig_hit_cnt = *new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(mutate_buf, stage_cur);
    FLIP_BIT(mutate_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) {
      return 0;
    }

    FLIP_BIT(mutate_buf, stage_cur);
    FLIP_BIT(mutate_buf, stage_cur + 1);
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP2] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  return 1;
}
