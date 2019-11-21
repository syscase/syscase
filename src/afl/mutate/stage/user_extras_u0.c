#include "afl/types.h"

#include "afl/mutate/stage/user_extras_u0.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/utils/random.h"

#include <string.h>

/* Overwrite with user-supplied extras. */
int stage_user_extras_u0(char** argv,
                         u64* orig_hit_cnt,
                         u64* new_hit_cnt,
                         u8* in_buf,
                         u8* out_buf,
                         s32 len,
                         u8* eff_map) {
  s32 mutate_len;
  u8* mutate_buf = mutation_buffer_pos(out_buf, len, &mutate_len);
  s32 mutate_in_len;
  u8* mutate_in_buf = mutation_buffer_pos(in_buf, len, &mutate_in_len);

  stage_name = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur = 0;
  stage_max = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < mutate_len; i++) {
    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */
    for (int j = 0; j < extras_cnt; j++) {
      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */
      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > mutate_len - i ||
          !memcmp(extras[j].data, mutate_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {
        stage_max--;
        continue;
      }

      last_len = extras[j].len;
      memcpy(mutate_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) {
        return 0;
      }

      stage_cur++;
    }

    /* Restore all the clobbered memory. */
    memcpy(mutate_buf + i, mutate_in_buf + i, last_len);
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;

  return 1;
}
