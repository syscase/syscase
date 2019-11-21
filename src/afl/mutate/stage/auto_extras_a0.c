#include "afl/types.h"

#include "afl/mutate/stage/auto_extras_a0.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"

#include <string.h>

int stage_auto_extras_a0(char** argv,
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

  stage_name = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur = 0;
  stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * mutate_len;

  stage_val_type = STAGE_VAL_NONE;

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < mutate_len; i++) {
    u32 last_len = 0;

    stage_cur_byte = i;

    for (int j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {
      /* See the comment in the earlier code; extras are sorted by size. */
      if (a_extras[j].len > mutate_len - i ||
          !memcmp(a_extras[j].data, mutate_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, a_extras[j].len))) {
        stage_max--;
        continue;
      }

      last_len = a_extras[j].len;
      memcpy(mutate_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) {
        return 0;
      }

      stage_cur++;
    }

    /* Restore all the clobbered memory. */
    memcpy(mutate_buf + i, mutate_in_buf + i, last_len);
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;

  return 1;
}
