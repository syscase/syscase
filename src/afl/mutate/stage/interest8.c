#include "afl/types.h"

#include "afl/mutate/stage/interest8.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/arithmetic.h"
#include "afl/mutate/test/bitflip.h"
#include "afl/mutate/test/interest.h"

int stage_interest8(char** argv,
                    u64* orig_hit_cnt,
                    u64* new_hit_cnt,
                    u8* out_buf,
                    s32 len,
                    u8* eff_map) {
  s32 mutate_len;
  u8* mutate_buf = mutation_buffer_pos(out_buf, len, &mutate_len);

  stage_name = "interest 8/8";
  stage_short = "int8";
  stage_cur = 0;
  stage_max = mutate_len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  *orig_hit_cnt = *new_hit_cnt;

  /* Setting 8-bit integers. */
  for (int i = 0; i < mutate_len; i++) {
    u8 orig = mutate_buf[i];

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= sizeof(interesting_8);
      continue;
    }

    stage_cur_byte = i;

    for (int j = 0; j < sizeof(interesting_8); j++) {
      /* Skip if the value could be a product of bitflips or arithmetics. */
      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      mutate_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) {
        return 0;
      }

      mutate_buf[i] = orig;
      stage_cur++;
    }
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST8] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  return 1;
}
