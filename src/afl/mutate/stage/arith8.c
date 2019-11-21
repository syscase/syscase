#include "afl/types.h"

#include "afl/mutate/stage/arith8.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/bitflip.h"

/* 8-bit arithmetics. */
int stage_arith8(char** argv,
                 u64* orig_hit_cnt,
                 u64* new_hit_cnt,
                 u8* out_buf,
                 s32 len,
                 u8* eff_map) {
  s32 mutate_len;
  u8* mutate_buf = mutation_buffer_pos(out_buf, len, &mutate_len);

  stage_name = "arith 8/8";
  stage_short = "arith8";
  stage_cur = 0;
  stage_max = 2 * mutate_len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < mutate_len; i++) {
    u8 orig = mutate_buf[i];

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (int j = 1; j <= ARITH_MAX; j++) {
      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */
      if (!could_be_bitflip(r)) {
        stage_cur_val = j;
        mutate_buf[i] = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {
        stage_cur_val = -j;
        mutate_buf[i] = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      mutate_buf[i] = orig;
    }
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH8] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;
  return 1;
}
