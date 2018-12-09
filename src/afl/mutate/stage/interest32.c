#include "afl/types.h"

#include "afl/mutate/stage/interest32.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/bitflip.h"
#include "afl/mutate/test/arithmetic.h"
#include "afl/mutate/test/interest.h"

/* Setting 32-bit integers, both endians. */
int stage_interest32(char** argv, u64 *orig_hit_cnt, u64 *new_hit_cnt,
    u8 *out_buf, s32 len, u8 *eff_map) {
  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < len - 3; i++) {
    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }

    stage_cur_byte = i;

    for (int j = 0; j < sizeof(interesting_32) / 4; j++) {
      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */
      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {
        stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {
        stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }
    }

    *(u32*)(out_buf + i) = orig;
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST32]  += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

  return 1;
}

