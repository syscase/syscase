#include "afl/types.h"

#include "afl/mutate/stage/interest16.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/arithmetic.h"
#include "afl/mutate/test/bitflip.h"
#include "afl/mutate/test/interest.h"

/* Setting 16-bit integers, both endians. */
int stage_interest16(char** argv,
                     u64* orig_hit_cnt,
                     u64* new_hit_cnt,
                     u8* out_buf,
                     s32 len,
                     u8* eff_map) {
  s32 mutate_len;
  u8* mutate_buf = mutation_buffer_pos(out_buf, len, &mutate_len);

  stage_name = "interest 16/8";
  stage_short = "int16";
  stage_cur = 0;
  stage_max = 2 * (mutate_len - 1) * (sizeof(interesting_16) >> 1);

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < mutate_len - 1; i++) {
    u16 orig = *(u16*)(mutate_buf + i);

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (int j = 0; j < sizeof(interesting_16) / 2; j++) {
      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */
      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {
        stage_val_type = STAGE_VAL_LE;

        *(u16*)(mutate_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {
        stage_val_type = STAGE_VAL_BE;

        *(u16*)(mutate_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }
    }

    *(u16*)(mutate_buf + i) = orig;
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  return 1;
}
