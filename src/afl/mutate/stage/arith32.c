#include "afl/types.h"

#include "afl/mutate/stage/arith32.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/bitflip.h"

/* 32-bit arithmetics, both endians. */
int stage_arith32(char** argv,
                  u64* orig_hit_cnt,
                  u64* new_hit_cnt,
                  u8* out_buf,
                  s32 len,
                  u8* eff_map) {
  stage_name = "arith 32/8";
  stage_short = "arith32";
  stage_cur = 0;
  stage_max = 4 * (len - 3) * ARITH_MAX;

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < len - 3; i++) {
    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (int j = 1; j <= ARITH_MAX; j++) {
      u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */
      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {
        stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;

      } else {
        stage_max--;
      }

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {
        stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      /* Big endian next. */
      stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {
        stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {
        stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;

      } else {
        stage_max--;
      }

      *(u32*)(out_buf + i) = orig;
    }
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH32] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

  return 1;
}
