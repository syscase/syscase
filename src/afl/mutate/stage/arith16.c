#include "afl/types.h"

#include "afl/mutate/stage/arith16.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/bitflip.h"

/* 16-bit arithmetics, both endians. */
int stage_arith16(char** argv,
                  u64* orig_hit_cnt,
                  u64* new_hit_cnt,
                  u8* out_buf,
                  s32 len,
                  u8* eff_map) {
  s32 mutate_len;
  u8* mutate_buf = mutation_buffer_pos(out_buf, len, &mutate_len);

  stage_name = "arith 16/8";
  stage_short = "arith16";
  stage_cur = 0;
  stage_max = 4 * (mutate_len - 1) * ARITH_MAX;

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < mutate_len - 1; i++) {
    u16 orig = *(u16*)(mutate_buf + i);

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (int j = 1; j <= ARITH_MAX; j++) {
      u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */
      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {
        stage_cur_val = j;
        *(u16*)(mutate_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {
        stage_cur_val = -j;
        *(u16*)(mutate_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      /* Big endian comes next. Same deal. */
      stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {
        stage_cur_val = j;
        *(u16*)(mutate_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;
      } else {
        stage_max--;
      }

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {
        stage_cur_val = -j;
        *(u16*)(mutate_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) {
          return 0;
        }
        stage_cur++;

      } else {
        stage_max--;
      }

      *(u16*)(mutate_buf + i) = orig;
    }
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  return 1;
}
