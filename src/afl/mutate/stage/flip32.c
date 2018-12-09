#include "afl/types.h"

#include "afl/mutate/stage/flip32.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/flip.h"

int stage_flip32(char** argv,
                 u64* orig_hit_cnt,
                 u64* new_hit_cnt,
                 u8* out_buf,
                 s32 len,
                 u8* eff_map) {
  /* Four walking bytes. */
  stage_name = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur = 0;
  stage_max = len - 3;

  *orig_hit_cnt = *new_hit_cnt;

  for (int i = 0; i < len - 3; i++) {
    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) {
      return 0;
    }
    stage_cur++;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

  return 1;
}
