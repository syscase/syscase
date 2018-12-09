#include "afl/types.h"

#include "afl/mutate/stage/flip8.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/hash.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/flip.h"

#include <string.h>

int stage_flip8(char** argv,
                u64* orig_hit_cnt,
                u64* new_hit_cnt,
                u8* out_buf,
                s32 len,
                u8* eff_map,
                u32* eff_cnt) {
  /* Walking byte. */
  stage_name = "bitflip 8/8";
  stage_short = "flip8";
  stage_max = len;

  *orig_hit_cnt = *new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) {
      return 0;
    }

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */
    if (!eff_map[EFF_APOS(stage_cur)]) {
      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */
      if (!dumb_mode && len >= EFF_MIN_LEN) {
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      } else {
        cksum = ~queue_cur->exec_cksum;
      }

      if (cksum != queue_cur->exec_cksum) {
        eff_map[EFF_APOS(stage_cur)] = 1;
        (*eff_cnt)++;
      }
    }

    out_buf[stage_cur] ^= 0xFF;
  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */
  if (*eff_cnt != EFF_ALEN(len) &&
      *eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {
    memset(eff_map, 1, EFF_ALEN(len));

    blocks_eff_select += EFF_ALEN(len);
  } else {
    blocks_eff_select += *eff_cnt;
  }

  blocks_eff_total += EFF_ALEN(len);

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8] += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  return 1;
}
