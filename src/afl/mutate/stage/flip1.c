#include "afl/types.h"

#include "afl/mutate/stage/flip1.h"

#include "afl/globals.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/flip.h"
#include "afl/hash.h"
#include "afl/extras.h"

int stage_flip1(char** argv, u64 *orig_hit_cnt, u64 *new_hit_cnt,
    u32 *prev_cksum, u8 *out_buf, s32 len, u8 *a_collect, u32 * a_len) {
  /* Single walking bit. */
  stage_short = "flip1";
  stage_max   = len << 3;
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  *orig_hit_cnt = queued_paths + unique_crashes;

  *prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) {
      return 0;
    }

    FLIP_BIT(out_buf, stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).
       
       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */
    if (!dumb_mode && (stage_cur & 7) == 7) {
      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == *prev_cksum) {
        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */
        if (*a_len < MAX_AUTO_EXTRA) {
          a_collect[*a_len] = out_buf[stage_cur >> 3];
        }
        (*a_len)++;

        if (*a_len >= MIN_AUTO_EXTRA && *a_len <= MAX_AUTO_EXTRA) {
          maybe_add_auto(a_collect, *a_len);
        }
      } else if (cksum != *prev_cksum) {
        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */
        if (*a_len >= MIN_AUTO_EXTRA && *a_len <= MAX_AUTO_EXTRA) {
          maybe_add_auto(a_collect, *a_len);
        }

        *a_len = 0;
        *prev_cksum = cksum;
      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */
      if (cksum != queue_cur->exec_cksum) {
        if (*a_len < MAX_AUTO_EXTRA) {
          a_collect[*a_len] = out_buf[stage_cur >> 3];
        }
        (*a_len)++;
      }
    }
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += *new_hit_cnt - *orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  return 1;
}

