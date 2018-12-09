#include "afl/types.h"

#include "afl/testcase/trim.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include "afl/bitmap/favorable.h"
#include "afl/capture/stats.h"
#include "afl/describe.h"
#include "afl/hash.h"
#include "afl/queue_entry.h"
#include "afl/syscase/coverage.h"
#include "afl/testcase.h"
#include "afl/testcase/result.h"
#include "afl/utils/math.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */
u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf) {
  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8 needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */
  if (q->len < 5) {
    return 0;
  }

  stage_name = tmp;
  bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */
  len_p2 = next_p2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */
  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {
    u32 remove_pos = remove_len;

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

    stage_cur = 0;
    stage_max = q->len / remove_len;

    while (remove_pos < q->len) {
      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 cksum;

      write_with_gap(in_buf, q->len, remove_pos, trim_avail);

      fault = run_target(argv, exec_tmout);
      trim_execs++;

      if (stop_soon || fault == FAULT_ERROR) {
        goto abort_trimming;
      }

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? */
      cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */
      if (cksum == q->exec_cksum) {
        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2 = next_p2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */
        if (!needs_write) {
          needs_write = 1;
          memcpy(clean_trace, trace_bits, MAP_SIZE);
        }
      } else {
        remove_pos += remove_len;
      }

      /* Since this can be slow, update the screen every now and then. */
      if (!(trim_exec++ % stats_update_freq)) {
        show_stats();
      }
      stage_cur++;
    }

    remove_len >>= 1;
  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */
  if (needs_write) {
    s32 fd;

    unlink(q->fname); /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) {
      PFATAL("Unable to create '%s'", q->fname);
    }

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);
  }

abort_trimming:

  bytes_trim_out += q->len;
  return fault;
}
