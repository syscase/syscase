#include "afl/types.h"
#include "afl/fuzz/common.h"

#include "afl/globals.h"

#include "afl/postprocessor.h"
#include "afl/testcase.h"
#include "afl/testcase/result.h"
#include "afl/capture.h"
#include "afl/capture/stats.h"
#include "afl/syscase/coverage.h"

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */
u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {
  u8 fault;

  if (post_handler) {
    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len) {
      return 0;
    }
  }

  write_to_testcase(out_buf, len);

  fault = run_target(argv, exec_tmout);

  if (stop_soon) {
    return 1;
  }

  if (fault == FAULT_TMOUT) {
    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else {
    subseq_tmouts = 0;
  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */
  if (skip_requested) {
     skip_requested = 0;
     cur_skipped_paths++;
     return 1;
  }

  /* This handles FAULT_ERROR for us: */
  queued_discovered += save_if_interesting(argv, out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max) {
    show_stats();
  }

  return 0;
}

