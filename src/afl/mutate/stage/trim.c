#include "afl/types.h"

#include "afl/mutate/stage/trim.h"

#include "afl/globals.h"
#include "afl/debug.h"

#include "afl/testcase/trim.h"
#include "afl/testcase/result.h"

int stage_trim(char** argv, u8 *in_buf, s32 *len) {
  if (!dumb_mode && !queue_cur->trim_done) {
    u8 res = trim_case(argv, queue_cur, in_buf);

    if (res == FAULT_ERROR) {
      FATAL("Unable to execute target application");
    }

    if (stop_soon) {
      cur_skipped_paths++;
      return 0;
    }

    /* Don't retry trimming, even if it failed. */
    queue_cur->trim_done = 1;

    if (*len != queue_cur->len) {
      *len = queue_cur->len;
    }
  }

  return 1;
}

