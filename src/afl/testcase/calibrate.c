#include "afl/types.h"

#include "afl/testcase/calibrate.h"

#include "afl/globals.h"
#include "afl/debug.h"

#include "afl/bitmap.h"
#include "afl/bitmap/favorable.h"
#include "afl/queue_entry.h"
#include "afl/hash.h"
#include "afl/testcase.h"
#include "afl/testcase/result.h"
#include "afl/forkserver.h"
#include "afl/capture/stats.h"
#include "afl/utils/time.h"
#include "afl/syscase/coverage.h"

#include <string.h>

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */
u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {
  static u8 first_trace[MAP_SIZE];

  u8  fault = 0, new_bits = 0, var_detected = 0,
      first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */
  if (!from_queue || resuming_fuzz) {
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);
  }

  q->cal_failed++;

  stage_name = "calibration";
  stage_max  = fast_cal ? 3 : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */
  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid) {
    init_forkserver(argv);
  }

  // OPTEE-DEBUG START
  ACTF("Initialized fork server");
  fflush(stdout);
  // OPTEE-DEBUG END
  if (q->exec_cksum) {
    memcpy(first_trace, trace_bits, MAP_SIZE);
  }

  start_us = get_cur_time_us();

  if (coverage_mode) {
    // Rotate boot path and logs
    rotate_boot_coverage_files();
  }

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) {
      show_stats();
    }

    write_to_testcase(use_mem, q->len);

    fault = run_target(argv, use_tmout);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */
    if (stop_soon || fault != crash_mode) {
      goto abort_calibration;
    }

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {

      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) {
        new_bits = hnb;
      }

      if (q->exec_cksum) {
        u32 i;

        for (i = 0; i < MAP_SIZE; i++) {
          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {
            var_bytes[i] = 1;
            stage_max    = CAL_CYCLES_LONG;
          }
        }

        var_detected = 1;
      } else {
        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);
      }
    }
  }

  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */
  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */
  if (!dumb_mode && first_run && !fault && !new_bits) {
    fault = FAULT_NOBITS;
  }

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths. */
  if (var_detected) {
    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior) {
      mark_as_variable(q);
      queued_variable++;
    }
  }

  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;

  if (!first_run) {
    show_stats();
  }

  return fault;
}

