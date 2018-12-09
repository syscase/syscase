#include "afl/types.h"
#include "afl/fuzz/one.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include "afl/testcase/result.h"
#include "afl/testcase/calibrate.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/stage/trim.h"
#include "afl/mutate/stage/flip1.h"
#include "afl/mutate/stage/flip2.h"
#include "afl/mutate/stage/flip4.h"
#include "afl/mutate/stage/flip8.h"
#include "afl/mutate/stage/flip16.h"
#include "afl/mutate/stage/flip32.h"
#include "afl/mutate/stage/arith8.h"
#include "afl/mutate/stage/arith16.h"
#include "afl/mutate/stage/arith32.h"
#include "afl/mutate/stage/interest8.h"
#include "afl/mutate/stage/interest16.h"
#include "afl/mutate/stage/interest32.h"
#include "afl/mutate/stage/user_extras_u0.h"
#include "afl/mutate/stage/user_extras_ui.h"
#include "afl/mutate/stage/auto_extras_a0.h"
#include "afl/mutate/stage/havoc.h"
#include "afl/utils/random.h"

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>


/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */
u32 calculate_score(struct queue_entry* q) {
  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */
  if (q->exec_us * 0.1 > avg_exec_us) {
    perf_score = 10;
  } else if (q->exec_us * 0.25 > avg_exec_us) {
    perf_score = 25;
  } else if (q->exec_us * 0.5 > avg_exec_us) {
    perf_score = 50;
  } else if (q->exec_us * 0.75 > avg_exec_us) {
    perf_score = 75;
  } else if (q->exec_us * 4 < avg_exec_us) {
    perf_score = 300;
  } else if (q->exec_us * 3 < avg_exec_us) {
    perf_score = 200;
  } else if (q->exec_us * 2 < avg_exec_us) {
    perf_score = 150;
  }

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */
  if (q->bitmap_size * 0.3 > avg_bitmap_size) {
    perf_score *= 3;
  } else if (q->bitmap_size * 0.5 > avg_bitmap_size) {
    perf_score *= 2;
  } else if (q->bitmap_size * 0.75 > avg_bitmap_size) {
    perf_score *= 1.5;
  } else if (q->bitmap_size * 3 < avg_bitmap_size) {
    perf_score *= 0.25;
  } else if (q->bitmap_size * 2 < avg_bitmap_size) {
    perf_score *= 0.5;
  } else if (q->bitmap_size * 1.5 < avg_bitmap_size) {
    perf_score *= 0.75;
  }

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */
  if (q->handicap >= 4) {
    perf_score *= 4;
    q->handicap -= 4;
  } else if (q->handicap) {
    perf_score *= 2;
    q->handicap--;
  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */
  switch (q->depth) {
    case 0 ... 3:
      break;
    case 4 ... 7:
      perf_score *= 2;
      break;
    case 8 ... 13:
      perf_score *= 3;
      break;
    case 14 ... 25:
      perf_score *= 4;
      break;
    default:
      perf_score *= 5;
  }

  /* Make sure that we don't go over limit. */
  if (perf_score > HAVOC_MAX_MULT * 100) {
    perf_score = HAVOC_MAX_MULT * 100;
  }

  return perf_score;
}

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */
u8 fuzz_one(char** argv) {
  s32 len, fd;
  u8  *in_buf, *out_buf, *orig_in, *eff_map = 0;
  u64 orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8  ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS
  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */
  if (queue_cur->depth > 1) {
    return 1;
  }
#else
  if (pending_favored) {
    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */
    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) {
      return 1;
    }

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {
    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */
    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {
      if (UR(100) < SKIP_NFAV_NEW_PROB) {
        return 1;
      }
    } else {
      if (UR(100) < SKIP_NFAV_OLD_PROB) {
        return 1;
      }
    }
  }
#endif /* ^IGNORE_FINDS */

  if (not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* Map the test case into memory. */
  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) {
    PFATAL("Unable to open '%s'", queue_cur->fname);
  }

  len = queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) {
    PFATAL("Unable to mmap '%s'", queue_cur->fname);
  }

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */
  out_buf = ck_alloc_nozero(len);

  subseq_tmouts = 0;

  cur_depth = queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/
  if (queue_cur->cal_failed) {
    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {
      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR) {
        FATAL("Unable to execute target application");
      }
    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;
      goto abandon_entry;
    }
  }

  /************
   * TRIMMING *
   ************/
  if(!stage_trim(argv, in_buf, &len)) {
    goto abandon_entry;
  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/
  orig_perf = perf_score = calculate_score(queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */
  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det) {
    goto havoc_stage;
  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */
  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1) {
    goto havoc_stage;
  }

  doing_det = 1;


  if(!stage_flip1(argv, &orig_hit_cnt, &new_hit_cnt, &prev_cksum, out_buf, len, a_collect, &a_len)) {
    goto abandon_entry;
  }

  if(!stage_flip2(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len)) {
    goto abandon_entry;
  }

  if(!stage_flip4(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len)) {
    goto abandon_entry;
  }

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */
  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }

  if(!stage_flip8(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map, &eff_cnt)) {
    goto abandon_entry;
  }

  if (len < 2) {
    goto skip_bitflip;
  }

  if(!stage_flip16(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

  if (len < 4) {
    goto skip_bitflip;
  }

  if(!stage_flip32(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

skip_bitflip:

  if (no_arith) {
    goto skip_arith;
  }

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  if(!stage_arith8(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

  if (len < 2) {
    goto skip_arith;
  }

  if(!stage_arith16(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

  if (len < 4) {
    goto skip_arith;
  }

  if(!stage_arith32(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  if(!stage_interest8(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

  if (no_arith || len < 2) {
    goto skip_interest;
  }

  if(!stage_interest16(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

  if (len < 4) {
    goto skip_interest;
  }

  if(!stage_interest32(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/
  if (!extras_cnt) {
    goto skip_user_extras;
  }

  if(!stage_user_extras_u0(argv, &orig_hit_cnt, &new_hit_cnt, in_buf, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

  if(!stage_user_extras_ui(argv, &orig_hit_cnt, &new_hit_cnt, out_buf, len, eff_map)) {
    goto abandon_entry;
  }


skip_user_extras:

  if (!a_extras_cnt) {
    goto skip_extras;
  }

  if(!stage_auto_extras_a0(argv, &orig_hit_cnt, &new_hit_cnt, in_buf, out_buf, len, eff_map)) {
    goto abandon_entry;
  }

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */
  if (!queue_cur->passed_det) {
    mark_as_det_done(queue_cur);
  }

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  if(!stage_havoc(argv, &orig_hit_cnt, &new_hit_cnt, &in_buf, &out_buf, len, eff_map, splice_cycle,
        orig_perf, &perf_score, doing_det, orig_in)) {
    goto abandon_entry;
  }

  ret_val = 0;

abandon_entry:
  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */
  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;
    pending_not_fuzzed--;
    if (queue_cur->favored) {
      pending_favored--;
    }
  }

  munmap(orig_in, queue_cur->len);

  if (in_buf != orig_in) {
    ck_free(in_buf);
  }
  ck_free(out_buf);
  ck_free(eff_map);

  return ret_val;

#undef FLIP_BIT

}

