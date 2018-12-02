#include "afl/types.h"
#include "afl/fuzz/one.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include "afl/testcase/trim.h"
#include "afl/testcase/result.h"
#include "afl/testcase/calibrate.h"
#include "afl/mutate/flip.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/bitflip.h"
#include "afl/mutate/test/arithmetic.h"
#include "afl/mutate/test/interest.h"
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
#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/queue_entry.h"
#include "afl/extras.h"
#include "afl/hash.h"
#include "afl/utils/random.h"
#include "afl/utils/buffer.h"

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */
u32 choose_block_len(u32 limit) {
  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m) {
    rlim = 1;
  }

  switch (UR(rlim)) {
    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;

    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;

    default: 
      if (UR(10)) {
        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;
      } else {
        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;
      }
  }

  if (min_value >= limit) {
    min_value = 1;
  }

  return min_value + UR(MIN(max_value, limit) - min_value + 1);
}

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
  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
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
  if (!dumb_mode && !queue_cur->trim_done) {
    u8 res = trim_case(argv, queue_cur, in_buf);

    if (res == FAULT_ERROR) {
      FATAL("Unable to execute target application");
    }

    if (stop_soon) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */
    queue_cur->trim_done = 1;

    if (len != queue_cur->len) {
      len = queue_cur->len;
    }
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

  /* Insertion of user-supplied extras. */
  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++) {
    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++) {
      if (len + extras[j].len > MAX_FILE) {
        stage_max--; 
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      stage_cur++;
    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];
  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:

  if (!a_extras_cnt) {
    goto skip_extras;
  }

  stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {
    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {
      /* See the comment in the earlier code; extras are sorted by size. */
      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {
        stage_max--;
        continue;
      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) {
        goto abandon_entry;
      }

      stage_cur++;
    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;

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

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */
  if (!splice_cycle) {
    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;
  } else {
    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;
  }

  if (stage_max < HAVOC_MIN) {
    stage_max = HAVOC_MIN;
  }

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {
      switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {
        case 0:
          /* Flip a single bit somewhere. Spooky! */
          FLIP_BIT(out_buf, UR(temp_len << 3));
          break;

        case 1: 
          /* Set byte to interesting value. */
          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:
          /* Set word to interesting value, randomly choosing endian. */
          if (temp_len < 2) {
            break;
          }

          if (UR(2)) {
            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];
          } else {
            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);
          }

          break;

        case 3:
          /* Set dword to interesting value, randomly choosing endian. */
          if (temp_len < 4) {
            break;
          }

          if (UR(2)) {
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];
          } else {
            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);
          }

          break;

        case 4:
          /* Randomly subtract from byte. */
          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:
          /* Randomly add to byte. */
          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:
          /* Randomly subtract from word, random endian. */
          if (temp_len < 2) {
            break;
          }

          if (UR(2)) {
            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);
          }

          break;

        case 7:
          /* Randomly add to word, random endian. */
          if (temp_len < 2) {
            break;
          }

          if (UR(2)) {
            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);
          }

          break;

        case 8:
          /* Randomly subtract from dword, random endian. */
          if (temp_len < 4) {
            break;
          }

          if (UR(2)) {
            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {
            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);
          }

          break;

        case 9:
          /* Randomly add to dword, random endian. */
          if (temp_len < 4) {
            break;
          }

          if (UR(2)) {
            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);
          }

          break;

        case 10:
          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */
          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;

        case 11 ... 12: {
            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */
            u32 del_from, del_len;

            if (temp_len < 2) {
              break;
            }

            /* Don't delete too much. */
            del_len = choose_block_len(temp_len - 1);

            del_from = UR(temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;
          }

        case 13:
          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {
            /* Clone bytes (75%) or insert a block of constant bytes (25%). */
            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {
              clone_len  = choose_block_len(temp_len);
              clone_from = UR(temp_len - clone_len + 1);
            } else {
              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;
            }

            clone_to   = UR(temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */
            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */
            if (actually_clone) {
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            } else {
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);
            }

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;
          }

          break;

        case 14: {
            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */
            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) {
              break;
            }

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {
              if (copy_from != copy_to) {
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
              }
            } else {
              memset(out_buf + copy_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);
            }

            break;
          }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */
        case 15: {
            /* Overwrite bytes with an extra. */
            if (!extras_cnt || (a_extras_cnt && UR(2))) {
              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */
              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) {
                break;
              }

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {
              /* No auto extras or odds in our favor. Use the dictionary. */
              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) {
                break;
              }

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);
            }

            break;
          }

        case 16: {
            u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */
            if (!extras_cnt || (a_extras_cnt && UR(2))) {
              use_extra = UR(a_extras_cnt);
              extra_len = a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) {
                break;
              }

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);
            } else {
              use_extra = UR(extras_cnt);
              extra_len = extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) {
                break;
              }

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);
            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);

            ck_free(out_buf);
            out_buf   = new_buf;
            temp_len += extra_len;

            break;
          }
      }
    }

    if (common_fuzz_stuff(argv, out_buf, temp_len)) {
      goto abandon_entry;
    }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */
    if (temp_len < len) {
      out_buf = ck_realloc(out_buf, len);
    }
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */
    if (queued_paths != havoc_queued) {
      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }
      havoc_queued = queued_paths;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS
  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */
retry_splicing:
  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {
    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */
    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */
    do {
      tid = UR(queued_paths);
    } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) {
      target = target->next_100;
      tid -= 100;
    }
    while (tid--) {
      target = target->next;
    }

    /* Make sure that the target has a reasonable length. */
    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) {
      goto retry_splicing;
    }

    /* Read the testcase into a new buffer. */
    fd = open(target->fname, O_RDONLY);

    if (fd < 0) {
      PFATAL("Unable to open '%s'", target->fname);
    }

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */
    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */
    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */
    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;
  }

#endif /* !IGNORE_FINDS */

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

