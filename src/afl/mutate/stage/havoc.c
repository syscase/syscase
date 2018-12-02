#include "afl/types.h"
#include "afl/mutate/stage/havoc.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"
#include "afl/debug.h"

#include "afl/fuzz/common.h"
#include "afl/fuzz/stages.h"
#include "afl/mutate/flip.h"
#include "afl/mutate/eff.h"
#include "afl/mutate/test/interest.h"
#include "afl/utils/random.h"
#include "afl/utils/buffer.h"

#include <unistd.h>
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

int stage_havoc(char** argv, u64 *orig_hit_cnt, u64 *new_hit_cnt,
    u8 *in_buf, u8 *out_buf, s32 len, u8 *eff_map, u32 splice_cycle,
    u32 orig_perf, u32 *perf_score, u8 doing_det, u8 *orig_in) {
  s32 temp_len, fd;
  u64 havoc_queued;

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */
  if (!splice_cycle) {
    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  (*perf_score) / havoc_div / 100;
  } else {
    static u8 tmp[32];

    *perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * (*perf_score) / havoc_div / 100;
  }

  if (stage_max < HAVOC_MIN) {
    stage_max = HAVOC_MIN;
  }

  temp_len = len;

  *orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;
 
    for (int i = 0; i < use_stacking; i++) {
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
      return 0;
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
      if ((*perf_score) <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        (*perf_score) *= 2;
      }
      havoc_queued = queued_paths;
    }
  }

  *new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += *new_hit_cnt - *orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += *new_hit_cnt - *orig_hit_cnt;
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

  return 1;
}

