/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "afl/globals.h"
#include "afl/alloc-inl.h"
#include "afl/debug.h"

#include "afl/usage.h"
#include "afl/bitmap.h"
#include "afl/bitmap/winners.h"
#include "afl/signal.h"
#include "afl/setup/asan.h"
#include "afl/setup/sync.h"
#include "afl/setup/args.h"
#include "afl/setup/checks.h"
#include "afl/setup/files.h"
#include "afl/setup/dirs.h"
#include "afl/setup/qemu.h"
#include "afl/postprocessor.h"
#include "afl/shm.h"
#include "afl/testcase.h"
#include "afl/testcase/rotate.h"
#include "afl/testcase/resume.h"
#include "afl/testcase/result.h"
#include "afl/testcase/sync.h"
#include "afl/capture/stats.h"
#include "afl/dry_run.h"
#include "afl/fuzz/one.h"
#include "afl/classify.h"
#include "afl/extras.h"
#include "afl/banner.h"
#include "afl/binary.h"
#include "afl/tty.h"
#include "afl/utils/cpu.h"
#include "afl/utils/time.h"

/* Defaults */
u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
u32 hang_tmout = EXEC_TIMEOUT; /* Timeout used for hang det (ms)   */

u64 mem_limit  = MEM_LIMIT;    /* Memory cap for child (MB)        */

u32 stats_update_freq = 1;     /* Stats update frequency (execs)   */

u8 bitmap_changed = 1;         /* Time to update bitmap?           */
u8 boot_rotated = 0;           /* Time to update bitmap?           */

s32 dev_urandom_fd = -1;       /* Persistent fd for /dev/urandom   */
s32 dev_null_fd = -1;          /* Persistent fd for /dev/null      */

s32 child_pid = -1;            /* PID of the fuzzed program        */
s32 out_dir_fd = -1;           /* FD of the lock file              */

volatile u8 clear_screen = 1;  /* Window resized?                  */

u32 havoc_div = 1;             /* Cycle count divisor for havoc    */

u8 *stage_name = "init";       /* Name of the current fuzz stage   */

s32 splicing_with = -1;        /* Splicing with which test case?   */

s32 cpu_aff = -1;       	     /* Selected CPU core                */

/* Other globals */
u8 *in_dir,                    /* Input directory with test cases  */
   *out_file,                  /* File to fuzz, if any             */
   *out_file_coverage,         /* QEMU coverage log file           */
   *out_file_log_secure,       /* QEMU secure log file             */
   *out_file_log_normal,       /* QEMU normal log file             */
   *out_file_log_qemu,         /* QEMU log file                    */
   *out_dir,                   /* Working & output directory       */
   *sync_dir,                  /* Synchronization directory        */
   *sync_id,                   /* Fuzzer ID                        */
   *use_banner,                /* Display banner                   */
   *in_bitmap,                 /* Input bitmap                     */
   *doc_path,                  /* Path to documentation dir        */
   *target_path,               /* Path to target binary            */
   *orig_cmdline;              /* Original command line            */

u8  skip_deterministic,        /* Skip deterministic stages?       */
    force_deterministic,       /* Force deterministic stages?      */
    use_splicing,              /* Recombine input files?           */
    dumb_mode,                 /* Run in non-instrumented mode?    */
    score_changed,             /* Scoring for favorites changed?   */
    kill_signal,               /* Signal that killed the child     */
    resuming_fuzz,             /* Resuming an older fuzzing job?   */
    timeout_given,             /* Specific timeout given?          */
    not_on_tty,                /* stdout is not a tty              */
    term_too_small,            /* terminal dimensions too small    */
    uses_asan,                 /* Target uses ASAN?                */
    no_forkserver,             /* Disable forkserver?              */
    crash_mode,                /* Crash mode! Yeah!                */
    in_place_resume,           /* Attempt in-place resume?         */
    auto_changed,              /* Auto-generated tokens changed?   */
    no_cpu_meter_red,          /* Feng shui on the status screen   */
    no_arith,                  /* Skip most arithmetic ops         */
    shuffle_queue,             /* Shuffle input queue?             */
    qemu_mode,                 /* Running in QEMU mode?            */
    skip_requested,            /* Skip request, via SIGUSR1        */
    run_over10m,               /* Run time over 10 minutes?        */
    persistent_mode,           /* Running in persistent mode?      */
    deferred_mode,             /* Deferred forkserver mode?        */
    fast_cal;                  /* Try to calibrate faster?         */

u8  coverage_mode = 1;         /* Coverage mode                    */

s32 out_fd,                    /* Persistent fd for out_file       */
    fsrv_ctl_fd,               /* Fork server control pipe (write) */
    fsrv_st_fd;                /* Fork server status pipe (read)   */

s32 forksrv_pid;               /* PID of the fork server           */

u8* trace_bits;                /* SHM with instrumentation bitmap  */

u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
    virgin_tmout[MAP_SIZE],    /* Bits we haven't seen in tmouts   */
    virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

u8  var_bytes[MAP_SIZE];       /* Bytes that appear to be variable */

s32 shm_id;                    /* ID of the SHM region             */

volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
            child_timed_out;   /* Traced process timed out?        */

u32 queued_paths,              /* Total number of queued testcases */
    queued_variable,           /* Testcases with variable behavior */
    queued_at_start,           /* Total number of initial inputs   */
    queued_discovered,         /* Items discovered during this run */
    queued_imported,           /* Items imported via -S            */
    queued_favored,            /* Paths deemed favorable           */
    queued_with_cov,           /* Paths with new coverage bytes    */
    pending_not_fuzzed,        /* Queued but not done yet          */
    pending_favored,           /* Pending favored paths            */
    cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
    cur_depth,                 /* Current path depth               */
    max_depth,                 /* Max path depth                   */
    useless_at_start,          /* Number of useless starting paths */
    var_byte_count,            /* Bitmap bytes with var behavior   */
    current_entry;             /* Current queue entry ID           */

u64 total_crashes,             /* Total number of crashes          */
    unique_crashes,            /* Crashes with unique signatures   */
    total_tmouts,              /* Total number of timeouts         */
    unique_tmouts,             /* Timeouts with unique signatures  */
    unique_hangs,              /* Hangs with unique signatures     */
    total_execs,               /* Total execve() calls             */
    start_time,                /* Unix start time (ms)             */
    last_path_time,            /* Time for most recent path (ms)   */
    last_crash_time,           /* Time for most recent crash (ms)  */
    last_hang_time,            /* Time for most recent hang (ms)   */
    last_crash_execs,          /* Exec counter at last crash       */
    queue_cycle,               /* Queue round counter              */
    cycles_wo_finds,           /* Cycles without any new paths     */
    trim_execs,                /* Execs done to trim input files   */
    bytes_trim_in,             /* Bytes coming into the trimmer    */
    bytes_trim_out,            /* Bytes coming outa the trimmer    */
    blocks_eff_total,          /* Blocks subject to effector maps  */
    blocks_eff_select;         /* Blocks selected as fuzzable      */

u32 subseq_tmouts;             /* Number of timeouts in a row      */

u8 *stage_short,               /* Short stage name                 */
   *syncing_party;             /* Currently syncing with...        */

s32 stage_cur, stage_max;      /* Stage progression                */

u32 master_id, master_max;     /* Master instance job splitting    */

u32 syncing_case;              /* Syncing with case #...           */

s32 stage_cur_byte,            /* Byte offset of current stage op  */
    stage_cur_val;             /* Value used for stage op          */

u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */

u64 stage_finds[32],           /* Patterns found per fuzz stage    */
    stage_cycles[32];          /* Execs per fuzz stage             */

u32 rand_cnt;                  /* Random number counter            */

u64 total_cal_us,              /* Total calibration time (us)      */
    total_cal_cycles;          /* Total calibration cycles         */

u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
    total_bitmap_entries;      /* Number of bitmaps counted        */

s32 cpu_core_count;            /* CPU core count                   */

FILE* plot_file;               /* Gnuplot output file              */

struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                   *queue_cur, /* Current offset within the queue  */
                   *queue_top, /* Top of the list                  */
                   *q_prev100; /* Previous 100 marker              */

struct queue_entry*
  top_rated[MAP_SIZE];         /* Top entries for bitmap bytes     */

struct extra_data* extras;     /* Extra tokens to fuzz with        */
u32 extras_cnt;                /* Total number of tokens read      */

struct extra_data* a_extras;   /* Automatically selected extras    */
u32 a_extras_cnt;              /* Total number of tokens available */

/* Main entry point */
int main(int argc, char** argv) {
  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8  *extras_dir = 0;
  u8  mem_limit_given = 0;
  u8  exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  char** use_argv;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  doc_path = "docs";

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:Qc:")) > 0) {
    switch (opt) {
      case 'i': /* input dir */
        if (in_dir) {
          FATAL("Multiple -i options not supported");
        }
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) {
          in_place_resume = 1;
        }

        break;

      case 'o': /* output dir */
        if (out_dir) {
          FATAL("Multiple -o options not supported");
        }
        out_dir = optarg;
        break;

      case 'M': { /* master sync ID */
          u8* c;

          if (sync_id) {
            FATAL("Multiple -S or -M options not supported");
          }
          sync_id = ck_strdup(optarg);

          if ((c = strchr(sync_id, ':'))) {
            *c = 0;

            if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
                !master_id || !master_max || master_id > master_max ||
                master_max > 1000000) {
              FATAL("Bogus master ID passed to -M");
            }
          }

          force_deterministic = 1;
        }

        break;

      case 'S':
        if (sync_id) {
          FATAL("Multiple -S or -M options not supported");
        }
        sync_id = ck_strdup(optarg);
        break;

      case 'f': /* target file */
        if (out_file) {
          FATAL("Multiple -f options not supported");
        }
        out_file = optarg;
        break;

      case 'x': /* dictionary */
        if (extras_dir) {
          FATAL("Multiple -x options not supported");
        }
        extras_dir = optarg;
        break;

      case 't': { /* timeout */
          u8 suffix = 0;

          if (timeout_given) {
            FATAL("Multiple -t options not supported");
          }

          if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
              optarg[0] == '-') {
            FATAL("Bad syntax used for -t");
          }

          if (exec_tmout < 5) {
            FATAL("Dangerously low value of -t");
          }

          if (suffix == '+') {
            timeout_given = 2;
          } else {
            timeout_given = 1;
          }

          break;
      }

      case 'm': { /* mem limit */
          u8 suffix = 'M';

          if (mem_limit_given) {
            FATAL("Multiple -m options not supported");
          }
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {
            mem_limit = 0;
            break;
          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') {
            FATAL("Bad syntax used for -m");
          }

          switch (suffix) {
            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");
          }

          if (mem_limit < 5) {
            FATAL("Dangerously low value of -m");
          }

          if (sizeof(rlim_t) == 4 && mem_limit > 2000) {
            FATAL("Value of -m out of range on 32-bit systems");
          }
        }

        break;

      case 'd': /* skip deterministic */
        if (skip_deterministic) {
          FATAL("Multiple -d options not supported");
        }
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B': /* load bitmap */
        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */
        if (in_bitmap) {
          FATAL("Multiple -B options not supported");
        }

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'C': /* crash mode */
        if (crash_mode) {
          FATAL("Multiple -C options not supported");
        }
        crash_mode = FAULT_CRASH;
        break;

      case 'n': /* dumb mode */
        if (dumb_mode) {
          FATAL("Multiple -n options not supported");
        }
        if (getenv("AFL_DUMB_FORKSRV")) {
          dumb_mode = 2;
        } else {
          dumb_mode = 1;
        }

        break;

      case 'T': /* banner */
        if (use_banner) {
          FATAL("Multiple -T options not supported");
        }
        use_banner = optarg;
        break;

      case 'Q': /* QEMU mode */
        //if (qemu_mode) {
        //  FATAL("Multiple -Q options not supported");
        //}
        qemu_mode += 1;

        if (!mem_limit_given) {
          mem_limit = MEM_LIMIT_QEMU;
        }

        break;

      case 'c': /* Coverage mode */
        if(!strcmp(optarg, "0")) {
          coverage_mode = 0;
        } else if(!strcmp(optarg, "1")) {
          coverage_mode = 1;
        } else {
          FATAL("Argument -c does not support given value");
        }

        break;

      default:
        usage(argv[0]);
    }
  }

  if (optind == argc || !in_dir || !out_dir) {
    usage(argv[0]);
  }

  setup_signal_handlers();
  check_asan_opts();

  if (sync_id) {
    fix_up_sync();
  }

  if (!strcmp(in_dir, out_dir)) {
    FATAL("Input and output directories can't be the same");
  }

  if (dumb_mode) {
    if (crash_mode) {
      FATAL("-C and -n are mutually exclusive");
    }
    if (qemu_mode) {
      FATAL("-Q and -n are mutually exclusive");
    }
  }

  if (getenv("AFL_NO_FORKSRV")) {
    no_forkserver    = 1;
  }
  if (getenv("AFL_NO_CPU_RED")) {
    no_cpu_meter_red = 1;
  }
  if (getenv("AFL_NO_ARITH")) {
    no_arith = 1;
  }
  if (getenv("AFL_SHUFFLE_QUEUE")) {
    shuffle_queue = 1;
  }
  if (getenv("AFL_FAST_CAL")) {
    fast_cal = 1;
  }

  if (getenv("AFL_HANG_TMOUT")) {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) {
      FATAL("Invalid value of AFL_HANG_TMOUT");
    }
  }

  if (dumb_mode == 2 && no_forkserver) {
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");
  }

  if (getenv("AFL_PRELOAD")) {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

  if (getenv("AFL_LD_PRELOAD")) {
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");
  }

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_shm();
  init_count_class16();

  setup_dirs_fds();
  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir) {
    load_extras(extras_dir);
  }

  if (!timeout_given) {
    find_timeout();
  }

  detect_file_args(argv + optind + 1);

  if (!out_file) {
    setup_stdio_file();
  }

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode) {
    use_argv = get_qemu_argv(qemu_mode, argv[0], argv + optind, argc - optind);
  } else {
    use_argv = argv + optind;
  }

  // OPTEE-DEBUG START
  char ** argv_index = use_argv;
  while(*argv_index) {
    ACTF("Perform dry run with: %s", *argv_index++);
    fflush(stdout);
  }
  // OPTEE-DEBUG END
  perform_dry_run(use_argv);
  // OPTEE-DEBUG START
  ACTF("Dry run finished");
  fflush(stdout);
  // OPTEE-DEBUG END

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon) {
    goto stop_fuzzing;
  }

  /* Woop woop woop */
  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) {
      goto stop_fuzzing;
    }
  }

  while (1) {
    // OPTEE-DEBUG START
    ACTF("In fuzz loop");
    fflush(stdout);
    // OPTEE-DEBUG END

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {
      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {
        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;
      }

      show_stats();

      if (not_on_tty) {
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */
      if (queued_paths == prev_queued) {
        if (use_splicing) {
          cycles_wo_finds++;
        } else {
          use_splicing = 1;
        }
      } else {
        cycles_wo_finds = 0;
      }

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST")) {
        sync_fuzzers(use_argv);
      }
    }

    skipped_fuzz = fuzz_one(use_argv);

    if (!stop_soon && sync_id && !skipped_fuzz) {
      if (!(sync_interval_cnt++ % SYNC_INTERVAL)) {
        sync_fuzzers(use_argv);
      }
    }

    if (!stop_soon && exit_1) {
      stop_soon = 2;
    }

    if (stop_soon) {
      break;
    }

    queue_cur = queue_cur->next;
    current_entry++;
  }

  if (queue_cur) {
    show_stats();
  }

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */
  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {
    SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming, see %s/README.)\n", doc_path);
  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);
}

