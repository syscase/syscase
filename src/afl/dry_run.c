#include "afl/types.h"
#include "afl/dry_run.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "afl/testcase/calibrate.h"
#include "afl/testcase/result.h"
#include "afl/describe.h"
#include "afl/bitmap/coverage.h"

/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */
void perform_dry_run(char** argv) {
  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {
    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) {
      PFATAL("Unable to open '%s'", q->fname);
    }

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len) {
      FATAL("Short read from '%s'", q->fname);
    }

    close(fd);

    // OPTEE-DEBUG START
    ACTF("Calibrate case");
    fflush(stdout);
    // OPTEE-DEBUG END
    res = calibrate_case(argv, q, use_mem, 0, 1);
    // OPTEE-DEBUG START
    ACTF("Calibrate case finished");
    fflush(stdout);
    // OPTEE-DEBUG END
    ck_free(use_mem);

    if (stop_soon) {
      return;
    }

    if (res == crash_mode || res == FAULT_NOBITS) {
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST, 
           q->len, q->bitmap_size, q->exec_us);
    }

    switch (res) {
      case FAULT_NONE:
        if (q == queue) {
          check_map_coverage();
        }

        if (crash_mode) {
          FATAL("Test case '%s' does *NOT* crash", fn);
        }

        break;

      case FAULT_TMOUT:
        if (timeout_given) {
          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (timeout_given > 1) {
            WARNF("Test case results in a timeout (skipping)");
            q->cal_failed = CAL_CHANCES;
            cal_failures++;
            break;
          }

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
               "    what you are doing and want to simply skip the unruly test cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n", exec_tmout,
               exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);
        } else {
          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);
        }

      case FAULT_CRASH:  
        if (crash_mode) {
          break;
        }

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        if (mem_limit) {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               "    - The current memory limit (%s) is too low for this program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix this, try\n"
               "      bumping it up with the -m setting in the command line. If in doubt,\n"
               "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
               "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
               "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

               "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
               "      estimate the required amount of virtual memory for the binary. Also,\n"
               "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
               DMS(mem_limit << 20), mem_limit - 1, doc_path);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

        }

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:
        FATAL("Unable to execute target application ('%s')", argv[0]);

      case FAULT_NOINST:
        FATAL("No instrumentation detected");

      case FAULT_NOBITS: 
        useless_at_start++;

        if (!in_bitmap && !shuffle_queue) {
          WARNF("No new instrumentation output, test case may be useless.");
        }

        break;
    }

    if (q->var_behavior) {
      WARNF("Instrumentation output varies across runs.");
    }

    q = q->next;
  }

  if (cal_failures) {
    if (cal_failures == queued_paths) {
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");
    }

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths) {
      WARNF(cLRD "High percentage of rejected test cases, check settings!");
    }
  }

  OKF("All test cases processed.");
}

