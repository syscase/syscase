#include "afl/types.h"

#include "afl/testcase/common.h"
#include "afl/testcase/resume/clean.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include "afl/utils/file.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Delete the temporary directory used for in-place session resume. */
void nuke_resume_dir(void) {
  u8* fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");
}

/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */
void maybe_delete_out_dir(void) {
  FILE* f;
  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/
  out_dir_fd = open(out_dir, O_RDONLY);
  if (out_dir_fd < 0) {
    PFATAL("Unable to open '%s'", out_dir);
  }

#ifndef __sun
  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {
    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by "
         "another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);
  }
#endif /* !__sun */
  f = fopen(fn, "r");

  if (f) {
    u64 start_time, last_update;

    if (fscanf(f,
               "start_time     : %llu\n"
               "last_update    : %llu\n",
               &start_time, &last_update) != 2) {
      FATAL("Malformed data in '%s'", fn);
    }

    fclose(f);

    /* Let's see how much work is at stake. */
    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60) {
      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results "
           "of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz "
           "will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the "
           "directory manually,\n"
           "    or specify a different output location for this job. To resume "
           "the old\n"
           "    session, put '-' as the input directory in the command line "
           "('-i -') and\n"
           "    try again.\n",
           OUTPUT_GRACE);

      FATAL("At-risk data found in '%s'", out_dir);
    }
  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */
  if (in_place_resume) {
    u8* orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);

    rename(orig_q, in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {
    OKF("Output directory exists but deemed OK to reuse.");
  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  if (!in_place_resume) {
    fn = alloc_printf("%s/.synced", out_dir);
    if (delete_files(fn, NULL)) {
      goto dir_cleanup_failed;
    }
    ck_free(fn);
  }

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */
  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */
  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */
  if (!in_place_resume) {
    fn = alloc_printf("%s/crashes/README.txt", out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);
  }

  fn = alloc_printf("%s/crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */
  if (in_place_resume && rmdir(fn)) {
    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES
    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);
#else
    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn, t->tm_year + 1900,
                           t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min,
                           t->tm_sec);
#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/hangs", out_dir);

  /* Backup hangs, too. */
  if (in_place_resume && rmdir(fn)) {
    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES
    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);
#else
    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn, t->tm_year + 1900,
                           t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min,
                           t->tm_sec);
#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX)) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  /* And now, for some finishing touches. */
  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink(fn) && errno != ENOENT) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  if (!in_place_resume) {
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT) {
      goto dir_cleanup_failed;
    }
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT) {
    goto dir_cleanup_failed;
  }
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */
  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped "
       "into\n"
       "    some files that shouldn't be there or that couldn't be removed - "
       "so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a "
       "different\n"
       "    output location for the tool.\n",
       fn);

  FATAL("Output directory cleanup failed");
}
