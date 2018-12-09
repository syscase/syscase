#include "afl/types.h"
#include "afl/setup/dirs.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"
#include "afl/debug.h"

#include "afl/testcase/resume/clean.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

/* Prepare output directories and fds. */
void setup_dirs_fds(void) {
  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST) {
      PFATAL("Unable to create '%s'", sync_dir);
  }

  if (mkdir(out_dir, 0700)) {
    if (errno != EEXIST) {
      PFATAL("Unable to create '%s'", out_dir);
    }

    maybe_delete_out_dir();
  } else {
    if (in_place_resume) {
      FATAL("Resume attempted but old output directory not found");
    }

    out_dir_fd = open(out_dir, O_RDONLY);

#ifndef __sun
    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB)) {
      PFATAL("Unable to flock() output directory.");
    }
#endif /* !__sun */

  }

  /* Queue directory for any starting & discovered paths. */
  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */
  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */
  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */
  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */
  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  /* The set of paths showing variable behavior. */
  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */
  if (sync_id) {
    tmp = alloc_printf("%s/.synced/", out_dir);

    if (mkdir(tmp, 0700) && (!in_place_resume || errno != EEXIST)) {
      PFATAL("Unable to create '%s'", tmp);
    }

    ck_free(tmp);
  }

  /* All recorded crashes. */
  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  /* All recorded hangs. */
  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  if (coverage_mode) {
    /* Coverage results. */
    struct stat coverage_st = {0};
    tmp = alloc_printf("%s/coverage", out_dir);
    if (stat(tmp, &coverage_st) == -1) {
      if (mkdir(tmp, 0700)) {
        PFATAL("Unable to create '%s'", tmp);
      }
    }
    ck_free(tmp);
  }

  /* Generally useful file descriptors. */
  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) {
    PFATAL("Unable to open /dev/null");
  }

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) {
    PFATAL("Unable to open /dev/urandom");
  }

  /* Gnuplot output file. */
  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    PFATAL("Unable to create '%s'", tmp);
  }
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file) {
    PFATAL("fdopen() failed");
  }

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec\n");
                     /* ignore errors */
}

