#include "afl/types.h"

#include "afl/testcase.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include "afl/describe.h"
#include "afl/utils/random.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */
void read_testcases(void) {
  struct dirent** nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* Auto-detect non-in-place resumption attempts. */
  fn = alloc_printf("%s/queue", in_dir);
  if (!access(fn, F_OK)) {
    in_dir = fn;
  } else {
    ck_free(fn);
  }

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */
  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {
    if (errno == ENOENT || errno == ENOTDIR) {
      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The "
           "fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file "
           "under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in "
           "the input\n"
           "    directory.\n");
    }

    PFATAL("Unable to open '%s'", in_dir);
  }

  if (shuffle_queue && nl_cnt > 1) {
    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);
  }

  for (i = 0; i < nl_cnt; i++) {
    struct stat st;

    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn =
        alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8 passed_det = 0;

    free(nl[i]); /* not tracked */

    if (lstat(fn, &st) || access(fn, R_OK)) {
      PFATAL("Unable to access '%s'", fn);
    }

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {
      ck_free(fn);
      ck_free(dfn);
      continue;
    }

    if (st.st_size > MAX_FILE) {
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn, DMS(st.st_size),
            DMS(MAX_FILE));
    }

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */
    if (!access(dfn, F_OK)) {
      passed_det = 1;
    }
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);
  }

  free(nl); /* not tracked */

  if (!queued_paths) {
    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The "
         "fuzzer\n"
         "    needs one or more test case to start with - ideally, a small "
         "file under\n"
         "    1 kB or so. The cases must be stored as regular files directly "
         "in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);
  }

  last_path_time = 0;
  queued_at_start = queued_paths;
}

/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */
void write_to_testcase(void* mem, u32 len) {
  s32 fd = out_fd;

  if (out_file) {
    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) {
      PFATAL("Unable to create '%s'", out_file);
    }
  } else {
    lseek(fd, 0, SEEK_SET);
  }

  ck_write(fd, mem, len, out_file);

  if (!out_file) {
    if (ftruncate(fd, len)) {
      PFATAL("ftruncate() failed");
    }
    lseek(fd, 0, SEEK_SET);
  } else {
    close(fd);
  }
}

/* The same, but with an adjustable gap. Used for trimming. */
void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len) {
  s32 fd = out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (out_file) {
    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) {
      PFATAL("Unable to create '%s'", out_file);
    }
  } else {
    lseek(fd, 0, SEEK_SET);
  }

  if (skip_at) {
    ck_write(fd, mem, skip_at, out_file);
  }

  if (tail_len) {
    ck_write(fd, mem + skip_at + skip_len, tail_len, out_file);
  }

  if (!out_file) {
    if (ftruncate(fd, len - skip_len)) {
      PFATAL("ftruncate() failed");
    }
    lseek(fd, 0, SEEK_SET);
  } else {
    close(fd);
  }
}
