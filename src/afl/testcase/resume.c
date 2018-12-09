#include "afl/types.h"

#include "afl/testcase/resume.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */
u32 find_start_position(void) {
  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) {
    return 0;
  }

  if (in_place_resume) {
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  } else {
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);
  }

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) {
    return 0;
  }

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path          : ");
  if (!off) {
    return 0;
  }

  ret = atoi(off + 20);
  if (ret >= queued_paths) {
    ret = 0;
  }

  return ret;
}

/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */
void find_timeout(void) {
  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) {
    return;
  }

  if (in_place_resume) {
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  } else {
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);
  }

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) {
    return;
  }

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout   : ");
  if (!off) {
    return;
  }

  ret = atoi(off + 17);
  if (ret <= 4) {
    return;
  }

  exec_tmout = ret;
  timeout_given = 3;
}

