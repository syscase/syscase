#include "afl/types.h"

#include "afl/capture/crash/readme.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include "afl/describe.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Write a message accompanying the crash directory :-) */
void write_crash_readme(void) {
  u8* fn = alloc_printf("%s/crashes/README.txt", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */
  if (fd < 0) {
    return;
  }

  f = fdopen(fd, "w");

  if (!f) {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

             orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);
}

