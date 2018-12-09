#include "afl/types.h"

#include "afl/setup/files.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Setup the output file for fuzzed data, if not using -f. */
void setup_stdio_file(void) {
  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) {
    PFATAL("Unable to create '%s'", fn);
  }

  ck_free(fn);

  if (coverage_mode) {
    fn = alloc_printf("%s.coverage", fn);
    unlink(fn); /* Ignore errors */
  }
}

/* Detect @@ in args. */
void detect_file_args(char** argv) {
  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) {
    PFATAL("getcwd() failed");
  }

  while (argv[i]) {
    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {
      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */
      if (!out_file) {
        out_file = alloc_printf("%s/.cur_input", out_dir);

        if (coverage_mode) {
          out_file_coverage = alloc_printf("%s.coverage", out_file);
          out_file_log_secure = alloc_printf("%s/secure.log", out_dir);
          out_file_log_normal = alloc_printf("%s/normal.log", out_dir);
          out_file_log_qemu = alloc_printf("%s/qemu.log", out_dir);
        }
      }

      /* Be sure that we're always using fully-qualified paths. */
      if (out_file[0] == '/') {
        aa_subst = out_file;
      }
      else {
        aa_subst = alloc_printf("%s/%s", cwd, out_file);
      }

      /* Construct a replacement argv value. */
      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') {
        ck_free(aa_subst);
      }
    }

    i++;
  }

  free(cwd); /* not tracked */
}

