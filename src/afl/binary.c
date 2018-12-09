#define _GNU_SOURCE // Required for memmem

#include "afl/types.h"

#include "afl/binary.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"
#include "afl/debug.h"

#include <string.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>

u8 *target_path;
u8 *doc_path;
u8 qemu_mode;
u8 dumb_mode;
u8 uses_asan;
u8 persistent_mode;
u8 deferred_mode;

/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */
void check_binary(u8* fname) {
  u8* env_path = 0;
  struct stat st;

  s32 fd;
  u8* f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4) {
      FATAL("Program '%s' not found or not executable", fname);
    }
  } else {
    while (env_path) {
      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {
        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;
      } else {
        cur_elem = ck_strdup(env_path);
      }

      env_path = delim;

      if (cur_elem[0]) {
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      } else {
        target_path = ck_strdup(fname);
      }

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4) {
        break;
      }

      ck_free(target_path);
      target_path = 0;
    }

    if (!target_path) {
      FATAL("Program '%s' not found or not executable", fname);
    }
  }

  if (qemu_mode > 1 || getenv("AFL_SKIP_BIN_CHECK")) {
    return;
  }

  /* Check for blatant user errors. */
  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/'))) {
     FATAL("Please don't keep binaries in /tmp or /var/tmp");
  }

  fd = open(target_path, O_RDONLY);

  if (fd < 0) {
    PFATAL("Unable to open '%s'", target_path);
  }

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED) {
    PFATAL("Unable to mmap file '%s'", target_path);
  }

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {
    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n" 
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n" 
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);
  }

#ifndef __APPLE__
  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3)) {
    FATAL("Program '%s' is not an ELF binary", target_path);
  }
#else
  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED) {
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);
  }
#endif /* ^!__APPLE__ */

  if (!qemu_mode && !dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {
    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         doc_path);

    FATAL("No instrumentation detected");
  }

  if (qemu_mode &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {
    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");
  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11)) {
    uses_asan = 1;
  }

  /* Detect persistent & deferred init signatures in the binary. */
  if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1)) {
    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    persistent_mode = 1;
  } else if (getenv("AFL_PERSISTENT")) {
    WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");
  }

  if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1)) {
    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);
    deferred_mode = 1;
  } else if (getenv("AFL_DEFER_FORKSRV")) {
    WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");
  }
  if (munmap(f_data, f_len)) {
    PFATAL("unmap() failed");
  }
}

