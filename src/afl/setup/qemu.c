#include "afl/types.h"

#include "afl/setup/qemu.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include <string.h>
#include <unistd.h>

/* Rewrite argv for QEMU. */
char** get_qemu_argv(int qemu_mode, u8* own_loc, char** argv, int argc) {
  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  /* Workaround for a QEMU stability glitch. */
  setenv("QEMU_LOG", "nochain", 1);

  if (qemu_mode == 1) {
    memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

    new_argv[2] = target_path;
    new_argv[1] = "--";
  } else {
    memcpy(new_argv + 1, argv + 1, sizeof(char*) * argc);
  }

  /* Now we need to actually find the QEMU binary to put in argv[0]. */
  tmp = getenv("AFL_PATH");

  if (tmp) {
    if (qemu_mode == 1) {
      cp = alloc_printf("%s/afl-qemu-trace", tmp);
    } else {
      cp = alloc_printf("%s/%s", tmp, argv[0]);
    }

    if (access(cp, X_OK)) {
      FATAL("Unable to find '%s'", tmp);
    }

    target_path = new_argv[0] = cp;
    return new_argv;
  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {
    *rsl = 0;

    if (qemu_mode == 1) {
      cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    } else {
      cp = alloc_printf("%s/%s", own_copy, argv[0]);
    }
    ck_free(own_copy);

    if (!access(cp, X_OK)) {
      target_path = new_argv[0] = cp;
      return new_argv;
    }
  } else {
    ck_free(own_copy);
  }

  // Always expect qemu binary as first argument
  cp = alloc_printf("%s", argv[0]);
  if (qemu_mode > 1 && !access(cp, X_OK)) {
    target_path = new_argv[0] = cp;
    return new_argv;
  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be "
       "built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. "
       "If you\n"
       "    already have the binary installed, you may need to specify "
       "AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with "
       "binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to "
       "use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command "
       "line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");
}
