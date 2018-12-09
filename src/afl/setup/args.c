#include "afl/types.h"

#include "afl/setup/args.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include <string.h>

/* Make a copy of the current command line. */
void save_cmdline(u32 argc, char** argv) {
  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; i++) {
    len += strlen(argv[i]) + 1;
  }
  
  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++) {
    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) {
      *(buf++) = ' ';
    }
  }

  *buf = 0;
}

