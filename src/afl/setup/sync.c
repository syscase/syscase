#include "afl/types.h"

#include "afl/setup/sync.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"
#include "afl/debug.h"

#include <string.h>
#include <ctype.h>

/* Validate and fix up out_dir and sync_dir when using -S. */
void fix_up_sync(void) {
  u8* x = sync_id;

  if (dumb_mode) {
    FATAL("-S / -M and -n are mutually exclusive");
  }

  if (skip_deterministic) {
    if (force_deterministic) {
      FATAL("use -S instead of -M -d");
    } else {
      FATAL("-S already implies -d");
    }
  }

  while (*x) {
    if (!isalnum(*x) && *x != '_' && *x != '-') {
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");
    }

    x++;
  }

  if (strlen(sync_id) > 32) {
    FATAL("Fuzzer ID too long");
  }

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir  = x;

  if (!force_deterministic) {
    skip_deterministic = 1;
    use_splicing = 1;
  }
}

