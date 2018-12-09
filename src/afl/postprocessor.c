#include "afl/types.h"

#include "afl/postprocessor.h"

#include "afl/debug.h"

#include <dlfcn.h>

/* Load postprocessor, if available. */
void setup_post(void) {
  void* dh;
  u8* fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn) {
    return;
  }

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) {
    FATAL("%s", dlerror());
  }

  post_handler = dlsym(dh, "afl_postprocess");
  if (!post_handler) {
    FATAL("Symbol 'afl_postprocess' not found.");
  }

  /* Do a quick test. It's better to segfault now than later =) */
  post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");
}

