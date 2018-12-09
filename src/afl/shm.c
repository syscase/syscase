#include "afl/types.h"

#include "afl/shm.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include <string.h>
#include <sys/shm.h>

/* Get rid of shared memory (atexit handler). */
void remove_shm(void) {
  shmctl(shm_id, IPC_RMID, NULL);
}

/* Configure shared memory and virgin_bits. This is called at startup. */
void setup_shm(void) {
  u8* shm_str;

  if (!in_bitmap) {
    memset(virgin_bits, 255, MAP_SIZE);
  }

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) {
    PFATAL("shmget() failed");
  }

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */
  if (!dumb_mode) {
    setenv(SHM_ENV_VAR, shm_str, 1);
  }

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);

  if (!trace_bits) {
    PFATAL("shmat() failed");
  }
}
