#include "afl/types.h"

#include "afl/utils/proc.h"

#include "afl/config.h"

#include <stdio.h>
#include <string.h>

/* Get the number of runnable processes, with some simple smoothing. */
double get_runnable_processes(void) {
  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */
  if (getloadavg(&res, 1) != 1) {
    return 0;
  }
#else
  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */
  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) {
    return 0;
  }

  while (fgets(tmp, sizeof(tmp), f)) {
    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) {
      val += atoi(tmp + 14);
    }
  }

  fclose(f);

  if (!res) {
    res = val;
  } else {
    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);
  }
#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;
}
