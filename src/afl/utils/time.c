#include "afl/types.h"

#include "afl/utils/time.h"

#include <sys/time.h>

/* Get unix time in milliseconds */
u64 get_cur_time(void) {
  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

/* Get unix time in microseconds */
u64 get_cur_time_us(void) {
  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}
