#include "afl/types.h"
#include "afl/utils/cpu.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include "afl/utils/proc.h"

#include <ctype.h>

#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */
void bind_to_free_cpu(void) {
  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = { 0 };
  u32 i;

  if (cpu_core_count < 2) {
    return;
  }

  if (getenv("AFL_NO_AFFINITY")) {
    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;
  }

  d = opendir("/proc");

  if (!d) {
    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;
  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */
  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */
  while ((de = readdir(d))) {
    u8* fn;
    FILE* f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0])) {
      continue;
    }
    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) {
      ck_free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f)) {
      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */
      if (!strncmp(tmp, "VmSize:\t", 8)) {
        has_vmsize = 1;
      }

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize) {

        cpu_used[hval] = 1;
        break;
      }
    }

    ck_free(fn);
    fclose(f);
  }

  closedir(d);

  for (i = 0; i < cpu_core_count; i++) {
    if (!cpu_used[i]) {
      break;
    }
  }

  if (i == cpu_core_count) {
    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");
  }

  OKF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c)) {
    PFATAL("sched_setaffinity failed");
  }
}

#endif /* HAVE_AFFINITY */

/* Count the number of logical CPU cores. */
void get_core_count(void) {
  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */
#ifdef __APPLE__
  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0) {
    return;
  }
#else
  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) {
    return;
  }
#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY
  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);
#else
  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) {
    return;
  }

  while (fgets(tmp, sizeof(tmp), f)) {
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) {
      cpu_core_count++;
    }
  }

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) {
    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
    /* Add ourselves, since the 1-minute average doesn't include that yet. */
    cur_runnable++;
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {
      if (cur_runnable > cpu_core_count * 1.5) {
        WARNF("System under apparent load, performance may be spotty.");
      } else if (cur_runnable + 1 <= cpu_core_count) {
        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
      }
    }
  } else {
    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");
  }
}

