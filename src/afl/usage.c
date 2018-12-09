#include "afl/types.h"

#include "afl/usage.h"

#include "afl/debug.h"
#include "afl/globals.h"

/* Display usage hints. */
void usage(u8* argv0) {
  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n\n"

      "  -i dir        - input directory with test cases\n"
      "  -o dir        - output directory for fuzzer findings\n\n"

      "Execution control settings:\n\n"

      "  -f file       - location read by the fuzzed program (stdin)\n"
      "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
      "  -m megs       - memory limit for child process (%u MB)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"
      "  -c            - coverage mode used: \n"
      "                  0: disable writing coverage files\n"
      "                  1: enable writing coverage files (default)\n\n"

      "Fuzzing behavior settings:\n\n"

      "  -d            - quick & dirty mode (skips deterministic steps)\n"
      "  -n            - fuzz without instrumentation (dumb mode)\n"
      "  -x dir        - optional fuzzer dictionary (see README)\n\n"
      "  -s            - syscase mode used: \n"
      "                  0: run all stages (default)\n"
      "                  1: run syscase stage only\n\n"

      "Other stuff:\n\n"

      "  -T text       - text banner to show on the screen\n"
      "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
      "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

      "For additional tips, please consult %s/README.\n\n",

      argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);
}
