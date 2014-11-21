Here's a quick overview of the stuff you can find in this directory:

  - arm_support         - a very experimental and unstable support for ARMv7.

  - bash_harness        - a simple shell harness used to find a bunch of
                          post-Shellshock bugs.

  - canvas_harness      - a test harness used to find browser bugs with a 
                          corpus generated using simple image parsing 
                          binaries & afl-fuzz.

  - crash_triage        - a very rudimentary example of how to annotate crashes
                          with additional gdb metadata.

  - distributed_fuzzing - a sample script for synchronizing fuzzer instances
                          across multiple machines (see parallel_fuzzing.txt).

  - instrumented_cmp    - an experiment showing how a custom memcmp() or
                          strcmp() can be used to work around one of the
                          limitations of afl-fuzz.

  - libpng_no_checksum  - a sample patch for removing CRC checks in libpng.

  - minimization_script - a script for removing redundant files from a corpus
                          to simplify it. May be useful for pre- or
                          postprocessing the data for some fuzzing runs.

Most of these are meant chiefly as examples that need to be tweaked for your
specific needs. They come with some basic documentation, but are not really
production-grade.
