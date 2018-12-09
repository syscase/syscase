#include "afl/types.h"

#include "afl/forkserver.h"

#include "afl/alloc-inl.h"
#include "afl/describe.h"
#include "afl/globals.h"

#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */
void init_forkserver(char** argv) {
  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) {
    PFATAL("pipe() failed");
  }

  forksrv_pid = fork();

  if (forksrv_pid < 0) {
    PFATAL("fork() failed");
  }

  if (!forksrv_pid) {
    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {
      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
    }

    if (mem_limit) {
      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r); /* Ignore errors */
#else
      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */
      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
#endif /* ^RLIMIT_AS */
    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */
    r.rlim_max = r.rlim_cur = 0;

    // XXX setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */
    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {
      dup2(dev_null_fd, 0);
    } else {
      dup2(out_fd, 0);
      close(out_fd);
    }

    /* Set up control and status pipes, close the unneeded original fds. */
    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) {
      PFATAL("dup2() failed");
    }
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) {
      PFATAL("dup2() failed");
    }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */
    if (!getenv("LD_BIND_LAZY")) {
      setenv("LD_BIND_NOW", "1", 0);
    }

    /* Set sane defaults for ASAN if nothing else specified. */
    setenv("ASAN_OPTIONS",
           "abort_on_error=1:"
           "detect_leaks=0:"
           "symbolize=0:"
           "allocator_may_return_null=1",
           0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */
    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */
    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }

  /* Close the unneeded endpoints. */
  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */
  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  // OPTEE-DEBUG START
  ACTF("Wait %lus for fork server to come up", it.it_value.tv_sec);
  fflush(stdout);
  // OPTEE-DEBUG END

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  // OPTEE-DEBUG START
  ACTF("Read finished");
  fflush(stdout);
  // OPTEE-DEBUG END

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */
  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out) {
    FATAL("Timeout while initializing fork server (adjusting -t may help)");
  }

  if (waitpid(forksrv_pid, &status, 0) <= 0) {
    PFATAL("waitpid() failed");
  }

  if (WIFSIGNALED(status)) {
    if (mem_limit && mem_limit < 500 && uses_asan) {
      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any "
           "input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you "
           "have a\n"
           "    restrictive memory limit configured, this is expected; please "
           "read\n"
           "    %s/notes_for_asan.txt for help.\n",
           doc_path);
    } else if (!mem_limit) {
      SAYF(
          "\n" cLRD "[-] " cRST
          "Whoops, the target binary crashed suddenly, before receiving any "
          "input\n"
          "    from the fuzzer! There are several probable explanations:\n\n"

          "    - The binary is just buggy and explodes entirely on its own. If "
          "so, you\n"
          "      need to fix the underlying problem or find a better "
          "replacement.\n\n"

#ifdef __APPLE__
          "    - On MacOS X, the semantics of fork() syscalls are non-standard "
          "and may\n"
          "      break afl-fuzz performance optimizations when running "
          "platform-specific\n"
          "      targets. To fix this, set AFL_NO_FORKSRV=1 in the "
          "environment.\n\n"
#endif /* __APPLE__ */

          "    - Less likely, there is a horrible bug in the fuzzer. If other "
          "options\n"
          "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
    } else {
      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any "
           "input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing "
           "the\n"
           "      target to hit an OOM condition in the dynamic linker. Try "
           "bumping up\n"
           "      the limit with the -m setting in the command line. A simple "
           "way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to "
           "quickly\n"
           "      estimate the required amount of virtual memory for the "
           "binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. "
           "If so, you\n"
           "      need to fix the underlying problem or find a better "
           "replacement.\n\n"

#ifdef __APPLE__
           "    - On MacOS X, the semantics of fork() syscalls are "
           "non-standard and may\n"
           "      break afl-fuzz performance optimizations when running "
           "platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the "
           "environment.\n\n"
#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);
    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));
  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG) {
    FATAL("Unable to execute target application ('%s')", argv[0]);
  }

  if (mem_limit && mem_limit < 500 && uses_asan) {
    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could "
         "complete a\n"
         "    handshake with the injected code. Since it seems to be built "
         "with ASAN and\n"
         "    you have a restrictive memory limit configured, this is "
         "expected; please\n"
         "    read %s/notes_for_asan.txt for help.\n",
         doc_path);
  } else if (!mem_limit) {
    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could "
         "complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible "
         "bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
  } else {
    SAYF(
        "\n" cLRD "[-] " cRST
        "Hmm, looks like the target binary terminated before we could complete "
        "a\n"
        "    handshake with the injected code. There are %s probable "
        "explanations:\n\n"

        "%s"
        "    - The current memory limit (%s) is too restrictive, causing an "
        "OOM\n"
        "      fault in the dynamic linker. This can be fixed with the -m "
        "option. A\n"
        "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
        "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
        "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

        "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
        "      estimate the required amount of virtual memory for the "
        "binary.\n\n"

        "    - Less likely, there is a horrible bug in the fuzzer. If other "
        "options\n"
        "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
        getenv(DEFER_ENV_VAR) ? "three" : "two",
        getenv(DEFER_ENV_VAR)
            ? "    - You are using deferred forkserver, but __AFL_INIT() is "
              "never\n"
              "      reached before the program terminates.\n\n"
            : "",
        DMS(mem_limit << 20), mem_limit - 1);
  }

  FATAL("Fork server handshake failed");
}
