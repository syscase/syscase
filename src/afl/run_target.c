#include "afl/types.h"

#include "afl/run_target.h"

#include "afl/debug.h"
#include "afl/globals.h"

#include "afl/classify.h"
#include "afl/testcase/result.h"

#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */
u8 afl_run_target(char** argv, u32 timeout) {
  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */
  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and
     init_forkserver(), but c'est la vie. */
  if (dumb_mode == 1 || no_forkserver) {
    child_pid = fork();

    if (child_pid < 0) {
      PFATAL("fork() failed");
    }

    if (!child_pid) {
      struct rlimit r;

      if (mem_limit) {
        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS
        setrlimit(RLIMIT_AS, &r); /* Ignore errors */
#else
        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
#endif /* ^RLIMIT_AS */
      }

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

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */
      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */
      setenv("ASAN_OPTIONS",
             "abort_on_error=1:"
             "detect_leaks=0:"
             "symbolize=0:"
             "allocator_may_return_null=1",
             0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */
      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);
    }
  } else {
    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */
    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {
      if (stop_soon) {
        return 0;
      }
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {
      if (stop_soon) {
        return 0;
      }
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if (child_pid <= 0) {
      FATAL("Fork server is misbehaving (OOM?)");
    }
  }

  /* Configure timeout, as requested by user, then wait for child to terminate.
   */
  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */
  if (dumb_mode == 1 || no_forkserver) {
    if (waitpid(child_pid, &status, 0) <= 0) {
      PFATAL("waitpid() failed");
    }
  } else {
    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
      if (stop_soon) {
        return 0;
      }
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");
    }
  }

  if (!WIFSTOPPED(status)) {
    child_pid = 0;
  }

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */
  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */
  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) {
      return FAULT_TMOUT;
    }

    return FAULT_CRASH;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */
  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  /* treat all non-zero return values from qemu system test as a crash */
  if (qemu_mode > 1 && WEXITSTATUS(status) != 0) {
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG) {
    return FAULT_ERROR;
  }

  return FAULT_NONE;
}
