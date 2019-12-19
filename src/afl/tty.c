#include "afl/types.h"

#include "afl/tty.h"

#include "afl/debug.h"
#include "afl/globals.h"

#include <errno.h>
#include <sys/ioctl.h>

/* Check if we're on TTY. */
void check_if_tty(void) {
  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {
    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less "
          "verbose.");
      not_on_tty = 1;
    }

    return;
  }
}

/* Check terminal dimensions after resize. */
void check_term_size(void) {
  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) {
    return;
  }

  if (ws.ws_row < 25 || ws.ws_col < 80) {
    term_too_small = 1;
  }
}
