#ifndef AFL_SIGNAL_H
#define AFL_SIGNAL_H

void handle_stop_sig(int sig);
void handle_skipreq(int sig);
void handle_timeout(int sig);
void handle_resize(int sig);
void setup_signal_handlers(void);

#endif /* ! AFL_SIGNAL_H */

