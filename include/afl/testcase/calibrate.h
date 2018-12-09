#ifndef AFL_TESTCASE_CALIBRATE_H
#define AFL_TESTCASE_CALIBRATE_H

#include "afl/queue_entry.h"

u8 calibrate_case(char** argv,
                  struct queue_entry* q,
                  u8* use_mem,
                  u32 handicap,
                  u8 from_queue);

#endif /* ! AFL_TESTCASE_CALIBRATE_H */
