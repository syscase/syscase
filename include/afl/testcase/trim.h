#ifndef AFL_TESTCASE_TRIM_H
#define AFL_TESTCASE_TRIM_H

#include "afl/queue_entry.h"

u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf);

#endif /* ! AFL_TESTCASE_TRIM_H */
