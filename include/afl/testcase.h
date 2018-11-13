#ifndef AFL_TESTCASE_H
#define AFL_TESTCASE_H

void read_testcases(void);
void write_to_testcase(void* mem, u32 len);
void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len);

#endif /* ! AFL_TESTCASE_H */

