#ifndef AFL_TESTCASE_RESULT_H
#define AFL_TESTCASE_RESULT_H

/* Execution status fault codes */
enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS,
  /* 06 */ FAULT_NONE_BOOT
};

#endif /* ! AFL_TESTCASE_RESULT_H */
