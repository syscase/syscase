#ifndef AFL_TESTCASE_COMMON_H
#define AFL_TESTCASE_COMMON_H

/* If the original file name conforms to the syntax and the recorded
 ID matches the one we'd assign, just use the original file name.
 This is valuable for resuming fuzzing runs. */
#ifndef SIMPLE_FILES
#define CASE_PREFIX "id:"
#else
#define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

#endif /* ! AFL_TESTCASE_COMMON_H */
