#ifndef AFL_SYSCASE_COVERAGE_H
#define AFL_SYSCASE_COVERAGE_H

const char* result_string_for(u8 result);
void copy_file(char* source, char* target);
void rotate_coverage_files(u8 result);
void rotate_boot_coverage_files();
u8 run_target(char** argv, u32 timeout);
u8 run_target(char** argv, u32 timeout);

#endif /* ! AFL_SYSCASE_COVERAGE_H */
