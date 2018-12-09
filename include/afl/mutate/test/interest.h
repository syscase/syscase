#ifndef AFL_MUTATE_TEST_INTEREST_H
#define AFL_MUTATE_TEST_INTEREST_H

/* Interesting values, as per config.h */
s8 interesting_8[9];
s16 interesting_16[19];
extern s32 interesting_32[27];

u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le);

#endif /* ! AFL_MUTATE_TEST_INTEREST_H */
