#ifndef AFL_FUZZ_ONE_H
#define AFL_FUZZ_ONE_H

#include "afl/config.h"
#include "afl/queue_entry.h"

/* Interesting values, as per config.h */
s8 interesting_8[9];
s16 interesting_16[19];
extern s32 interesting_32[27];

u32 choose_block_len(u32 limit);
u32 calculate_score(struct queue_entry* q);
u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le);
u8 fuzz_one(char** argv);

#endif /* ! AFL_FUZZ_ONE_H */

