#ifndef AFL_FUZZ_ONE_H
#define AFL_FUZZ_ONE_H

#include "afl/config.h"
#include "afl/queue_entry.h"

u32 choose_block_len(u32 limit);
u32 calculate_score(struct queue_entry* q);
u8 fuzz_one(char** argv);

#endif /* ! AFL_FUZZ_ONE_H */

