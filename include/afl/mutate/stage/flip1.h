#ifndef AFL_MUTATE_STAGE_FLIP1_H
#define AFL_MUTATE_STAGE_FLIP1_H

int stage_flip1(char** argv,
                u64* orig_hit_cnt,
                u64* new_hit_cnt,
                u32* prev_cksum,
                u8* out_buf,
                s32 len,
                u8* a_collect,
                u32* a_len);

#endif /* ! AFL_MUTATE_STAGE_FLIP1_H */
