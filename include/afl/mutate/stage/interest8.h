#ifndef AFL_MUTATE_STAGE_INTEREST8_H
#define AFL_MUTATE_STAGE_INTEREST8_H

int stage_interest8(char** argv,
                    u64* orig_hit_cnt,
                    u64* new_hit_cnt,
                    u8* out_buf,
                    s32 len,
                    u8* eff_map);

#endif /* ! AFL_MUTATE_STAGE_INTEREST8_H */
