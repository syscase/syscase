#ifndef AFL_MUTATE_STAGE_AUTO_EXTRAS_A0_H
#define AFL_MUTATE_STAGE_AUTO_EXTRAS_A0_H

int stage_auto_extras_a0(char** argv,
                         u64* orig_hit_cnt,
                         u64* new_hit_cnt,
                         u8* in_buf,
                         u8* out_buf,
                         s32 len,
                         u8* eff_map);

#endif /* ! AFL_MUTATE_STAGE_AUTO_EXTRAS_A0_H */
