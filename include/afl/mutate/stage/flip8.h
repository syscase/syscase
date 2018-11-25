#ifndef AFL_MUTATE_STAGE_FLIP8_H
#define AFL_MUTATE_STAGE_FLIP8_H

int stage_flip8(char** argv, u64 *orig_hit_cnt, u64 *new_hit_cnt,
    u8 *out_buf, s32 len, u8 *eff_map, u32 *eff_cnt);

#endif /* ! AFL_MUTATE_STAGE_FLIP8_H */

