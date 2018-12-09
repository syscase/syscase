#ifndef AFL_MUTATE_STAGE_HAVOC_H
#define AFL_MUTATE_STAGE_HAVOC_H

u32 choose_block_len(u32 limit);
int stage_havoc(char** argv, u64 *orig_hit_cnt, u64 *new_hit_cnt,
    u8 **orig_in_buf, u8 **orig_out_buf, s32 len, u8 *eff_map, u32 splice_cycle,
    u32 orig_perf, u32 *perf_score, u8 doing_det, u8 *orig_in);

#endif /* ! AFL_MUTATE_STAGE_HAVOC_H */

