#ifndef AFL_MUTATE_STAGE_USER_EXTRAS_UI_H
#define AFL_MUTATE_STAGE_USER_EXTRAS_UI_H

int stage_user_extras_ui(char** argv,
                         u64* orig_hit_cnt,
                         u64* new_hit_cnt,
                         u8* out_buf,
                         s32 len,
                         u8* eff_map);

#endif /* ! AFL_MUTATE_STAGE_USER_EXTRAS_UI_H */
