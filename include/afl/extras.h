#ifndef AFL_EXTRAS_H
#define AFL_EXTRAS_H

int compare_extras_len(const void* p1, const void* p2);
int compare_extras_use_d(const void* p1, const void* p2);
void load_extras_file(u8* fname, u32* min_len, u32* max_len,
                             u32 dict_level);
void load_extras(u8* dir);
inline u8 memcmp_nocase(u8* m1, u8* m2, u32 len);
void maybe_add_auto(u8* mem, u32 len);
void save_auto(void);
void load_auto(void);
void destroy_extras(void);

#endif /* ! AFL_EXTRAS_H */

