#ifndef AFL_BITMAP_H
#define AFL_BITMAP_H

void write_bitmap(void);
void read_bitmap(u8* fname);
inline u8 has_new_bits(u8* virgin_map);
u32 count_bits(u8* mem);
u32 count_bytes(u8* mem);
u32 count_non_255_bytes(u8* mem);

#endif /* ! AFL_BITMAP_H */

