#ifndef AFL_FUZZ_COMMON_H
#define AFL_FUZZ_COMMON_H

#define BINARY_DELIMITER "\xb7\xe3"

void* mutation_buffer_pos(u8* out_buf, u32 len, u32* mutate_buffer_len);
u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len);

#endif /* ! AFL_FUZZ_COMMON_H */
