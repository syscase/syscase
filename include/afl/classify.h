#ifndef AFL_CLASSIFY_H
#define AFL_CLASSIFY_H

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */
const u8 count_class_lookup8[256];

u16 count_class_lookup16[65536];

void init_count_class16(void);

#ifdef __x86_64__
inline void classify_counts(u64* mem);
#else
inline void classify_counts(u32* mem);
#endif /* ^__x86_64__ */

#endif /* ! AFL_CLASSIFY_H */
