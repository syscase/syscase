#ifndef AFL_MUTATE_FLIP_H
#define AFL_MUTATE_FLIP_H

/*********************************************
 * SIMPLE BITFLIP (+dictionary construction) *
 *********************************************/
#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

#endif /* ! AFL_MUTATE_FLIP_H */

