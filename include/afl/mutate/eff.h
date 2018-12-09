#ifndef AFL_MUTATE_EFF_H
#define AFL_MUTATE_EFF_H

/* Effector map setup. These macros calculate:

  EFF_APOS      - position of a particular file offset in the map.
  EFF_ALEN      - length of a map with a particular number of bytes.
  EFF_SPAN_ALEN - map span for a sequence of bytes.

*/
#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

#endif /* ! AFL_MUTATE_EFF_H */
