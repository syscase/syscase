#ifndef AFL_UTILS_CPU_H
#define AFL_UTILS_CPU_H

#ifdef HAVE_AFFINITY
void bind_to_free_cpu(void);
#endif /* HAVE_AFFINITY */

void get_core_count(void);

#endif /* ! AFL_UTILS_CPU_H */

