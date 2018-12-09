#ifndef AFL_SIMPLIFY_TRACE_H
#define AFL_SIMPLIFY_TRACE_H

#ifdef __x86_64__
void simplify_trace(u64* mem);
#else
void simplify_trace(u32* mem);
#endif /* ^__x86_64__ */

#endif /* ! AFL_SIMPLIFY_TRACE_H */
