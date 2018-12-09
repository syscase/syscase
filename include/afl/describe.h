#ifndef AFL_DESCRIBE_H
#define AFL_DESCRIBE_H

u8* DI(u64 val);
u8* DF(double val);
u8* DMS(u64 val);
u8* DTD(u64 cur_ms, u64 event_ms);

#endif /* ! AFL_DESCRIBE_H */
