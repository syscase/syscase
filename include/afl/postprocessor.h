#ifndef AFL_POSTPROCESSOR_H
#define AFL_POSTPROCESSOR_H

void setup_post(void);

u8* (*post_handler)(u8* buf, u32* len);

#endif /* ! AFL_POSTPROCESSOR_H */

