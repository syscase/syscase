#include "afl/types.h"

#include "afl/capture/operation.h"

#include "afl/globals.h"

#include "afl/fuzz/stages.h"

#include <stdio.h>
#include <string.h>

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */
u8* describe_op(u8 hnb) {
  static u8 ret[256];

  if (syncing_party) {
    sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);
  } else {
    sprintf(ret, "src:%06u", current_entry);

    if (splicing_with >= 0) {
      sprintf(ret + strlen(ret), "+%06u", splicing_with);
    }

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {
      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE) {
        sprintf(ret + strlen(ret), ",val:%s%+d",
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "", stage_cur_val);
      }

    } else {
      sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);
    }
  }

  if (hnb == 2) {
    strcat(ret, ",+cov");
  }

  return ret;
}

#endif /* !SIMPLE_FILES */
