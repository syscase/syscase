#include "afl/types.h"

#include "afl/bitmap/favorable.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include "afl/bitmap/minimize.h"
#include "afl/queue_entry.h"

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */
void update_bitmap_score(struct queue_entry* q) {
  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */
  for (i = 0; i < MAP_SIZE; i++) {
    if (trace_bits[i]) {
      if (top_rated[i]) {
        /* Faster-executing or smaller test cases are favored. */
        if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) {
          continue;
        }

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its trace_bits[] if necessary. */
        if (!--top_rated[i]->tc_ref) {
          ck_free(top_rated[i]->trace_mini);
          top_rated[i]->trace_mini = 0;
        }
      }

      /* Insert ourselves as the new winner. */
      top_rated[i] = q;
      q->tc_ref++;

      if (!q->trace_mini) {
        q->trace_mini = ck_alloc(MAP_SIZE >> 3);
        minimize_bits(q->trace_mini, trace_bits);
      }

      score_changed = 1;
    }
  }
}
