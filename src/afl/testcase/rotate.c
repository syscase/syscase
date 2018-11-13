#include "afl/types.h"
#include "afl/testcase/rotate.h"
#include "afl/testcase/common.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include "afl/utils/file.h"
#include "afl/testcase/resume/clean.h"

#include <stdio.h>
#include <string.h>

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */
void pivot_inputs(void) {
  struct queue_entry* q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {
    u8  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) {
      rsl = q->fname;
    } else {
      rsl++;
    }

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {
      u8* src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */
      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {
        struct queue_entry* s = queue;
        while (src_id-- && s) {
          s = s->next;
        }
        if (s) {
          q->depth = s->depth + 1;
        }

        if (max_depth < q->depth) {
          max_depth = q->depth;
        }
      }
    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */
#ifndef SIMPLE_FILES
      u8* use_name = strstr(rsl, ",orig:");

      if (use_name) {
        use_name += 6;
      } else {
        use_name = rsl;
      }
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);
#else
      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);
#endif /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */
    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */
    if (q->passed_det) {
      mark_as_det_done(q);
    }

    q = q->next;
    id++;
  }

  if (in_place_resume) {
    nuke_resume_dir();
  }
}

