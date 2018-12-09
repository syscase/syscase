#include "afl/types.h"

#include "afl/queue_entry.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"
#include "afl/utils/time.h"

#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */
void mark_as_det_done(struct queue_entry* q) {
  u8* fn = strrchr(q->fname, '/');
  s32 fd;
  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    PFATAL("Unable to create '%s'", fn);
  }
  close(fd);

  ck_free(fn);

  q->passed_det = 1;
}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */
void mark_as_variable(struct queue_entry* q) {
  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn)) {
    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      PFATAL("Unable to create '%s'", fn);
    }
    close(fd);
  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;
}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */
void mark_as_redundant(struct queue_entry* q, u8 state) {
  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) {
    return;
  }

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state) {
    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      PFATAL("Unable to create '%s'", fn);
    }

    close(fd);
  } else {
    if (unlink(fn)) {
      PFATAL("Unable to remove '%s'", fn);
    }
  }

  ck_free(fn);
}

/* Append new test case to the queue. */
void add_to_queue(u8* fname, u32 len, u8 passed_det) {
  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = fname;
  q->len          = len;
  q->depth        = cur_depth + 1;
  q->passed_det   = passed_det;

  if (q->depth > max_depth) {
    max_depth = q->depth;
  }

  if (queue_top) {
    queue_top->next = q;
    queue_top = q;
  } else {
    q_prev100 = queue = queue_top = q;
  }

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  if (!(queued_paths % 100)) {
    q_prev100->next_100 = q;
    q_prev100 = q;
  }

  last_path_time = get_cur_time();
}

/* Destroy the entire queue. */
void destroy_queue(void) {
  struct queue_entry *q = queue, *n;

  while (q) {
    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;
  }
}

