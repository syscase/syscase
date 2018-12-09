#include "afl/types.h"

#include "afl/testcase/sync.h"
#include "afl/testcase/common.h"

#include "afl/globals.h"
#include "afl/alloc-inl.h"

#include "afl/testcase.h"
#include "afl/capture.h"
#include "afl/capture/stats.h"
#include "afl/syscase/coverage.h"

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

/* Grab interesting test cases from other fuzzers. */
void sync_fuzzers(char** argv) {
  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);
  if (!sd) {
    PFATAL("Unable to open '%s'", sync_dir);
  }

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */
  while ((sd_ent = readdir(sd))) {
    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */
    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) {
      continue;
    }

    /* Skip anything that doesn't have a queue/ subdirectory. */
    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */
    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) {
      PFATAL("Unable to create '%s'", qd_synced_path);
    }

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) {
      lseek(id_fd, 0, SEEK_SET);
    }

    next_min_accept = min_accept;

    /* Show stats */    
    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur  = 0;
    stage_max  = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not. */
    while ((qd_ent = readdir(qd))) {
      u8* path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 || 
          syncing_case < min_accept) {
        continue;
      }

      /* OK, sounds like a new one. Let's give it a try. */
      if (syncing_case >= next_min_accept) {
        next_min_accept = syncing_case + 1;
      }

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      /* Allow this to fail in case the other fuzzer is resuming or so... */
      fd = open(path, O_RDONLY);

      if (fd < 0) {
         ck_free(path);
         continue;
      }

      if (fstat(fd, &st)) {
        PFATAL("fstat() failed");
      }

      /* Ignore zero-sized or oversized files. */
      if (st.st_size && st.st_size <= MAX_FILE) {
        u8  fault;
        u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) {
          PFATAL("Unable to mmap '%s'", path);
        }

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */
        write_to_testcase(mem, st.st_size);

        fault = run_target(argv, exec_tmout);

        if (stop_soon) {
          return;
        }

        syncing_party = sd_ent->d_name;
        queued_imported += save_if_interesting(argv, mem, st.st_size, fault);
        syncing_party = 0;

        munmap(mem, st.st_size);

        if (!(stage_cur++ % stats_update_freq)) {
          show_stats();
        }
      }

      ck_free(path);
      close(fd);
    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
  }  

  closedir(sd);
}

