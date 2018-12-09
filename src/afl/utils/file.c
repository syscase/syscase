#include "afl/types.h"

#include "afl/utils/file.h"

#include "afl/alloc-inl.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Helper function: link() if possible, copy otherwise. */
void link_or_copy(u8* old_path, u8* new_path) {
  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8* tmp;

  if (!i) {
    return;
  }

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0) {
    PFATAL("Unable to open '%s'", old_path);
  }

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0) {
    PFATAL("Unable to create '%s'", new_path);
  }

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) {
    ck_write(dfd, tmp, i, new_path);
  }

  if (i < 0) {
    PFATAL("read() failed");
  }

  ck_free(tmp);
  close(sfd);
  close(dfd);
}

/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */
u8 delete_files(u8* path, u8* prefix) {
  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);

  if (!d) {
    return 0;
  }

  while ((d_ent = readdir(d))) {
    if (d_ent->d_name[0] != '.' &&
        (!prefix || !strncmp(d_ent->d_name, prefix, strlen(prefix)))) {
      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) {
        PFATAL("Unable to delete '%s'", fname);
      }
      ck_free(fname);
    }
  }

  closedir(d);

  return !!rmdir(path);
}
