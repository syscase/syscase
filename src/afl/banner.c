#include "afl/types.h"

#include "afl/globals.h"
#include "afl/banner.h"

#include "afl/alloc-inl.h"

#include <string.h>

u8 *use_banner;
u8 *sync_id;

/* Trim and possibly create a banner for the run. */
void fix_up_banner(u8* name) {
  if (!use_banner) {
    if (sync_id) {
      use_banner = sync_id;
    } else {
      u8* trim = strrchr(name, '/');
      if (!trim) {
        use_banner = name;
      } else {
        use_banner = trim + 1;
      }
    }
  }

  if (strlen(use_banner) > 40) {
    u8* tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;
  }
}

