#include "afl/types.h"

#include "afl/bitmap.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */
void write_bitmap(void) {
  u8* fname;
  s32 fd;

  if (!bitmap_changed) {
    return;
  }

  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) {
    PFATAL("Unable to open '%s'", fname);
  }

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);
}

/* Read bitmap from file. This is for the -B option again. */
void read_bitmap(u8* fname) {
  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) {
    PFATAL("Unable to open '%s'", fname);
  }

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */
inline u8 has_new_bits(u8* virgin_map) {
#ifdef __x86_64__

  u64* current = (u64*)trace_bits;
  u64* virgin = (u64*)virgin_map;

  u32 i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin = (u32*)virgin_map;

  u32 i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8 ret = 0;

  while (i--) {
    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */
    if (unlikely(*current) && unlikely(*current & *virgin)) {
      if (likely(ret < 2)) {
        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) {
          ret = 2;
        } else {
          ret = 1;
        }
#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) {
          ret = 2;
        } else {
          ret = 1;
        }

#endif /* ^__x86_64__ */
      }

      *virgin &= ~*current;
    }

    current++;
    virgin++;
  }

  if (ret && virgin_map == virgin_bits) {
    bitmap_changed = 1;
  }

  return ret;
}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */
u32 count_bits(u8* mem) {
  u32* ptr = (u32*)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */
    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;
  }

  return ret;
}

#define FF(_b) (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */
u32 count_bytes(u8* mem) {
  u32* ptr = (u32*)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    if (!v) {
      continue;
    }

    if (v & FF(0)) {
      ret++;
    }
    if (v & FF(1)) {
      ret++;
    }
    if (v & FF(2)) {
      ret++;
    }
    if (v & FF(3)) {
      ret++;
    }
  }

  return ret;
}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */
u32 count_non_255_bytes(u8* mem) {
  u32* ptr = (u32*)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */
    if (v == 0xffffffff) {
      continue;
    }
    if ((v & FF(0)) != FF(0)) {
      ret++;
    }
    if ((v & FF(1)) != FF(1)) {
      ret++;
    }
    if ((v & FF(2)) != FF(2)) {
      ret++;
    }
    if ((v & FF(3)) != FF(3)) {
      ret++;
    }
  }

  return ret;
}
