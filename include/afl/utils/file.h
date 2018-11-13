#ifndef AFL_UTILS_FILE_H
#define AFL_UTILS_FILE_H

void link_or_copy(u8* old_path, u8* new_path);
u8 delete_files(u8* path, u8* prefix);

#endif /* ! AFL_UTILS_FILE_H */

