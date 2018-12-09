#ifndef AFL_SETUP_QEMU_H
#define AFL_SETUP_QEMU_H

char** get_qemu_argv(int qemu_mode, u8* own_loc, char** argv, int argc);

#endif /* ! AFL_SETUP_QEMU_H */
