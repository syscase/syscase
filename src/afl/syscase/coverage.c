#include "afl/types.h"

#include "afl/syscase/coverage.h"

#include "afl/alloc-inl.h"
#include "afl/globals.h"

#include "afl/run_target.h"
#include "afl/testcase/result.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>

const char* result_string_for(u8 result) {
  switch (result) {
    case FAULT_TMOUT:
      return "timeout";
    case FAULT_CRASH:
      return "crash";
    case FAULT_ERROR:
      return "error";
    case FAULT_NOINST:
      return "noinst";
    case FAULT_NOBITS:
      return "nobits";
    case FAULT_NONE_BOOT:
      return "boot";
  }

  return "none";
}

void copy_file(char* source, char* target) {
  s32 in_fd = open(source, O_RDONLY);
  assert(in_fd >= 0);
  s32 out_fd = open(target, O_WRONLY | O_CREAT | O_EXCL, 0644);
  assert(out_fd >= 0);
  char buf[8192];
  ssize_t result;

  while ((result = read(in_fd, &buf[0], sizeof(buf)))) {
    assert(result > 0);
    assert(write(out_fd, &buf[0], result) == result);
  }

  close(in_fd);
  close(out_fd);
}

void rotate_coverage_files(u8 result) {
  // Generate UUID
  uuid_t uuid;
  uuid_generate(uuid);
  char uuid_str[37];
  uuid_unparse_lower(uuid, uuid_str);
  const char* result_str = alloc_printf("%s", result_string_for(result));

  // Time
  time_t rawtime = time(NULL);
  struct tm* timeinfo = localtime(&rawtime);
  char time_str[64];
  strftime(time_str, sizeof(time_str), "%Y-%m-%d-%H%M%S-%Z", timeinfo);

  // Copy log files
  char* target_log_secure =
      alloc_printf("%s/coverage/%s-%s-result-%s.secure.log", out_dir, time_str,
                   uuid_str, result_str);
  char* target_log_normal =
      alloc_printf("%s/coverage/%s-%s-result-%s.normal.log", out_dir, time_str,
                   uuid_str, result_str);
  char* target_log_qemu = alloc_printf("%s/coverage/%s-%s-result-%s.qemu.log",
                                       out_dir, time_str, uuid_str, result_str);
  copy_file(out_file_log_secure, target_log_secure);
  copy_file(out_file_log_normal, target_log_normal);
  copy_file(out_file_log_qemu, target_log_qemu);

  // Create unique hard link for input file
  char* target_file = alloc_printf("%s/coverage/%s-%s-result-%s.scase", out_dir,
                                   time_str, uuid_str, result_str);
  if (link(out_file, target_file) != 0) {
    PFATAL("Unable to create '%s'", target_file);
  }

  // Create coverage file, if QEMU has not created one (assume empty path).
  // Open will fail, if file already exists.
  s32 fd = open(out_file_coverage, O_CREAT | O_WRONLY | O_EXCL,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd >= 0) {
    close(fd);
  }

  // Rename coverage file to unique name
  char* target_coverage_file =
      alloc_printf("%s/coverage/%s-%s-result-%s.scov", out_dir, time_str,
                   uuid_str, result_str);
  if (link(out_file_coverage, target_coverage_file) != 0) {
    PFATAL("Unable to create '%s'", target_coverage_file);
  }
  unlink(out_file_coverage);

  ck_free((char*)result_str);
  ck_free(target_log_secure);
  ck_free(target_log_normal);
  ck_free(target_log_qemu);
  ck_free(target_file);
  ck_free(target_coverage_file);
}

void rotate_boot_coverage_files() {
  if (boot_rotated) {
    return;
  }

  // Create empty boot input file
  // Open will fail, if file already exists.
  s32 fd = open(out_file, O_CREAT | O_WRONLY | O_EXCL,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd >= 0) {
    close(fd);
    // Truncate existing input file
    if (truncate(out_file, 0) != 0) {
      PFATAL("Unable to truncate '%s'", out_file);
    }
  }

  // Rotate boot path and logs
  rotate_coverage_files(FAULT_NONE_BOOT);
  boot_rotated = 1;
}

u8 run_target(char** argv, u32 timeout) {
  if (!coverage_mode) {
    return afl_run_target(argv, timeout);
  }

  // Truncate secure log
  if (truncate(out_file_log_secure, 0) != 0) {
    PFATAL("Unable to truncate '%s'", out_file_log_secure);
  }

  // Truncate normal log
  if (truncate(out_file_log_normal, 0) != 0) {
    PFATAL("Unable to truncate '%s'", out_file_log_normal);
  }

  // Truncate qemu log
  if (truncate(out_file_log_qemu, 0) != 0) {
    PFATAL("Unable to truncate '%s'", out_file_log_qemu);
  }

  // Run target
  u8 result = afl_run_target(argv, timeout);
  rotate_coverage_files(result);
  return result;
}
