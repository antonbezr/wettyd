// Unit tests for src/homedir.c: where the spawned shell lands when the
// operator didn't pass --cwd explicitly.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/homedir.h"

static int failures = 0;

static void check(int condition, const char *description) {
  if (condition) {
    printf("PASS %s\n", description);
  } else {
    printf("FAIL %s\n", description);
    failures++;
  }
}

int main(void) {
  check(path_is_dir("/") == true, "the root directory is a usable directory");
  check(path_is_dir("/definitely/does/not/exist/wettyd-test") == false,
        "a nonexistent path is not a usable directory");
  check(path_is_dir("") == false, "an empty path is not a usable directory");
  check(path_is_dir(NULL) == false, "a NULL path is not a usable directory, and doesn't crash");

  // A regular file is not a directory, even though it exists.
  const char *tmp_file = "/tmp/wettyd_test_homedir_not_a_dir";
  FILE *f = fopen(tmp_file, "w");
  check(f != NULL, "could create a scratch file for the not-a-directory case");
  if (f != NULL) fclose(f);
  check(path_is_dir(tmp_file) == false, "an existing regular file is not a usable directory");
  remove(tmp_file);

  char *cwd = default_cwd();
  check(cwd != NULL, "default_cwd never returns NULL");
  if (cwd != NULL) {
    check(cwd[0] != '\0', "default_cwd never returns an empty string");
    check(path_is_dir(cwd), "default_cwd returns a directory that actually exists");
    free(cwd);
  }

  if (failures > 0) {
    printf("\n%d test(s) failed\n", failures);
    return 1;
  }
  printf("\nall tests passed\n");
  return 0;
}
