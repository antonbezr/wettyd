#include "homedir.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "compat.h"

#ifndef _WIN32
#include <pwd.h>
#include <unistd.h>
#endif

bool path_is_dir(const char *path) {
  if (path == NULL || path[0] == '\0') return false;
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

char *default_cwd(void) {
  const char *home = getenv("HOME");
  if (path_is_dir(home)) return strdup(home);

#ifndef _WIN32
  struct passwd *pw = getpwuid(getuid());
  if (pw != NULL && path_is_dir(pw->pw_dir)) return strdup(pw->pw_dir);
#else
  const char *userprofile = getenv("USERPROFILE");
  if (path_is_dir(userprofile)) return strdup(userprofile);
#endif

  return strdup("/");
}
