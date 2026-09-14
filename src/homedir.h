#ifndef WETTYD_HOMEDIR_H
#define WETTYD_HOMEDIR_H

#include <stdbool.h>

// True if path is non-empty and refers to an existing, accessible directory.
bool path_is_dir(const char *path);

// Resolves a default working directory for the spawned shell: the home
// directory of the user this process is running as (checking $HOME, then
// falling back to the OS user database), if one can be found and actually
// exists on disk, otherwise "/". Never returns NULL. The returned string is
// heap-allocated, the caller must free() it.
char *default_cwd(void);

#endif
