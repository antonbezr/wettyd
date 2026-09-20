#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "compat.h"

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define mkdir_p(path) _mkdir(path)
#else
#include <unistd.h>
#define mkdir_p(path) mkdir(path, 0700)
#endif

#define CONFIG_MAX_SIZE 65536

static char *trim(char *s) {
  while (*s == ' ' || *s == '\t' || *s == '\r') s++;
  size_t len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r')) s[--len] = '\0';
  return s;
}

static char *unquote(char *s) {
  size_t len = strlen(s);
  if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') || (s[0] == '\'' && s[len - 1] == '\''))) {
    s[len - 1] = '\0';
    return s + 1;
  }
  return s;
}

static void set_error(char *error, size_t error_size, const char *fmt, ...) {
  if (error == NULL || error_size == 0) return;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(error, error_size, fmt, ap);
  va_end(ap);
}

void config_init(struct wettyd_config *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->auth = CONFIG_AUTH_PASSWORD;
}

bool config_parse(const char *text, struct wettyd_config *cfg, char *error, size_t error_size) {
  config_init(cfg);

  char *copy = strdup(text);
  if (copy == NULL) {
    set_error(error, error_size, "out of memory");
    return false;
  }

  bool ok = true;
  int lineno = 0;
  char *save = NULL;
  for (char *line = strtok_r(copy, "\n", &save); line != NULL && ok; line = strtok_r(NULL, "\n", &save)) {
    lineno++;
    char *trimmed = trim(line);
    if (trimmed[0] == '\0' || trimmed[0] == '#') continue;

    char *colon = strchr(trimmed, ':');
    if (colon == NULL) {
      set_error(error, error_size, "line %d: expected `key: value`, got `%s`", lineno, trimmed);
      ok = false;
      break;
    }

    *colon = '\0';
    char *key = trim(trimmed);
    char *value = unquote(trim(colon + 1));

    if (strcmp(key, "auth") == 0) {
      if (strcmp(value, "password") == 0) {
        cfg->auth = CONFIG_AUTH_PASSWORD;
      } else if (strcmp(value, "none") == 0) {
        cfg->auth = CONFIG_AUTH_NONE;
      } else {
        set_error(error, error_size, "line %d: auth must be `password` or `none`, got `%s`", lineno, value);
        ok = false;
      }
    } else if (strcmp(key, "password") == 0) {
      if (strlen(value) >= WETTYD_PASSWORD_MAX) {
        set_error(error, error_size, "line %d: password is longer than %d characters", lineno,
                  WETTYD_PASSWORD_MAX - 1);
        ok = false;
      } else {
        snprintf(cfg->password, sizeof(cfg->password), "%s", value);
      }
    }
  }

  if (ok && cfg->auth == CONFIG_AUTH_PASSWORD && cfg->password[0] == '\0') {
    set_error(error, error_size, "auth is `password` but no password is set");
    ok = false;
  }

  free(copy);
  return ok;
}

char *config_default_path(void) {
  char path[1024];
  const char *xdg = getenv("XDG_CONFIG_HOME");

  if (xdg != NULL && xdg[0] != '\0') {
    snprintf(path, sizeof(path), "%s/wettyd/config.yaml", xdg);
    return strdup(path);
  }

  const char *home = getenv("HOME");
#ifdef _WIN32
  if (home == NULL || home[0] == '\0') home = getenv("USERPROFILE");
#endif
  if (home == NULL || home[0] == '\0') return NULL;

  snprintf(path, sizeof(path), "%s/.config/wettyd/config.yaml", home);
  return strdup(path);
}

enum config_status config_read(const char *path, struct wettyd_config *cfg, char *error, size_t error_size) {
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    if (errno == ENOENT) return CONFIG_MISSING;
    set_error(error, error_size, "%s: %s", path, strerror(errno));
    return CONFIG_ERROR;
  }

  char *text = malloc(CONFIG_MAX_SIZE);
  if (text == NULL) {
    fclose(f);
    set_error(error, error_size, "out of memory");
    return CONFIG_ERROR;
  }

  size_t n = fread(text, 1, CONFIG_MAX_SIZE - 1, f);
  fclose(f);
  text[n] = '\0';

  bool ok = config_parse(text, cfg, error, error_size);
  free(text);

  return ok ? CONFIG_OK : CONFIG_ERROR;
}

static bool make_parent_dirs(const char *path) {
  char dir[1024];
  snprintf(dir, sizeof(dir), "%s", path);

  char *last = strrchr(dir, '/');
  if (last == NULL) return true;
  *last = '\0';

  for (char *p = dir + 1; *p != '\0'; p++) {
    if (*p != '/') continue;
    *p = '\0';
    if (mkdir_p(dir) != 0 && errno != EEXIST) return false;
    *p = '/';
  }

  return mkdir_p(dir) == 0 || errno == EEXIST;
}

bool config_write(const char *path, const struct wettyd_config *cfg, char *error, size_t error_size) {
  if (!make_parent_dirs(path)) {
    set_error(error, error_size, "%s: %s", path, strerror(errno));
    return false;
  }

  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    set_error(error, error_size, "%s: %s", path, strerror(errno));
    return false;
  }

  fprintf(f, "auth: %s\n", cfg->auth == CONFIG_AUTH_NONE ? "none" : "password");
  fprintf(f, "password: %s\n", cfg->password);
  fclose(f);

#ifndef _WIN32
  if (chmod(path, 0600) != 0) {
    set_error(error, error_size, "%s: %s", path, strerror(errno));
    return false;
  }
#endif

  return true;
}

void config_generate_password(char *out, size_t out_size) {
  static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t want = out_size - 1;
  if (want > 24) want = 24;

  unsigned char bytes[24];
  bool have_bytes = false;

#ifndef _WIN32
  FILE *f = fopen("/dev/urandom", "rb");
  if (f != NULL) {
    have_bytes = fread(bytes, 1, want, f) == want;
    fclose(f);
  }
#endif

  if (!have_bytes) {
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < want; i++) bytes[i] = (unsigned char)(rand() & 0xff);
  }

  for (size_t i = 0; i < want; i++) out[i] = alphabet[bytes[i] % (sizeof(alphabet) - 1)];
  out[want] = '\0';
}
