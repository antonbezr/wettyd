#ifndef WETTYD_CONFIG_H
#define WETTYD_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#define WETTYD_PASSWORD_MAX 256

enum config_auth { CONFIG_AUTH_PASSWORD, CONFIG_AUTH_NONE };

enum config_status { CONFIG_OK, CONFIG_MISSING, CONFIG_ERROR };

struct wettyd_config {
  enum config_auth auth;
  char password[WETTYD_PASSWORD_MAX];
};

void config_init(struct wettyd_config *cfg);

bool config_parse(const char *text, struct wettyd_config *cfg, char *error, size_t error_size);

char *config_default_path(void);

enum config_status config_read(const char *path, struct wettyd_config *cfg, char *error, size_t error_size);

bool config_write(const char *path, const struct wettyd_config *cfg, char *error, size_t error_size);

void config_generate_password(char *out, size_t out_size);

#endif
