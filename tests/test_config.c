#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/config.h"

static int failures = 0;

static void check(int condition, const char *description) {
  if (condition) {
    printf("PASS %s\n", description);
  } else {
    printf("FAIL %s\n", description);
    failures++;
  }
}

static bool parse(const char *text, struct wettyd_config *cfg) {
  char error[256];
  return config_parse(text, cfg, error, sizeof(error));
}

int main(void) {
  struct wettyd_config cfg;
  char error[256] = "";

  check(parse("auth: password\npassword: hunter2\n", &cfg) && cfg.auth == CONFIG_AUTH_PASSWORD &&
            strcmp(cfg.password, "hunter2") == 0,
        "a password config is parsed");

  check(parse("password: hunter2\n", &cfg) && cfg.auth == CONFIG_AUTH_PASSWORD, "auth defaults to password");

  check(parse("auth: none\n", &cfg) && cfg.auth == CONFIG_AUTH_NONE, "auth none needs no password");

  check(parse("  password :  hunter2  \n", &cfg) && strcmp(cfg.password, "hunter2") == 0,
        "whitespace around keys and values is trimmed");

  check(parse("password: \"hunter2\"\n", &cfg) && strcmp(cfg.password, "hunter2") == 0, "double quotes are stripped");
  check(parse("password: 'hunter2'\n", &cfg) && strcmp(cfg.password, "hunter2") == 0, "single quotes are stripped");

  check(parse("# a comment\n\npassword: hunter2\n", &cfg) && strcmp(cfg.password, "hunter2") == 0,
        "comments and blank lines are ignored");

  check(parse("bind-addr: 127.0.0.1:8080\npassword: hunter2\n", &cfg) && strcmp(cfg.password, "hunter2") == 0,
        "unknown keys are ignored");

  check(parse("password: a:b:c\n", &cfg) && strcmp(cfg.password, "a:b:c") == 0, "a password may contain colons");

  check(parse("auth: password\n", &cfg) == false, "auth password without a password is an error");
  check(parse("auth: token\npassword: x\n", &cfg) == false, "an unknown auth mode is an error");
  check(parse("password hunter2\n", &cfg) == false, "a line without a colon is an error");

  char long_line[WETTYD_PASSWORD_MAX + 32];
  snprintf(long_line, sizeof(long_line), "password: ");
  memset(long_line + strlen(long_line), 'x', WETTYD_PASSWORD_MAX);
  long_line[10 + WETTYD_PASSWORD_MAX] = '\0';
  check(parse(long_line, &cfg) == false, "an overlong password is an error");

  config_parse("auth: token\n", &cfg, error, sizeof(error));
  check(strlen(error) > 0, "a parse failure reports an error message");

  char password[64];
  config_generate_password(password, sizeof(password));
  check(strlen(password) == 24, "a generated password is 24 characters");
  char again[64];
  config_generate_password(again, sizeof(again));
  check(strcmp(password, again) != 0, "generated passwords differ between calls");

  const char *tmpdir = getenv("TMPDIR");
  if (tmpdir == NULL || tmpdir[0] == '\0') tmpdir = "/tmp";

  char base[200];
  snprintf(base, sizeof(base), "%s/wettyd-config-test-%d", tmpdir, (int)getpid());

  char path[256];
  snprintf(path, sizeof(path), "%s/nested/config.yaml", base);

  struct wettyd_config written;
  config_init(&written);
  snprintf(written.password, sizeof(written.password), "%s", password);
  check(config_write(path, &written, error, sizeof(error)), "a config file is written, creating parent directories");

  struct wettyd_config read_back;
  check(config_read(path, &read_back, error, sizeof(error)) == CONFIG_OK &&
            strcmp(read_back.password, password) == 0 && read_back.auth == CONFIG_AUTH_PASSWORD,
        "a written config file reads back identically");

  struct stat st;
  check(stat(path, &st) == 0 && (st.st_mode & 0077) == 0, "a written config file is not readable by other users");

  char missing[256];
  snprintf(missing, sizeof(missing), "%s/does-not-exist/config.yaml", base);
  check(config_read(missing, &cfg, error, sizeof(error)) == CONFIG_MISSING,
        "a missing config file is reported as missing, not as an error");

  unlink(path);
  char dir[256];
  snprintf(dir, sizeof(dir), "%s/nested", base);
  rmdir(dir);
  rmdir(base);

  if (failures > 0) {
    printf("\n%d test(s) failed\n", failures);
    return 1;
  }
  printf("\nall tests passed\n");
  return 0;
}
