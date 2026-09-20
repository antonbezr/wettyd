#include "auth.h"

#include <stdio.h>
#include <string.h>

bool auth_ws_upgrade_requires_header(const char *session_token, const char *auth_header) {
  return session_token == NULL || auth_header != NULL;
}

bool auth_should_defer_initial_messages(const char *session_token, const char *auth_header, bool authenticated) {
  return session_token != NULL && auth_header == NULL && !authenticated;
}

bool auth_token_matches(const char *token, const char *session_token) {
  if (token == NULL || session_token == NULL) return false;

  size_t expected_len = strlen(session_token);
  size_t token_len = strlen(token);
  unsigned char diff = (unsigned char)(expected_len ^ token_len);

  for (size_t i = 0; i < expected_len; i++) {
    unsigned char got = i < token_len ? (unsigned char)token[i] : 0;
    diff |= (unsigned char)(got ^ (unsigned char)session_token[i]);
  }

  return diff == 0 && expected_len == token_len;
}

void auth_session_token(const char *password, char out[AUTH_TOKEN_LEN]) {
  char salted[WETTYD_SHA256_HEX_LEN + 512];
  int n = snprintf(salted, sizeof(salted), "wettyd-session:%s", password == NULL ? "" : password);
  if (n < 0) n = 0;
  if ((size_t)n > sizeof(salted) - 1) n = (int)sizeof(salted) - 1;
  wettyd_sha256_hex(salted, (size_t)n, out);
}

bool auth_cookie_matches(const char *cookie_header, const char *session_token) {
  if (cookie_header == NULL || session_token == NULL) return false;

  const char *name = AUTH_COOKIE_NAME;
  size_t name_len = strlen(name);

  for (const char *p = cookie_header; *p != '\0';) {
    while (*p == ' ' || *p == ';') p++;
    if (*p == '\0') break;

    const char *end = strchr(p, ';');
    if (end == NULL) end = p + strlen(p);

    const char *eq = memchr(p, '=', (size_t)(end - p));
    if (eq != NULL && (size_t)(eq - p) == name_len && strncmp(p, name, name_len) == 0) {
      char value[AUTH_TOKEN_LEN + 1];
      size_t value_len = (size_t)(end - eq - 1);
      if (value_len < sizeof(value)) {
        memcpy(value, eq + 1, value_len);
        value[value_len] = '\0';
        if (auth_token_matches(value, session_token)) return true;
      }
    }

    p = *end == '\0' ? end : end + 1;
  }

  return false;
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool auth_form_password(const char *body, size_t len, char *out, size_t out_size) {
  if (body == NULL || out == NULL || out_size == 0) return false;

  size_t i = 0;
  while (i < len) {
    size_t start = i;
    while (i < len && body[i] != '&') i++;
    size_t field_len = i - start;
    if (i < len) i++;

    if (field_len < 9 || strncmp(body + start, "password=", 9) != 0) continue;

    const char *value = body + start + 9;
    size_t value_len = field_len - 9;
    size_t written = 0;

    for (size_t j = 0; j < value_len; j++) {
      char c = value[j];
      if (c == '+') {
        c = ' ';
      } else if (c == '%') {
        if (j + 2 >= value_len) return false;
        int hi = hex_value(value[j + 1]);
        int lo = hex_value(value[j + 2]);
        if (hi < 0 || lo < 0) return false;
        c = (char)((hi << 4) | lo);
        j += 2;
      }
      if (written + 1 >= out_size) return false;
      out[written++] = c;
    }

    out[written] = '\0';
    return true;
  }

  return false;
}
