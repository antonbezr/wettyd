#ifndef WETTYD_AUTH_H
#define WETTYD_AUTH_H

#include <stdbool.h>
#include <stddef.h>

#include "sha256.h"

#define AUTH_COOKIE_NAME "wettyd-session"
#define AUTH_TOKEN_LEN WETTYD_SHA256_HEX_LEN

bool auth_ws_upgrade_requires_header(const char *session_token, const char *auth_header);

bool auth_should_defer_initial_messages(const char *session_token, const char *auth_header, bool authenticated);

bool auth_token_matches(const char *token, const char *session_token);

void auth_session_token(const char *password, char out[AUTH_TOKEN_LEN]);

bool auth_cookie_matches(const char *cookie_header, const char *session_token);

bool auth_form_password(const char *body, size_t len, char *out, size_t out_size);

#endif
