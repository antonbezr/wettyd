#include "auth.h"

#include <string.h>

bool auth_ws_upgrade_requires_basic_auth(const char *credential, const char *auth_header) {
  return credential == NULL || auth_header != NULL;
}

bool auth_should_defer_initial_messages(const char *credential, const char *auth_header, bool authenticated) {
  return credential != NULL && auth_header == NULL && !authenticated;
}

bool auth_token_matches(const char *token, const char *credential) {
  if (token == NULL || credential == NULL) return false;
  return strcmp(token, credential) == 0;
}
