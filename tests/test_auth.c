#include <stdio.h>
#include <string.h>

#include "../src/auth.h"

static int failures = 0;

static void check(int condition, const char *description) {
  if (condition) {
    printf("PASS %s\n", description);
  } else {
    printf("FAIL %s\n", description);
    failures++;
  }
}

static const char *token_for(const char *password) {
  static char token[AUTH_TOKEN_LEN];
  auth_session_token(password, token);
  return token;
}

int main(void) {
  char token[AUTH_TOKEN_LEN];
  char other[AUTH_TOKEN_LEN];
  auth_session_token("hunter2", token);
  auth_session_token("hunter3", other);

  check(strlen(token) == AUTH_TOKEN_LEN - 1, "a session token is a 64 character hex digest");
  check(strstr(token, "hunter2") == NULL, "a session token does not contain the password");
  check(strcmp(token, token_for("hunter2")) == 0, "the same password always derives the same session token");
  check(strcmp(token, other) != 0, "a different password derives a different session token");

  check(auth_ws_upgrade_requires_header(NULL, NULL) == true,
        "no password configured, the header check on the WS upgrade is a no-op either way");
  check(auth_ws_upgrade_requires_header(token, NULL) == false,
        "password configured, the WS upgrade check is deferred to the cookie or AuthToken");
  check(auth_ws_upgrade_requires_header(token, "X-Auth-User") == true,
        "password configured but an auth proxy header is also set, the header check still applies");
  check(auth_ws_upgrade_requires_header(NULL, "X-Auth-User") == true,
        "only an auth proxy header is set, the header check still applies");

  check(auth_should_defer_initial_messages(NULL, NULL, false) == false,
        "no password configured, initial messages are never deferred");
  check(auth_should_defer_initial_messages(token, NULL, false) == true,
        "password configured and not yet authenticated, initial messages are deferred");
  check(auth_should_defer_initial_messages(token, NULL, true) == false,
        "password configured and authenticated, initial messages are no longer deferred");
  check(auth_should_defer_initial_messages(token, "X-Auth-User", false) == false,
        "an auth proxy header is set, initial messages are never deferred");

  check(auth_token_matches("secret", "secret") == true, "a matching token is accepted");
  check(auth_token_matches("wrong", "secret") == false, "a non-matching token is rejected");
  check(auth_token_matches("secretx", "secret") == false, "a token with a matching prefix is rejected");
  check(auth_token_matches("secre", "secret") == false, "a truncated token is rejected");
  check(auth_token_matches("", "") == true, "two empty values match");
  check(auth_token_matches(NULL, "secret") == false, "a missing token is rejected");
  check(auth_token_matches("secret", NULL) == false, "a missing session token is rejected safely");
  check(auth_token_matches(NULL, NULL) == false, "two missing values are rejected safely");

  char cookie[512];
  snprintf(cookie, sizeof(cookie), "wettyd-session=%s", token);
  check(auth_cookie_matches(cookie, token) == true, "a cookie holding the session token is accepted");

  snprintf(cookie, sizeof(cookie), "theme=dark; wettyd-session=%s; other=1", token);
  check(auth_cookie_matches(cookie, token) == true, "the session cookie is found among other cookies");

  snprintf(cookie, sizeof(cookie), "theme=dark;wettyd-session=%s", token);
  check(auth_cookie_matches(cookie, token) == true, "cookies without a space after the separator are parsed");

  snprintf(cookie, sizeof(cookie), "not-wettyd-session=%s", token);
  check(auth_cookie_matches(cookie, token) == false, "a cookie whose name only ends with the session name is ignored");

  snprintf(cookie, sizeof(cookie), "wettyd-session-other=%s", token);
  check(auth_cookie_matches(cookie, token) == false, "a cookie whose name only starts with the session name is ignored");

  snprintf(cookie, sizeof(cookie), "wettyd-session=%s", other);
  check(auth_cookie_matches(cookie, token) == false, "a cookie holding a stale session token is rejected");

  check(auth_cookie_matches("wettyd-session=", token) == false, "an empty session cookie is rejected");
  check(auth_cookie_matches("theme=dark", token) == false, "a request without the session cookie is rejected");
  check(auth_cookie_matches(NULL, token) == false, "a request without any cookie header is rejected");
  check(auth_cookie_matches(cookie, NULL) == false, "no session token configured means no cookie matches");

  char password[64];
  check(auth_form_password("password=hunter2", 16, password, sizeof(password)) && strcmp(password, "hunter2") == 0,
        "a password field is read from a form body");
  check(auth_form_password("csrf=x&password=hunter2", 23, password, sizeof(password)) &&
            strcmp(password, "hunter2") == 0,
        "a password field is found after other fields");
  check(auth_form_password("password=a%2Bb+c", 16, password, sizeof(password)) && strcmp(password, "a+b c") == 0,
        "percent escapes and plus signs are decoded");
  check(auth_form_password("password=", 9, password, sizeof(password)) && password[0] == '\0',
        "an empty password field decodes to an empty string");
  check(auth_form_password("username=admin", 14, password, sizeof(password)) == false,
        "a body without a password field is rejected");
  check(auth_form_password("password=%zz", 12, password, sizeof(password)) == false,
        "an invalid percent escape is rejected");
  check(auth_form_password("password=%4", 11, password, sizeof(password)) == false,
        "a truncated percent escape is rejected");
  check(auth_form_password("password=aaaaaaaaaa", 19, password, 5) == false,
        "a password too long for the buffer is rejected");
  check(auth_form_password(NULL, 0, password, sizeof(password)) == false, "a missing body is rejected safely");

  if (failures > 0) {
    printf("\n%d test(s) failed\n", failures);
    return 1;
  }
  printf("\nall tests passed\n");
  return 0;
}
