// Unit tests for the pure auth-decision logic in src/auth.c, extracted out
// of protocol.c's libwebsockets callback so it can be tested without a live
// server or socket. Run via ctest, or directly as a standalone binary.

#include <stdio.h>
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

int main(void) {
  check(auth_ws_upgrade_requires_basic_auth(NULL, NULL) == true,
        "no credential configured, basic auth check on the WS upgrade is a no-op either way");
  check(auth_ws_upgrade_requires_basic_auth("dXNlcjpwYXNz", NULL) == false,
        "credential configured, basic auth check on the WS upgrade is deferred to the AuthToken");
  check(auth_ws_upgrade_requires_basic_auth("dXNlcjpwYXNz", "X-Auth-User") == true,
        "credential configured but an auth proxy header is also set, basic auth check still required");
  check(auth_ws_upgrade_requires_basic_auth(NULL, "X-Auth-User") == true,
        "only an auth proxy header is set, basic auth check still required");

  check(auth_should_defer_initial_messages(NULL, NULL, false) == false,
        "no credential configured, initial messages are never deferred");
  check(auth_should_defer_initial_messages("dXNlcjpwYXNz", NULL, false) == true,
        "credential configured and not yet authenticated, initial messages are deferred");
  check(auth_should_defer_initial_messages("dXNlcjpwYXNz", NULL, true) == false,
        "credential configured and authenticated, initial messages are no longer deferred");
  check(auth_should_defer_initial_messages("dXNlcjpwYXNz", "X-Auth-User", false) == false,
        "an auth proxy header is set, initial messages are never deferred");

  check(auth_token_matches("secret", "secret") == true, "a matching token is accepted");
  check(auth_token_matches("wrong", "secret") == false, "a non-matching token is rejected");
  check(auth_token_matches(NULL, "secret") == false, "a missing token is rejected");
  check(auth_token_matches("secret", NULL) == false, "a missing configured credential is rejected safely");
  check(auth_token_matches(NULL, NULL) == false, "two missing values are rejected safely");

  if (failures > 0) {
    printf("\n%d test(s) failed\n", failures);
    return 1;
  }
  printf("\nall tests passed\n");
  return 0;
}
