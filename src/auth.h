#ifndef WETTYD_AUTH_H
#define WETTYD_AUTH_H

#include <stdbool.h>

// True if a WebSocket upgrade request should still be required to carry a
// valid HTTP Basic Auth header. False when credential auth is configured
// and enforcement is instead deferred to the AuthToken carried in the
// client's first WebSocket message, since some WebSocket client
// implementations cannot attach arbitrary headers to the upgrade request.
bool auth_ws_upgrade_requires_basic_auth(const char *credential, const char *auth_header);

// True if the server's initial post-connect messages (window title,
// preferences) should be withheld until the client has authenticated.
// Only relevant when the WebSocket upgrade itself is allowed to proceed
// without Basic Auth, see auth_ws_upgrade_requires_basic_auth above.
bool auth_should_defer_initial_messages(const char *credential, const char *auth_header, bool authenticated);

// True if a client-supplied token matches the configured credential.
// Safe to call with either argument NULL.
bool auth_token_matches(const char *token, const char *credential);

#endif
