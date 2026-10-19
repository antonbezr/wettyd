#include <errno.h>
#include <json.h>
#include <libwebsockets.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "homedir.h"
#include "pty.h"
#include "server.h"
#include "utils.h"
#include "compat.h"

// initial message list
static char initial_cmds[] = {SET_WINDOW_TITLE, SET_PREFERENCES, SET_SESSION};

// Recent output kept per session, replayed to a client that reconnects.
#define REPLAY_CAPACITY (256 * 1024)
// Replay no further back than this, leaving room for one more PTY read
// (libuv reads up to 64KB at a time) to land while a resuming client is still
// being caught up, without overwriting output it hasn't been sent yet.
#define REPLAY_LIMIT (REPLAY_CAPACITY - 64 * 1024)
#define OUTPUT_CHUNK (64 * 1024)

static session_t *sessions = NULL;

static int send_initial_message(struct lws *wsi, struct pss_tty *pss, int index) {
  unsigned char message[LWS_PRE + 1 + 4096];
  unsigned char *p = &message[LWS_PRE];
  char buffer[128];
  int n = 0;

  char cmd = initial_cmds[index];
  switch (cmd) {
    case SET_WINDOW_TITLE:
      gethostname(buffer, sizeof(buffer) - 1);
      n = snprintf((char *)p, 1 + 4096, "%c%s (%s)", cmd, server->command, buffer);
      break;
    case SET_PREFERENCES:
      n = snprintf((char *)p, 1 + 4096, "%c%s", cmd, server->prefs_json);
      break;
    case SET_SESSION:
      // offset is where the output that follows starts in the session's
      // stream, so a resuming client can tell whether it picks up exactly
      // where it left off or has to start over from a replay
      n = snprintf((char *)p, 1 + 4096, "%c{\"id\":\"%s\",\"offset\":%llu}", cmd, pss->session->id,
                   (unsigned long long)pss->sent);
      break;
    default:
      break;
  }

  return lws_write(wsi, p, (size_t)n, LWS_WRITE_BINARY);
}

static json_object *parse_window_size(const char *buf, size_t len, uint16_t *cols, uint16_t *rows) {
  json_tokener *tok = json_tokener_new();
  json_object *obj = json_tokener_parse_ex(tok, buf, len);
  struct json_object *o = NULL;

  if (json_object_object_get_ex(obj, "columns", &o)) *cols = (uint16_t)json_object_get_int(o);
  if (json_object_object_get_ex(obj, "rows", &o)) *rows = (uint16_t)json_object_get_int(o);

  json_tokener_free(tok);
  return obj;
}

static bool check_host_origin(struct lws *wsi) {
  char buf[256];
  memset(buf, 0, sizeof(buf));
  int len = lws_hdr_copy(wsi, buf, (int)sizeof(buf), WSI_TOKEN_ORIGIN);
  if (len <= 0) return false;

  const char *prot, *address, *path;
  int port;
  if (lws_parse_uri(buf, &prot, &address, &port, &path)) return false;
  if (port == 80 || port == 443) {
    snprintf(buf, sizeof(buf), "%s", address);
  } else {
    snprintf(buf, sizeof(buf), "%s:%d", address, port);
  }

  char host_buf[256];
  memset(host_buf, 0, sizeof(host_buf));
  len = lws_hdr_copy(wsi, host_buf, (int)sizeof(host_buf), WSI_TOKEN_HOST);

  return len > 0 && strcasecmp(buf, host_buf) == 0;
}

static bool session_id_generate(char out[33]) {
  unsigned char bytes[16];
  if (uv_random(NULL, NULL, bytes, sizeof(bytes), 0, NULL) != 0) return false;
  for (size_t i = 0; i < sizeof(bytes); i++) snprintf(out + i * 2, 3, "%02x", bytes[i]);
  return true;
}

static session_t *session_find(const char *id) {
  if (id == NULL) return NULL;
  for (session_t *s = sessions; s != NULL; s = s->next) {
    if (strcmp(s->id, id) == 0) return s;
  }
  return NULL;
}

static void session_unlink(session_t *s) {
  for (session_t **p = &sessions; *p != NULL; p = &(*p)->next) {
    if (*p == s) {
      *p = s->next;
      return;
    }
  }
}

static void timer_close_cb(uv_handle_t *handle) { free(handle); }

static void session_free(session_t *s) {
  session_unlink(s);
  uv_timer_stop(s->reap_timer);
  uv_close((uv_handle_t *)s->reap_timer, timer_close_cb);
  replay_free(&s->replay);
  free(s);
}

static void session_attach(session_t *s, struct pss_tty *pss, uint64_t offset) {
  if (s->pss != NULL) {
    // Most likely the same browser tab coming back before its old, dead
    // connection has timed out, so hand the session over rather than refuse.
    struct pss_tty *old = s->pss;
    lwsl_notice("TAKEOVER attach: old wsi %p new wsi %p\n", (void *)old->wsi, (void *)pss->wsi);
    old->session = NULL;
    old->lws_close_status = CLOSE_SESSION_TAKEN_OVER;
    lws_callback_on_writable(old->wsi);
  }
  uv_timer_stop(s->reap_timer);
  s->pss = pss;
  pss->session = s;
  pss->sent = replay_resume_offset(&s->replay, offset, REPLAY_LIMIT);
}

static void session_reap_cb(uv_timer_t *timer) {
  session_t *s = (session_t *)timer->data;
  lwsl_notice("session timed out, killing process, pid: %d\n", s->process->pid);
  pty_kill(s->process, server->sig_code);
}

static pty_process *pss_process(struct pss_tty *pss) { return pss->session != NULL ? pss->session->process : NULL; }

static void process_read_cb(pty_process *process, pty_buf_t *buf, bool eof) {
  session_t *s = (session_t *)process->ctx;
  if (eof) s->eof = true;
  if (buf != NULL) {
    replay_append(&s->replay, buf->base, buf->len);
    pty_buf_free(buf);
  }

  if (s->pss != NULL) {
    // reading resumes once the client has been sent this
    lws_callback_on_writable(s->pss->wsi);
  } else if (!eof) {
    // nobody to wait on while detached, keep output flowing into the replay
    pty_resume(process);
  }
}

static void process_exit_cb(pty_process *process) {
  session_t *s = (session_t *)process->ctx;
  lwsl_notice("process exited with code %d, signal %d, pid: %d\n", process->exit_code, process->exit_signal,
              process->pid);
  s->process = NULL;
  session_unlink(s);

  if (s->pss == NULL) {
    session_free(s);
  } else {
    // Freed on close, once the client has been sent the rest of the output.
    // Always a normal close, whatever the exit code: 1006 is what a dropped
    // connection looks like, which the client answers by reconnecting.
    s->pss->lws_close_status = LWS_CLOSE_STATUS_NORMAL;
    lws_callback_on_writable(s->pss->wsi);
  }

  // if we are going to exit, do it now.
  if (force_exit) exit(0);
}

static char **build_args(struct pss_tty *pss) {
  int i, n = 0;
  char **argv = xmalloc((server->argc + pss->argc + 1) * sizeof(char *));

  for (i = 0; i < server->argc; i++) {
    argv[n++] = server->argv[i];
  }

  for (i = 0; i < pss->argc; i++) {
    argv[n++] = pss->args[i];
  }

  argv[n] = NULL;

  return argv;
}

static char **build_env(struct pss_tty *pss) {
  int i = 0, n = 2;
  char **envp = xmalloc(n * sizeof(char *));

  // TERM
  envp[i] = xmalloc(36);
  snprintf(envp[i], 36, "TERM=%s", server->terminal_type);
  i++;

  // TTYD_USER
  if (strlen(pss->user) > 0) {
    envp = xrealloc(envp, (++n) * sizeof(char *));
    envp[i] = xmalloc(40);
    snprintf(envp[i], 40, "TTYD_USER=%s", pss->user);
    i++;
  }

  envp[i] = NULL;

  return envp;
}

static bool spawn_process(struct pss_tty *pss, uint16_t columns, uint16_t rows) {
  session_t *s = xmalloc(sizeof(session_t));
  memset(s, 0, sizeof(session_t));
  if (!session_id_generate(s->id)) {
    lwsl_err("failed to generate a session id\n");
    free(s);
    return false;
  }

  pty_process *process = process_init((void *)s, server->loop, build_args(pss), build_env(pss));
  // --cwd always wins if given; otherwise land in the invoking user's home
  // directory rather than wherever wettyd's own process happened to start,
  // falling back to "/" if that can't be resolved.
  process->cwd = server->cwd != NULL ? strdup(server->cwd) : default_cwd();
  if (columns > 0) process->columns = columns;
  if (rows > 0) process->rows = rows;
  if (pty_spawn(process, process_read_cb, process_exit_cb) != 0) {
    lwsl_err("pty_spawn: %d (%s)\n", errno, strerror(errno));
    process_free(process);
    free(s);
    return false;
  }
  lwsl_notice("started process, pid: %d\n", process->pid);

  s->process = process;
  replay_init(&s->replay, REPLAY_CAPACITY);
  s->reap_timer = xmalloc(sizeof(uv_timer_t));
  uv_timer_init(server->loop, s->reap_timer);
  s->reap_timer->data = s;
  s->next = sessions;
  sessions = s;
  session_attach(s, pss, 0);
  lws_callback_on_writable(pss->wsi);

  return true;
}

static bool resume_session(struct pss_tty *pss, session_t *s, uint64_t offset, uint16_t columns, uint16_t rows) {
  session_attach(s, pss, offset);
  lwsl_notice("resumed process, pid: %d, from offset %llu of %llu\n", s->process->pid, (unsigned long long)pss->sent,
              (unsigned long long)s->replay.total);
  if (columns > 0 && rows > 0) {
    s->process->columns = columns;
    s->process->rows = rows;
    pty_resize(s->process);
  }
  lws_callback_on_writable(pss->wsi);
  return true;
}

static void wsi_output(struct lws *wsi, struct pss_tty *pss) {
  replay_buf_t *replay = &pss->session->replay;
  // only if output outran a client still being caught up, see REPLAY_LIMIT
  if (pss->sent < replay_oldest(replay)) pss->sent = replay_resume_offset(replay, pss->sent, REPLAY_LIMIT);

  char *message = xmalloc(LWS_PRE + 1 + OUTPUT_CHUNK);
  char *ptr = message + LWS_PRE;

  *ptr = OUTPUT;
  size_t len = replay_read(replay, pss->sent, ptr + 1, OUTPUT_CHUNK);
  if (len == 0) {
    free(message);
    return;
  }
  pss->sent += len;
  size_t n = len + 1;

  if (lws_write(wsi, (unsigned char *)ptr, n, LWS_WRITE_BINARY) < n) {
    lwsl_err("write OUTPUT to WS\n");
  }

  free(message);
}

static bool check_auth(struct lws *wsi, struct pss_tty *pss) {
  if (server->auth_header != NULL) {
    return lws_hdr_custom_copy(wsi, pss->user, sizeof(pss->user), server->auth_header, strlen(server->auth_header)) > 0;
  }

  return true;
}

static bool check_session_cookie(struct lws *wsi) {
  if (server->session_token == NULL) return false;

  char cookie[1024];
  int n = lws_hdr_copy(wsi, cookie, sizeof(cookie), WSI_TOKEN_HTTP_COOKIE);
  if (n <= 0) return false;

  return auth_cookie_matches(cookie, server->session_token);
}

int callback_tty(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
  struct pss_tty *pss = (struct pss_tty *)user;
  char buf[256];
  size_t n = 0;

  switch (reason) {
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
      if (server->once && server->client_count > 0) {
        lwsl_warn("refuse to serve WS client due to the --once option.\n");
        return 1;
      }
      if (server->max_clients > 0 && server->client_count == server->max_clients) {
        lwsl_warn("refuse to serve WS client due to the --max-clients option.\n");
        return 1;
      }
      n = lws_hdr_copy(wsi, pss->path, sizeof(pss->path), WSI_TOKEN_GET_URI);
#if defined(LWS_ROLE_H2)
      if (n <= 0) n = lws_hdr_copy(wsi, pss->path, sizeof(pss->path), WSI_TOKEN_HTTP_COLON_PATH);
#endif
      if (strncmp(pss->path, endpoints.ws, n) != 0) {
        lwsl_warn("refuse to serve WS client for illegal ws path: %s\n", pss->path);
        return 1;
      }

      // Some WebSocket client implementations, Safari included, cannot attach
      // credentials to the upgrade request itself, see
      // https://github.com/tsl0922/ttyd/issues/1437. When password auth is
      // configured, defer enforcement to the session cookie the browser sends
      // with the upgrade, or to the AuthToken sent in the client's first WS
      // message, see auth_should_defer_initial_messages below and
      // auth_token_matches further down.
      if (auth_ws_upgrade_requires_header(server->session_token, server->auth_header)) {
        if (!check_auth(wsi, pss)) return 1;
      }

      pss->cookie_auth = check_session_cookie(wsi);

      if (server->check_origin && !check_host_origin(wsi)) {
        lwsl_warn(
            "refuse to serve WS client from different origin due to the "
            "--check-origin option.\n");
        return 1;
      }
      break;

    case LWS_CALLBACK_ESTABLISHED:
      pss->initialized = false;
      pss->authenticated = pss->cookie_auth;
      pss->wsi = wsi;
      pss->lws_close_status = LWS_CLOSE_STATUS_NOSTATUS;

      if (server->url_arg) {
        while (lws_hdr_copy_fragment(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_URI_ARGS, n++) > 0) {
          if (strncmp(buf, "arg=", 4) == 0) {
            pss->args = xrealloc(pss->args, (pss->argc + 1) * sizeof(char *));
            pss->args[pss->argc] = strdup(&buf[4]);
            pss->argc++;
          }
        }
      }

      server->client_count++;

      lws_get_peer_simple(lws_get_network_wsi(wsi), pss->address, sizeof(pss->address));
      lwsl_notice("WS   %s - %s, clients: %d\n", pss->path, pss->address, server->client_count);
      break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
      if (pss->session != NULL && !pss->initialized) {
        // Withhold the window-title and preferences messages from a client
        // that hasn't authenticated yet, so completing the WS handshake alone
        // doesn't leak the hostname and running command. spawn_process() calls
        // lws_callback_on_writable() once the client authenticates, so this
        // just defers sending them, it doesn't drop them.
        if (auth_should_defer_initial_messages(server->session_token, server->auth_header, pss->authenticated)) {
          break;
        }
        if (pss->initial_cmd_index < (int)sizeof(initial_cmds)) {
          if (send_initial_message(wsi, pss, pss->initial_cmd_index) < 0) {
            lwsl_err("failed to send initial message, index: %d\n", pss->initial_cmd_index);
            lws_close_reason(wsi, LWS_CLOSE_STATUS_UNEXPECTED_CONDITION, NULL, 0);
            return -1;
          }
          pss->initial_cmd_index++;
          lws_callback_on_writable(wsi);
          break;
        }
        pss->initialized = true;
      }

      // Catch the client up on the session's output first, live output and,
      // when resuming, whatever it missed while disconnected, so a command
      // that exits has all of its output delivered before the close below.
      if (pss->session != NULL && pss->sent < pss->session->replay.total) {
        wsi_output(wsi, pss);
        lws_callback_on_writable(wsi);
        break;
      }

      lwsl_notice("TAKEOVER writable wsi %p session %p close %d\n", (void *)wsi, (void *)pss->session, pss->lws_close_status);
      if (pss->lws_close_status > LWS_CLOSE_STATUS_NOSTATUS) {
        lws_close_reason(wsi, (enum lws_close_status)pss->lws_close_status, NULL, 0);
        return 1;
      }

      if (pss->session != NULL && !pss->session->eof) pty_resume(pss->session->process);
      break;

    case LWS_CALLBACK_RECEIVE:
      if (pss->buffer == NULL) {
        pss->buffer = xmalloc(len);
        pss->len = len;
        memcpy(pss->buffer, in, len);
      } else {
        pss->buffer = xrealloc(pss->buffer, pss->len + len);
        memcpy(pss->buffer + pss->len, in, len);
        pss->len += len;
      }

      const char command = pss->buffer[0];

      // check auth
      if (server->session_token != NULL && !pss->authenticated && command != JSON_DATA) {
        lwsl_warn("WS client not authenticated\n");
        return 1;
      }

      // check if there are more fragmented messages
      if (lws_remaining_packet_payload(wsi) > 0 || !lws_is_final_fragment(wsi)) {
        return 0;
      }

      switch (command) {
        case INPUT:
          if (!server->writable) break;
          int err = pty_write(pss_process(pss), pty_buf_init(pss->buffer + 1, pss->len - 1));
          if (err) {
            lwsl_err("uv_write: %s (%s)\n", uv_err_name(err), uv_strerror(err));
            return -1;
          }
          break;
        case RESIZE_TERMINAL: {
          pty_process *process = pss_process(pss);
          if (process == NULL) break;
          json_object_put(parse_window_size(pss->buffer + 1, pss->len - 1, &process->columns, &process->rows));
          pty_resize(process);
        } break;
        case PAUSE:
          pty_pause(pss_process(pss));
          break;
        case RESUME:
          pty_resume(pss_process(pss));
          break;
        case JSON_DATA:
          // already running, or just handed its session over to another connection
          if (pss->session != NULL || pss->lws_close_status > LWS_CLOSE_STATUS_NOSTATUS) break;
          uint16_t columns = 0;
          uint16_t rows = 0;
          json_object *obj = parse_window_size(pss->buffer, pss->len, &columns, &rows);
          if (server->session_token != NULL && !pss->authenticated) {
            struct json_object *o = NULL;
            if (json_object_object_get_ex(obj, "AuthToken", &o)) {
              const char *token = json_object_get_string(o);
              if (auth_token_matches(token, server->session_token))
                pss->authenticated = true;
              else
                lwsl_warn("WS authentication failed with an invalid token\n");
            }
            if (!pss->authenticated) {
              json_object_put(obj);
              lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, NULL, 0);
              return -1;
            }
          }
          // A client resuming a session it was disconnected from sends back
          // the id it was given, and how much of its output it already has.
          session_t *s = NULL;
          uint64_t offset = 0;
          struct json_object *o = NULL;
          if (json_object_object_get_ex(obj, "SessionId", &o)) s = session_find(json_object_get_string(o));
          if (json_object_object_get_ex(obj, "Offset", &o) && json_object_get_int64(o) > 0)
            offset = (uint64_t)json_object_get_int64(o);
          json_object_put(obj);
          if (s != NULL && s->process != NULL) {
            if (!resume_session(pss, s, offset, columns, rows)) return 1;
          } else if (!spawn_process(pss, columns, rows)) {
            return 1;
          }
          break;
        default:
          lwsl_warn("ignored unknown message type: %c\n", command);
          break;
      }

      if (pss->buffer != NULL) {
        free(pss->buffer);
        pss->buffer = NULL;
      }
      break;

    case LWS_CALLBACK_CLOSED:
      lwsl_notice("TAKEOVER closed wsi %p\n", (void *)wsi);
      if (pss->wsi == NULL) break;

      server->client_count--;
      lwsl_notice("WS closed from %s, clients: %d\n", pss->address, server->client_count);
      if (pss->buffer != NULL) free(pss->buffer);
      for (int i = 0; i < pss->argc; i++) {
        free(pss->args[i]);
      }

      pty_process *process = pss_process(pss);
      session_t *s = pss->session;
      if (s != NULL) {
        s->pss = NULL;
        pss->session = NULL;
        if (process == NULL) {
          session_free(s);
        } else if (server->session_timeout > 0 && !server->once && !server->exit_no_conn) {
          // keep it running for the same client to come back to, see session_attach
          lwsl_notice("detached process, pid: %d, kept for %ds\n", process->pid, server->session_timeout);
          uv_timer_start(s->reap_timer, session_reap_cb, (uint64_t)server->session_timeout * 1000, 0);
          if (!s->eof) pty_resume(process);
        } else if (process_running(process)) {
          lwsl_notice("killing process, pid: %d\n", process->pid);
          pty_kill(process, server->sig_code);
        }
      }

      if ((server->once || server->exit_no_conn) && server->client_count == 0) {
        lwsl_notice("exiting due to the --once/--exit-no-conn option.\n");

        // stop accepting new ws connections
        lws_cancel_service(context);

        if (process_running(process)) {
          force_exit = true;
          lwsl_notice("send ^C to force exit.\n");
        } else {
          exit(0);
        }
      }
      break;

    default:
      break;
  }

  return 0;
}
