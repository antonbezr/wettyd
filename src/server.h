#include <libwebsockets.h>
#include <stdbool.h>
#include <uv.h>

#include "config.h"
#include "pty.h"
#include "replay.h"

// client message
#define INPUT '0'
#define RESIZE_TERMINAL '1'
#define PAUSE '2'
#define RESUME '3'
#define JSON_DATA '{'

// server message
#define OUTPUT '0'
#define SET_WINDOW_TITLE '1'
#define SET_PREFERENCES '2'
#define SET_SESSION '3'

// close code telling a client its session was resumed by another connection
#define CLOSE_SESSION_TAKEN_OVER 4000

// url paths
struct endpoints {
  char *ws;
  char *index;
  char *token;
  char *login;
  char *logout;
  char *parent;
};

extern volatile bool force_exit;
extern struct lws_context *context;
extern struct server *server;
extern struct endpoints endpoints;

struct pss_http {
  char path[128];
  char *buffer;
  char *ptr;
  size_t len;
  bool authenticated;
  bool login_post;
  bool body_overflow;
  char *body;
  size_t body_len;
};

struct pss_tty;

// A spawned command and its recent output, outliving any one WebSocket so a
// client that drops its connection can resume it, see protocol.c.
typedef struct session_ {
  char id[33];
  pty_process *process;   // NULL once the command has exited
  struct pss_tty *pss;    // attached client, NULL while detached
  replay_buf_t replay;
  bool eof;               // the PTY has nothing more to read
  uv_timer_t *reap_timer;
  struct session_ *next;
} session_t;

struct pss_tty {
  bool initialized;
  int initial_cmd_index;
  bool authenticated;
  bool cookie_auth;
  char user[30];
  char address[50];
  char path[128];
  char **args;
  int argc;

  struct lws *wsi;
  char *buffer;
  size_t len;

  session_t *session;
  uint64_t sent;  // offset into session->replay the client has been sent up to

  int lws_close_status;
};

struct server {
  int client_count;        // client count
  char *prefs_json;        // client preferences
  char *password;
  char *session_token;
  char *config_path;
  char *auth_header;       // header name used for auth proxy
  char *index;             // custom index.html
  char *command;           // full command line
  char **argv;             // command with arguments
  int argc;                // command + arguments count
  char *cwd;               // working directory
  int sig_code;            // close signal
  char sig_name[20];       // human readable signal string
  bool url_arg;            // allow client to send cli arguments in URL
  bool writable;           // whether clients to write to the TTY
  bool check_origin;       // whether allow websocket connection from different origin
  int max_clients;         // maximum clients to support
  bool once;               // whether accept only one client and exit on disconnection
  bool exit_no_conn;       // whether exit on all clients disconnection
  int session_timeout;     // seconds a disconnected session is kept for resuming, 0 to kill it at once
  char socket_path[255];   // UNIX domain socket path
  char terminal_type[30];  // terminal type to report

  uv_loop_t *loop;         // the libuv event loop
};
