#include <libwebsockets.h>
#include <string.h>
#include <zlib.h>

#include "auth.h"
#include "compat.h"
#include "html.h"
#include "login_html.h"
#include "server.h"
#include "utils.h"

#define LOGIN_BODY_MAX 4096
#define SESSION_MAX_AGE 2592000

static char *html_cache = NULL;
static size_t html_cache_len = 0;
static char *login_cache = NULL;
static size_t login_cache_len = 0;

static bool uncompress_page(const unsigned char *src, size_t src_len, size_t size, char **cache, size_t *cache_len,
                            char **output, size_t *output_len) {
  if (*cache == NULL || *cache_len == 0) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 16 + 15) != Z_OK) return false;

    *cache_len = size;
    *cache = xmalloc(*cache_len);

    stream.avail_in = (uInt)src_len;
    stream.avail_out = (uInt)*cache_len;
    stream.next_in = (void *)src;
    stream.next_out = (void *)*cache;

    int ret = inflate(&stream, Z_SYNC_FLUSH);
    inflateEnd(&stream);
    if (ret != Z_STREAM_END) {
      free(*cache);
      *cache = NULL;
      *cache_len = 0;
      return false;
    }
  }

  *output = *cache;
  *output_len = *cache_len;

  return true;
}

static bool uncompress_html(char **output, size_t *output_len) {
  return uncompress_page(index_html, index_html_len, index_html_size, &html_cache, &html_cache_len, output, output_len);
}

static bool uncompress_login(char **output, size_t *output_len) {
  return uncompress_page(login_html, login_html_len, login_html_size, &login_cache, &login_cache_len, output,
                         output_len);
}

static bool accept_gzip(struct lws *wsi) {
  char buf[256];
  int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_ACCEPT_ENCODING);
  return len > 0 && strstr(buf, "gzip") != NULL;
}

static bool is_post(struct lws *wsi) {
  if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) > 0) return true;
#if defined(LWS_ROLE_H2)
  char method[16];
  if (lws_hdr_copy(wsi, method, sizeof(method), WSI_TOKEN_HTTP_COLON_METHOD) > 0) return strcasecmp(method, "POST") == 0;
#endif
  return false;
}

static bool request_authenticated(struct lws *wsi) {
  if (server->auth_header != NULL)
    return lws_hdr_custom_length(wsi, server->auth_header, (int)strlen(server->auth_header)) > 0;

  if (server->session_token == NULL) return true;

  char cookie[1024];
  int len = lws_hdr_copy(wsi, cookie, sizeof(cookie), WSI_TOKEN_HTTP_COOKIE);
  if (len <= 0) return false;

  return auth_cookie_matches(cookie, server->session_token);
}

static const char *cookie_path(void) { return endpoints.parent[0] ? endpoints.parent : "/"; }

static int send_redirect(struct lws *wsi, unsigned int code, const char *location, const char *set_cookie) {
  unsigned char buffer[2048 + LWS_PRE], *p, *end;
  p = buffer + LWS_PRE;
  end = p + sizeof(buffer) - LWS_PRE;

  if (lws_add_http_header_status(wsi, code, &p, end) ||
      lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)location, (int)strlen(location), &p,
                                   end))
    return 1;

  if (set_cookie != NULL &&
      lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)set_cookie,
                                  (int)strlen(set_cookie), &p, end))
    return 1;

  if (lws_add_http_header_content_length(wsi, 0, &p, end) || lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return 1;

  return 0;
}

static int send_proxy_auth_required(struct lws *wsi) {
  unsigned char buffer[1024 + LWS_PRE], *p, *end;
  p = buffer + LWS_PRE;
  end = p + sizeof(buffer) - LWS_PRE;

  if (lws_add_http_header_status(wsi, HTTP_STATUS_PROXY_AUTH_REQUIRED, &p, end) ||
      lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_PROXY_AUTHENTICATE, (unsigned char *)"Basic realm=\"wettyd\"",
                                   20, &p, end) ||
      lws_add_http_header_content_length(wsi, 0, &p, end) || lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return 1;

  return 0;
}

static int serve_login_page(struct lws *wsi, struct pss_http *pss) {
  unsigned char buffer[4096 + LWS_PRE], *p, *end;
  p = buffer + LWS_PRE;
  end = p + sizeof(buffer) - LWS_PRE;

  char *output = (char *)login_html;
  size_t output_len = login_html_len;
  bool gzipped = true;

#ifdef LWS_WITH_HTTP_STREAM_COMPRESSION
  gzipped = false;
#else
  gzipped = accept_gzip(wsi);
#endif

  if (!gzipped && !uncompress_login(&output, &output_len)) return 1;

  if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
      lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (const unsigned char *)"text/html", 9, &p, end) ||
      lws_add_http_header_by_name(wsi, (unsigned char *)"cache-control:", (unsigned char *)"no-store", 8, &p, end))
    return 1;

  if (gzipped &&
      lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (unsigned char *)"gzip", 4, &p, end))
    return 1;

  if (lws_add_http_header_content_length(wsi, (unsigned long)output_len, &p, end) ||
      lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return 1;

  pss->buffer = pss->ptr = output;
  pss->len = output_len;
  lws_callback_on_writable(wsi);

  return 0;
}

static int handle_login_post(struct lws *wsi, struct pss_http *pss) {
  char failed[256];
  snprintf(failed, sizeof(failed), "%s?error=1", endpoints.login);

  if (server->session_token == NULL) return send_redirect(wsi, HTTP_STATUS_SEE_OTHER, endpoints.index, NULL);

  char password[WETTYD_PASSWORD_MAX];
  bool ok = pss->body != NULL && !pss->body_overflow &&
            auth_form_password(pss->body, pss->body_len, password, sizeof(password)) &&
            auth_token_matches(password, server->password);

  if (!ok) {
    char rip[50];
    lws_get_peer_simple(lws_get_network_wsi(wsi), rip, sizeof(rip));
    lwsl_warn("failed login attempt from %s\n", rip);
    return send_redirect(wsi, HTTP_STATUS_SEE_OTHER, failed, NULL);
  }

  char cookie[256];
  snprintf(cookie, sizeof(cookie), "%s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Lax", AUTH_COOKIE_NAME,
           server->session_token, cookie_path(), SESSION_MAX_AGE);

  return send_redirect(wsi, HTTP_STATUS_SEE_OTHER, endpoints.index, cookie);
}

static void pss_buffer_free(struct pss_http *pss) {
  if (pss->buffer != (char *)index_html && pss->buffer != (char *)login_html && pss->buffer != html_cache &&
      pss->buffer != login_cache)
    free(pss->buffer);
  pss->buffer = NULL;
}

static void pss_body_free(struct pss_http *pss) {
  if (pss->body != NULL) free(pss->body);
  pss->body = NULL;
  pss->body_len = 0;
  pss->body_overflow = false;
  pss->login_post = false;
}

static void access_log(struct lws *wsi, const char *path) {
  char rip[50];

  lws_get_peer_simple(lws_get_network_wsi(wsi), rip, sizeof(rip));
  lwsl_notice("HTTP %s - %s\n", path, rip);
}

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
  struct pss_http *pss = (struct pss_http *)user;
  unsigned char buffer[4096 + LWS_PRE], *p, *end;
  char buf[256];
  bool done = false;

  switch (reason) {
    case LWS_CALLBACK_HTTP:
      access_log(wsi, (const char *)in);
      snprintf(pss->path, sizeof(pss->path), "%s", (const char *)in);
      pss->authenticated = request_authenticated(wsi);

      p = buffer + LWS_PRE;
      end = p + sizeof(buffer) - LWS_PRE;

      if (strcmp(pss->path, endpoints.login) == 0) {
        if (server->session_token == NULL) {
          if (send_redirect(wsi, HTTP_STATUS_FOUND, endpoints.index, NULL)) return 1;
          goto try_to_reuse;
        }
        if (is_post(wsi)) {
          pss->login_post = true;
          return 0;
        }
        if (pss->authenticated) {
          if (send_redirect(wsi, HTTP_STATUS_FOUND, endpoints.index, NULL)) return 1;
          goto try_to_reuse;
        }
        if (serve_login_page(wsi, pss)) return 1;
        break;
      }

      if (strcmp(pss->path, endpoints.logout) == 0) {
        char cookie[256];
        snprintf(cookie, sizeof(cookie), "%s=; Path=%s; Max-Age=0; HttpOnly; SameSite=Lax", AUTH_COOKIE_NAME,
                 cookie_path());
        const char *location = server->session_token != NULL ? endpoints.login : endpoints.index;
        if (send_redirect(wsi, HTTP_STATUS_SEE_OTHER, location, cookie)) return 1;
        goto try_to_reuse;
      }

      if (!pss->authenticated) {
        if (server->auth_header != NULL) {
          if (send_proxy_auth_required(wsi)) return 1;
          goto try_to_reuse;
        }
        if (strcmp(pss->path, endpoints.index) == 0 || strcmp(pss->path, endpoints.parent) == 0) {
          if (send_redirect(wsi, HTTP_STATUS_FOUND, endpoints.login, NULL)) return 1;
          goto try_to_reuse;
        }
        lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, NULL);
        goto try_to_reuse;
      }

      if (strcmp(pss->path, endpoints.token) == 0) {
        const char *token = server->session_token != NULL ? server->session_token : "";
        size_t n = snprintf(buf, sizeof(buf), "{\"token\": \"%s\"}", token);
        if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
                                         (unsigned char *)"application/json;charset=utf-8", 30, &p, end) ||
            lws_add_http_header_by_name(wsi, (unsigned char *)"cache-control:", (unsigned char *)"no-store", 8, &p,
                                        end) ||
            lws_add_http_header_content_length(wsi, (unsigned long)n, &p, end) ||
            lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;

        pss->buffer = pss->ptr = strdup(buf);
        pss->len = n;
        lws_callback_on_writable(wsi);
        break;
      }

      // redirects `/base-path` to `/base-path/`
      if (strcmp(pss->path, endpoints.parent) == 0) {
        if (send_redirect(wsi, HTTP_STATUS_FOUND, endpoints.index, NULL)) return 1;
        goto try_to_reuse;
      }

      if (strcmp(pss->path, endpoints.index) != 0) {
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
        goto try_to_reuse;
      }

      const char *content_type = "text/html";
      if (server->index != NULL) {
        int n = lws_serve_http_file(wsi, server->index, content_type, NULL, 0);
        if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi))) return 1;
      } else {
        char *output = (char *)index_html;
        size_t output_len = index_html_len;
        if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (const unsigned char *)content_type, 9, &p,
                                         end))
          return 1;
#ifdef LWS_WITH_HTTP_STREAM_COMPRESSION
        if (!uncompress_html(&output, &output_len)) return 1;
#else
        if (accept_gzip(wsi)) {
          if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (unsigned char *)"gzip", 4, &p, end))
            return 1;
        } else {
          if (!uncompress_html(&output, &output_len)) return 1;
        }
#endif

        if (lws_add_http_header_content_length(wsi, (unsigned long)output_len, &p, end) ||
            lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;

        pss->buffer = pss->ptr = output;
        pss->len = output_len;
        lws_callback_on_writable(wsi);
      }
      break;

    case LWS_CALLBACK_HTTP_BODY:
      if (!pss->login_post) break;
      if (pss->body_len + len > LOGIN_BODY_MAX) {
        pss->body_overflow = true;
        break;
      }
      pss->body = xrealloc(pss->body, pss->body_len + len + 1);
      memcpy(pss->body + pss->body_len, in, len);
      pss->body_len += len;
      pss->body[pss->body_len] = '\0';
      break;

    case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
      if (!pss->login_post) goto try_to_reuse;
      int ret = handle_login_post(wsi, pss);
      pss_body_free(pss);
      if (ret) return 1;
      goto try_to_reuse;
    }

    case LWS_CALLBACK_HTTP_WRITEABLE:
      if (!pss->buffer || pss->len == 0) {
        goto try_to_reuse;
      }

      do {
        int n = sizeof(buffer) - LWS_PRE;
        int m = lws_get_peer_write_allowance(wsi);
        if (m == 0) {
          lws_callback_on_writable(wsi);
          return 0;
        } else if (m != -1 && m < n) {
          n = m;
        }
        if (pss->ptr + n > pss->buffer + pss->len) {
          n = (int)(pss->len - (pss->ptr - pss->buffer));
          done = true;
        }
        memcpy(buffer + LWS_PRE, pss->ptr, n);
        pss->ptr += n;
        if (lws_write_http(wsi, buffer + LWS_PRE, (size_t)n) < n) {
          pss_buffer_free(pss);
          return -1;
        }
      } while (!lws_send_pipe_choked(wsi) && !done);

      if (!done && pss->ptr < pss->buffer + pss->len) {
        lws_callback_on_writable(wsi);
        break;
      }

      pss_buffer_free(pss);
      goto try_to_reuse;

    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
      goto try_to_reuse;

    case LWS_CALLBACK_CLOSED_HTTP:
      if (pss != NULL) pss_body_free(pss);
      break;
#if (defined(LWS_OPENSSL_SUPPORT) || defined(LWS_WITH_TLS)) && !defined(LWS_WITH_MBEDTLS)
    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
      if (!len || (SSL_get_verify_result((SSL *)in) != X509_V_OK)) {
        int err = X509_STORE_CTX_get_error((X509_STORE_CTX *)user);
        int depth = X509_STORE_CTX_get_error_depth((X509_STORE_CTX *)user);
        const char *msg = X509_verify_cert_error_string(err);
        lwsl_err("client certificate verification error: %s (%d), depth: %d\n", msg, err, depth);
        return 1;
      }
      break;
#endif
    default:
      break;
  }

  return 0;

  /* if we're on HTTP1.1 or 2.0, will keep the idle connection alive */
try_to_reuse:
  if (lws_http_transaction_completed(wsi)) return -1;

  return 0;
}
