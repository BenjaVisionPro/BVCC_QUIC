#include "test_util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#if defined(_WIN32)
  #include <direct.h>
  #define MKDTEMP_NOT_AVAILABLE 1
  #define unlink _unlink
  #define rmdir _rmdir
  #include <windows.h>
#else
  #include <unistd.h>
  #include <sys/wait.h> /* WIFEXITED, WEXITSTATUS */
#endif

/* ---------- Minimal helpers for ephemeral server cert ---------- */

static char g_tmp_dir[PATH_MAX];
static char g_cert_path[PATH_MAX];
static char g_key_path[PATH_MAX];

static int tu_run_cmd(const char* cmd) {
  int rc = system(cmd);
#if defined(_WIN32)
  /* On Windows, system() returns the program's return code directly (or -1). */
  return (rc == -1 || rc != 0) ? -1 : 0;
#else
  if (rc == -1) return -1;
  if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) return 0;
  return -1;
#endif
}

static void tu_pick_openssl(char* out, size_t cap) {
#if defined(_WIN32)
  snprintf(out, cap, "openssl");
#else
  const char* p = getenv("OPENSSL");
  snprintf(out, cap, "%s", (p && *p) ? p : "openssl");
#endif
}

static int tu_mktemp_dir(char* out, size_t cap) {
#if defined(MKDTEMP_NOT_AVAILABLE)
  int pid = (int)GetCurrentProcessId();
  snprintf(out, cap, "C:\\Windows\\Temp\\bvcq_%d_%u", pid, (unsigned)GetTickCount());
  if (_mkdir(out) == 0) return 0;
  return -1;
#else
  snprintf(out, cap, "/tmp/bvcqXXXXXX");
  return mkdtemp(out) ? 0 : -1;
#endif
}

/* Generate a throwaway EC P-256 key + self-signed cert (CN=localhost, 1 day) */
static int tu_make_ephemeral_cert(const char* dir,
                                  char* cert_path, size_t ccap,
                                  char* key_path,  size_t kcap) {
  snprintf(cert_path, ccap, "%s/%s", dir, "cert.pem");
  snprintf(key_path,  kcap, "%s/%s", dir, "key.pem");

  char openssl[512];
  tu_pick_openssl(openssl, sizeof(openssl));

  /* OpenSSL 3 one-shot EC key + self-signed cert.
     This is *much* faster than RSA:2048 (milliseconds vs seconds). */
#if defined(_WIN32)
  char cmd[1024];
  _snprintf(cmd, (unsigned)sizeof(cmd),
            "%s req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "
            "-sha256 -days 1 -subj /CN=localhost -keyout \"%s\" -out \"%s\" >NUL 2>&1",
            openssl, key_path, cert_path);
#else
  char cmd[1024];
  snprintf(cmd, sizeof(cmd),
           "%s req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "
           "-sha256 -days 1 -subj /CN=localhost -keyout %s -out %s >/dev/null 2>&1",
           openssl, key_path, cert_path);
#endif
  return tu_run_cmd(cmd);
}

/* ---------- Optional log sink so the lib can explain failures during tests ---------- */
static void tu_log_sink(int level, const char* msg, void* user) {
  (void)level; (void)user;
  fprintf(stderr, "[bvcq] %s\n", msg ? msg : "");
}

/* ---------- Last-resort cleanup if a test aborts ---------- */
static test_ctx* g_last_tc = NULL;

static void tu_atexit_cleanup(void) {
  if (!g_last_tc) return;

  /* Always stop any dangling listener first */
  if (g_last_tc->lst) {
    bvc_quic_listener_stop(g_last_tc->lst);
    g_last_tc->lst = 0;
  }
  if (g_last_tc->lib) {
    bvc_quic_shutdown(g_last_tc->lib);
    g_last_tc->lib = 0;
  }
}

/* ---------- Public test helpers ---------- */

int tu_init(test_ctx* tc){
  memset(tc, 0, sizeof(*tc));
  int wake = -1;

  bvc_quic_status st = bvc_quic_init(&tc->lib, &wake);
  if (st != BVCQ_OK) {
    fprintf(stderr, "tu_init: init -> %d\n", st);
    return 1;
  }

  /* Single ALPN for tests — must match client/server */
  const char* alpns[] = { "bvcp" };

  /* Settings (defaults; just set .size) */
  bvcq_settings settings;
  memset(&settings, 0, sizeof(settings));
  settings.size = sizeof(settings);

  /* Prepare credentials for each role */
  bvcq_credentials client;
  memset(&client, 0, sizeof(client));
  client.kind = BVCQ_CRED_NONE; /* client sends no cert; verify disabled */

  bvcq_credentials server;
  memset(&server, 0, sizeof(server));
  server.kind = BVCQ_CRED_NONE;

  /* If server creds are NONE, create a temporary self-signed cert */
  if (server.kind == BVCQ_CRED_NONE) {
    if (tu_mktemp_dir(g_tmp_dir, sizeof(g_tmp_dir)) != 0) {
      fprintf(stderr, "tu_init: mktemp dir failed\n");
      return 2;
    }
    if (tu_make_ephemeral_cert(g_tmp_dir, g_cert_path, sizeof(g_cert_path),
                               g_key_path,  sizeof(g_key_path)) != 0) {
      fprintf(stderr, "tu_init: openssl failed to create test cert\n");
      return 2;
    }
    server.kind      = BVCQ_CRED_PEM_FILES;
    server.cert_file = g_cert_path;
    server.key_file  = g_key_path;
    server.key_pass  = NULL;
  }

  /* Registration */
  bvcq_reg reg = 0;
  st = bvc_quic_open_registration(tc->lib, "tests", &reg);
  if (st != BVCQ_OK) {
    fprintf(stderr, "tu_init: open_registration -> %d\n", st);
    return 3;
  }
  tc->reg = reg;

  /* Client-only config */
  {
    bvcq_cfg cfg = 0;
    bvc_quic_status s = bvc_quic_open_config(tc->lib, tc->reg,
                            alpns, 1,
                            &settings,
                            &client,    /* client_creds */
                            /* server_creds */ NULL,
                            BVCQ_VERIFY_INSECURE_NO_VERIFY,
                            BVCQ_VERIFY_INSECURE_NO_VERIFY,
                            &cfg);
    if (s != BVCQ_OK) {
      fprintf(stderr, "tu_init: open_config(client-only) -> %d\n", s);
      return 4;
    }
    tc->cfg_client = cfg;
  }

  /* Server-only config */
  {
    bvcq_cfg cfg = 0;
    bvc_quic_status s = bvc_quic_open_config(tc->lib, tc->reg,
                            alpns, 1,
                            &settings,
                            /* client_creds */ NULL,
                            &server,    /* server_creds (PEM_FILES) */
                            BVCQ_VERIFY_INSECURE_NO_VERIFY,
                            BVCQ_VERIFY_INSECURE_NO_VERIFY,
                            &cfg);
    if (s != BVCQ_OK) {
      fprintf(stderr, "tu_init: open_config(server-only) -> %d\n", s);
      return 5;
    }
    tc->cfg_server = cfg;
  }

  /* Register last-resort cleanup once per process, and remember tc */
  static int atexit_registered = 0;
  if (!atexit_registered) { atexit(tu_atexit_cleanup); atexit_registered = 1; }
  g_last_tc = tc;

  tc->lst  = 0;
  tc->port = 0;

  return 0;
}

/* --- helper: try to re-bind the same port briefly to catch leaks --- */
static void tu_port_reuse_guard(test_ctx* tc){
  if (!tc || !tc->lib || tc->cfg_server == 0) return;

  /* Only useful if the test used a fixed/known port. */
  if (tc->port == 0) return;

  const int attempts = 10;     /* ~100–200ms total */
  const int sleep_ms = 20;

  for (int i = 0; i < attempts; i++) {
    bvcq_listener tmp = 0;
    bvc_quic_status s = bvc_quic_listener_start(
        tc->lib, tc->reg, tc->cfg_server, "0.0.0.0", tc->port, &tmp);

    if (s == BVCQ_OK) {
      /* success: port is reusable; stop and we’re done */
      bvc_quic_listener_stop(tmp);
      return;
    }

    /* If still in TIME_WAIT or a late close, give it a moment and retry */
#if defined(_WIN32)
    Sleep((DWORD)sleep_ms);
#else
    usleep(sleep_ms * 1000);
#endif
  }

  /* If we’re here, something is still holding the port. Warn loudly. */
  fprintf(stderr,
          "[bvcq] WARNING: port-reuse guard could not rebind port %u "
          "(possible leak or slow close)\n",
          (unsigned)tc->port);
}

void tu_shutdown(test_ctx* tc){
  if (!tc) return;

  /* Always stop any open listener first */
  if (tc->lst) {
    bvc_quic_listener_stop(tc->lst);
    tc->lst = 0;
  }

  /* --- port reuse/leak guard BEFORE shutting down the lib --- */
  tu_port_reuse_guard(tc);

  /* Now tear everything down */
  bvc_quic_shutdown(tc->lib);
  tc->lib = 0;

  /* Best-effort cleanup of ephemeral cert files/dir */
  if (g_cert_path[0]) unlink(g_cert_path);
  if (g_key_path[0])  unlink(g_key_path);
  if (g_tmp_dir[0])   rmdir(g_tmp_dir);

  if (g_last_tc == tc) g_last_tc = NULL;
}

int tu_open_server(test_ctx* tc, const char* ip, uint16_t port, bvcq_listener* out){
  if (!tc || !out) return 1;

  /* Defensive: stop any previous listener left around by the test */
  if (tc->lst) {
    bvc_quic_listener_stop(tc->lst);
    tc->lst = 0;
  }

  uint16_t want = port; /* if 0, ask OS for an ephemeral port */
  bvcq_listener lst = 0;

  if (bvc_quic_listener_start(tc->lib, tc->reg, tc->cfg_server, ip, want, &lst) != BVCQ_OK) {
    return 1;
  }

  /* If we bound to port 0, discover the real port and store it */
  uint16_t got = want;
  if (want == 0) {
    if (bvc_quic_listener_get_port(lst, &got) != BVCQ_OK) {
      bvc_quic_listener_stop(lst);
      return 1;
    }
  }

  tc->lst  = lst;
  tc->port = got;
  *out     = lst;
  return 0;
}

int tu_connect(test_ctx* tc, const char* sni_or_ip, uint16_t port, bvcq_conn* out_conn){
  /* Use the CLIENT config */
  return bvc_quic_connect(tc->lib, tc->reg, tc->cfg_client,
                          sni_or_ip, /* server_name (SNI) */
                          sni_or_ip, /* ip or hostname */
                          port, out_conn) == BVCQ_OK ? 0 : 1;
}

void evbuf_init(evbuf* b, size_t cap){
  b->buf = (uint8_t*)malloc(cap);
  b->cap = cap;
  b->used = 0;
}

void evbuf_free(evbuf* b){
  free(b->buf);
  b->buf = NULL;
  b->cap = 0;
  b->used = 0;
}

size_t tu_drain_until(test_ctx* tc, evbuf* b, int timeout_ms){
  const int step = 5;
  b->used = 0;
  for (int elapsed = 0; elapsed < timeout_ms; elapsed += step){
    size_t used = 0;
    bvc_quic_status st = bvc_quic_drain_events(tc->lib, b->buf, b->cap, &used);
    if (st == BVCQ_OK && used > 0){
      b->used = used;
      return used;
    }
    SLEEP_MS(step);
  }
  return 0;
}

const bvcq_ev_hdr* tu_find_event(const evbuf* b, uint32_t type){
  size_t off = 0;
  while (off + sizeof(bvcq_ev_hdr) <= b->used){
    const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(b->buf + off);
    if (h->type == type) return h;
    if (h->size == 0) break;
    off += h->size;
  }
  return NULL;
}