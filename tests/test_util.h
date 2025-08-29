#pragma once
#include "bvc_quic.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* -------- Tiny assert helpers used by all tests -------- */
#define ASSERT_TRUE(cond)                                                         \
  do {                                                                            \
    if (!(cond)) {                                                                \
      fprintf(stderr, "ASSERT_TRUE failed: %s @%s:%d\n",                          \
              #cond, __FILE__, __LINE__);                                         \
      exit(1);                                                                    \
    }                                                                             \
  } while (0)

#define ASSERT_EQ(actual, expected)                                               \
  do {                                                                            \
    long long _a = (long long)(actual);                                           \
    long long _e = (long long)(expected);                                         \
    if (_a != _e) {                                                               \
      fprintf(stderr, "ASSERT_EQ failed: %s (%lld) != %s (%lld) @%s:%d\n",        \
              #actual, _a, #expected, _e, __FILE__, __LINE__);                    \
      exit(1);                                                                    \
    }                                                                             \
  } while (0)

#define ASSERT_OK(expr)                                                           \
  do {                                                                            \
    bvc_quic_status _st = (expr);                                                 \
    if (_st != BVCQ_OK) {                                                         \
      fprintf(stderr, "ASSERT_OK failed: %s -> %d @%s:%d\n",                      \
              #expr, (int)_st, __FILE__, __LINE__);                               \
      exit(1);                                                                    \
    }                                                                             \
  } while (0)

/* -------- Sleep helper -------- */
#if defined(_WIN32)
#  include <windows.h>
#  define SLEEP_MS(ms) Sleep(ms)
#else
#  include <time.h>
#  define SLEEP_MS(ms) do {                                                       \
      struct timespec ts;                                                         \
      ts.tv_sec = (ms) / 1000;                                                    \
      ts.tv_nsec = ((ms) % 1000) * 1000000L;                                      \
      nanosleep(&ts, NULL);                                                       \
    } while (0)
#endif

/* -------- Test context & utils -------- */
typedef struct test_ctx {
  bvcq_lib lib;
  bvcq_reg reg;
  bvcq_cfg cfg_client;
  bvcq_cfg cfg_server;
  uint16_t port;         // actual port the server bound to
  bvcq_listener lst;     // last listener (if any) so we can auto-stop
  char cert_file[512];
  char key_file[512];
} test_ctx;

typedef struct {
  uint8_t* buf;
  size_t cap;
  size_t used;
} evbuf;

// Opens a server on ip and (optionally) port. If port==0 an ephemeral port
// is chosen and returned via tc->port (and *out).
int tu_open_server(test_ctx* tc, const char* ip, uint16_t port, bvcq_listener* out);

int  tu_init(test_ctx* tc);
void tu_shutdown(test_ctx* tc);

int  tu_open_server(test_ctx* tc, const char* ip, uint16_t port, bvcq_listener* out);
int  tu_connect(test_ctx* tc, const char* sni_or_ip, uint16_t port, bvcq_conn* out_conn);

void   evbuf_init(evbuf* b, size_t cap);
void   evbuf_free(evbuf* b);
size_t tu_drain_until(test_ctx* tc, evbuf* b, int timeout_ms);
const bvcq_ev_hdr* tu_find_event(const evbuf* b, uint32_t type);