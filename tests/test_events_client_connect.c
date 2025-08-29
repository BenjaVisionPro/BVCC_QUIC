// tests/test_events_client_connect.c
#include "test_util.h"
#include <string.h>
#include <stdint.h>

/* Walk & count events of a specific type */
static size_t count_of(const uint8_t* buf, size_t len, uint32_t type) {
  size_t off = 0, n = 0;
  while (off + sizeof(bvcq_ev_hdr) <= len) {
    const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
    if (h->size < sizeof(bvcq_ev_hdr) || off + h->size > len) break;
    if (h->type == type) n++;
    off += h->size;
  }
  return n;
}

static size_t validate_all(const uint8_t* buf, size_t len) {
  size_t off = 0, n = 0;
  while (off + sizeof(bvcq_ev_hdr) <= len) {
    const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
    ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr));
    ASSERT_TRUE(off + h->size <= len);
    switch (h->type) {
      case BVCQ_EV_CONN_ACCEPTED:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr)+sizeof(uint64_t)+sizeof(uint64_t)+sizeof(bvcq_addr));
        break;
      case BVCQ_EV_CONN_CONNECTED:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr)+sizeof(uint64_t)+sizeof(bvcq_addr));
        break;
      default: break;
    }
    n++; off += h->size;
  }
  return n;
}

int main(void) {
  test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

  /* Start server (uses tu_open_server: builds config with server creds) */
  bvcq_listener lst = 0;
  ASSERT_EQ(tu_open_server(&tc, "0.0.0.0", 0, &lst), 0);

  uint16_t port = 0;
  ASSERT_EQ(bvc_quic_listener_get_port(lst, &port), BVCQ_OK);
  ASSERT_TRUE(port != 0);

  /* Minimal inline client connect (no tu_connect_client required) */
  // Open a client-only config: ALPN "bvcp", client creds NONE (ok for tests)
  const char* alpn[] = { "bvcp" };
  bvcq_cfg client_cfg = 0;
  ASSERT_EQ(bvc_quic_open_config(
              tc.lib, tc.reg,
              alpn, 1,
              NULL,                         /* settings: none */
              &(bvcq_credentials){ .kind = BVCQ_CRED_NONE }, /* client creds */
              NULL,                         /* server creds: unused here */
              BVCQ_VERIFY_INSECURE_NO_VERIFY,
              BVCQ_VERIFY_STRICT,
              &client_cfg),
            BVCQ_OK);

  bvcq_conn client_conn = 0;
  char host[] = "127.0.0.1";
  ASSERT_EQ(bvc_quic_connect(tc.lib, tc.reg, client_cfg, host, host, port, &client_conn), BVCQ_OK);

  /* Drain & assert we observed the expected connection events */
  evbuf big; evbuf_init(&big, 64 * 1024);
  ssize_t drained = tu_drain_until(&tc, &big, 2000);  /* up to 2s */
  ASSERT_TRUE(drained >= 0);

  if (drained > 0) {
    size_t total = validate_all(big.buf, (size_t)drained);
    size_t n_acc = count_of(big.buf, (size_t)drained, BVCQ_EV_CONN_ACCEPTED);
    size_t n_con = count_of(big.buf, (size_t)drained, BVCQ_EV_CONN_CONNECTED);
    ASSERT_TRUE(n_acc >= 1);
    ASSERT_TRUE(n_con >= 1);
    ASSERT_TRUE(total >= n_acc + n_con);
  }

  /* Clean up */
  bvc_quic_listener_stop(lst);
  tu_shutdown(&tc);
  evbuf_free(&big);
  return 0;
}