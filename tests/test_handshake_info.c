#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
#include <stdint.h>

/* helper: wait for a specific event type */
static int wait_for_event(test_ctx* tc, uint32_t want_type, int timeout_ms) {
  evbuf eb; evbuf_init(&eb, 64 * 1024);
  size_t used = tu_drain_until(tc, &eb, timeout_ms);
  int ok = 0;
  if (used > 0) {
    const bvcq_ev_hdr* h = tu_find_event(&eb, want_type);
    ok = (h != NULL);
  }
  evbuf_free(&eb);
  return ok;
}

int main(void){
  test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

  /* 1) Bad args / edge cases */
  bvcq_handshake_info hi; memset(&hi, 0xAA, sizeof(hi));

  /* NULL out pointer */
  ASSERT_EQ(bvc_quic_get_conn_handshake((bvcq_conn)1, NULL), BVCQ_ERR_BADARG);

  /* size too small -> BADARG */
  memset(&hi, 0, sizeof(hi));
  hi.size = (uint32_t)(sizeof(hi) - 1);
  ASSERT_EQ(bvc_quic_get_conn_handshake((bvcq_conn)1, &hi), BVCQ_ERR_BADARG);

  /* bogus conn handle -> NOTFOUND */
  memset(&hi, 0, sizeof(hi));
  hi.size = sizeof(hi);
  ASSERT_EQ(bvc_quic_get_conn_handshake((bvcq_conn)999999, &hi), BVCQ_ERR_NOTFOUND);

  /* 2) Happy path: start server + connect client and query */
  bvcq_listener lst = 0;
  ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", /*port*/0, &lst) == 0);

  uint16_t bound = 0;
  ASSERT_EQ(bvc_quic_listener_get_port(lst, &bound), BVCQ_OK);
  ASSERT_TRUE(bound != 0);

  bvcq_conn conn = 0;
  ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", bound, &conn) == 0);

  /* Ensure the handshake has actually completed */
  ASSERT_TRUE(wait_for_event(&tc, BVCQ_EV_CONN_CONNECTED, 2000) == 1);

  /* 3) Get handshake info and validate */
  memset(&hi, 0xCC, sizeof(hi));            /* poison to ensure library overwrites */
  hi.size = sizeof(hi);
  ASSERT_EQ(bvc_quic_get_conn_handshake(conn, &hi), BVCQ_OK);

  /* API stability checks */
  ASSERT_EQ(hi.size, sizeof(hi));           /* library must return correct size */

  /* Accept either:
     - conservative defaults (UNKNOWN/0) when headers don't expose details
     - real values when available (TLS 1.3, nonzero group) */
  if (hi.tls_version == BVCQ_TLS_PROTOCOL_UNKNOWN) {
    ASSERT_EQ(hi.tls_group, 0u);
  } else {
    ASSERT_EQ(hi.tls_version, BVCQ_TLS_PROTOCOL_1_3);
    /* Don’t assert a specific group (varies: e.g., 29=X25519, 23=P-256, etc.). */
    ASSERT_TRUE(hi.tls_group != 0u);
  }

  /* 4) Cleanup */
  bvc_quic_conn_close(conn, 0);
  bvc_quic_listener_stop(lst);
  tu_shutdown(&tc);
  return 0;
}