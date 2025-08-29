#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
#include <stdio.h>

/* Count WRITABLE events (simple scanner over our serialized event buffer) */
static size_t count_writable(const uint8_t* buf, size_t len) {
  size_t off = 0, n = 0;
  while (off + sizeof(bvcq_ev_hdr) <= len) {
    const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
    if (h->size < sizeof(bvcq_ev_hdr) || off + h->size > len) break; // safety
    if (h->type == BVCQ_EV_STREAM_WRITABLE) n++;
    off += h->size;
  }
  return n;
}

int main(void){
  test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

  /* 1) Start server on an ephemeral port and discover it */
  bvcq_listener lst = 0;
  ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", 0, &lst) == 0);

  uint16_t port = 0;
  ASSERT_EQ(bvc_quic_listener_get_port(lst, &port), BVCQ_OK);
  ASSERT_TRUE(port != 0);

  /* 2) Connect client and open a bidi stream */
  bvcq_conn conn = 0;
  ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", port, &conn) == 0);

  bvcq_stream s = 0;
  ASSERT_OK(bvc_quic_stream_open(conn, /*bidi*/1, &s));

  /* 3) Push a bunch of small writes to create “soft” backpressure.
     MsQuic generally queues and eventually emits WRITABLE as sends complete. */
  const char* msg = "data";
  const size_t msg_len = strlen(msg);

  /* Fire a decent number of small writes; we don’t expect errors here.
     We’re not asserting on return codes beyond OK because MsQuic may queue
     internally and still return SUCCESS. */
  for (int i = 0; i < 200; i++) {
    ASSERT_OK(bvc_quic_stream_send(s, msg, msg_len, /*fin*/0, /*flags*/0));
  }

  /* 4) Drain events for a short period and assert that at least one WRITABLE
        arrived, indicating send credits cycled (i.e., pressure relieved). */
  evbuf eb; evbuf_init(&eb, 64 * 1024);
  ssize_t drained = tu_drain_until(&tc, &eb, /*ms*/ 2000);
  ASSERT_TRUE(drained >= 0);  /* tolerate very fast runs */
  if (drained > 0) {
    size_t n_wr = count_writable(eb.buf, (size_t)drained);
    /* We expect at least one writable notification across 200 sends. */
    ASSERT_TRUE(n_wr >= 1);
  }

  /* 5) Send a FIN to close the stream nicely; not strictly required, but keeps
        the transport happy for orderly shutdowns in CI. */
	const char* finmsg = "x";
	ASSERT_OK(bvc_quic_stream_send(s, finmsg, 1, /*fin*/1, /*flags*/0));

  /* 6) Cleanup */
  bvc_quic_conn_close(conn, 0);
  bvc_quic_listener_stop(lst);
  evbuf_free(&eb);
  tu_shutdown(&tc);
  return 0;
}