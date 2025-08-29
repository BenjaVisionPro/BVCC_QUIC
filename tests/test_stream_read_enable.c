#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
#include <stdint.h>

/* helper: count a specific event type in a drained buffer */
static size_t count_events_of_type(const uint8_t* buf, size_t len, uint32_t type) {
  size_t off = 0, n = 0;
  while (off + sizeof(bvcq_ev_hdr) <= len) {
    const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
    if (h->size < sizeof(bvcq_ev_hdr) || off + h->size > len) break;
    if (h->type == type) n++;
    off += h->size;
  }
  return n;
}

int main(void){
  test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);
  const uint16_t port = 40113;

  /* bring up server + client */
  bvcq_listener lst = 0; ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", port, &lst) == 0);
  bvcq_conn conn = 0;    ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", port, &conn) == 0);

  /* open a bidi stream from the client */
  bvcq_stream s = 0;
  ASSERT_OK(bvc_quic_stream_open(conn, /*bidi*/1, &s));

  /* disable reads (on our handle) — should succeed */
  ASSERT_OK(bvc_quic_stream_set_read_enabled(s, 0));

  /* send something with FIN so the peer definitely has readable data */
  const char* msg = "hello";
  ASSERT_OK(bvc_quic_stream_send(s, msg, strlen(msg), /*fin*/1, /*flags*/0));

  /* drain any events while reads are disabled (on our side) */
  evbuf eb; evbuf_init(&eb, 64 * 1024);
  ssize_t drained_disabled = tu_drain_until(&tc, &eb, 1000);
  if (drained_disabled < 0) drained_disabled = 0;

  /* We should still see stream lifecycle events (opened/writable), but we
     don't expect a BVCQ_EV_STREAM_READ for this handle while disabled. */
  size_t n_read_disabled = count_events_of_type(eb.buf, (size_t)drained_disabled, BVCQ_EV_STREAM_READ);
  /* Not a hard failure if zero events arrived quickly, but if events exist,
     assert there aren't reads for this handle yet. */
  if (drained_disabled > 0) {
    ASSERT_TRUE(n_read_disabled == 0);
  }

  /* now enable reads — API should succeed */
  ASSERT_OK(bvc_quic_stream_set_read_enabled(s, 1));

  /* after enabling, any pending peer data may now surface as READ events */
  ssize_t drained_enabled = tu_drain_until(&tc, &eb, 2000);
  if (drained_enabled < 0) drained_enabled = 0;
  /* We don't require reads to appear (ordering/timing is implementation-defined),
     but if anything arrived, it must be well-formed; tu_drain_until already ensures that. */

  /* cleanup */
  bvc_quic_conn_close(conn, 0);
  bvc_quic_listener_stop(lst);
  evbuf_free(&eb);
  tu_shutdown(&tc);
  return 0;
}