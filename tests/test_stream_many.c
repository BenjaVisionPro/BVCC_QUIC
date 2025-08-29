#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
#include <stdint.h>

/* tiny helpers to walk the event buffer */
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
  const uint16_t port = 40114;

  bvcq_listener lst = 0;
  ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", port, &lst) == 0);

  bvcq_conn conn = 0;
  ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", port, &conn) == 0);

  /* create many small streams and send a 1-byte FIN on each */
  enum { N = 8 };
  for (int i = 0; i < N; i++) {
    bvcq_stream s = 0;
    ASSERT_OK(bvc_quic_stream_open(conn, /*bidi*/1, &s));
    const char msg = 'x';
    ASSERT_OK(bvc_quic_stream_send(s, &msg, 1, /*fin*/1, /*flags*/0));
  }

  /* drain events and assert we saw what we expect */
  evbuf eb; evbuf_init(&eb, 64 * 1024);
  ssize_t drained = tu_drain_until(&tc, &eb, 2000);
  if (drained < 0) drained = 0;

  size_t n_opened   = count_events_of_type(eb.buf, (size_t)drained, BVCQ_EV_STREAM_OPENED);
  size_t n_writable = count_events_of_type(eb.buf, (size_t)drained, BVCQ_EV_STREAM_WRITABLE);

  ASSERT_TRUE(n_opened   >= N);
  ASSERT_TRUE(n_writable >= N);

  bvc_quic_conn_close(conn, 0);
  bvc_quic_listener_stop(lst);
  evbuf_free(&eb);
  tu_shutdown(&tc);
  return 0;
}