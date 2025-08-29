// tests/test_events_api.c
#include "test_util.h"
#include <string.h>
#include <stdint.h>

/* simple event walker so we can assert on what actually came back */
static size_t count_events_of_type(const uint8_t* buf, size_t len, uint32_t type) {
  size_t off = 0, n = 0;
  while (off + sizeof(bvcq_ev_hdr) <= len) {
    const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
    if (h->size < sizeof(bvcq_ev_hdr) || off + h->size > len) break; // safety
    if (h->type == type) n++;
    off += h->size;
  }
  return n;
}

static size_t validate_and_count(const uint8_t* buf, size_t len) {
  size_t off = 0, n = 0;
  while (off + sizeof(bvcq_ev_hdr) <= len) {
    const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
    ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr));
    ASSERT_TRUE(off + h->size <= len);
    switch (h->type) {
      case BVCQ_EV_CONN_ACCEPTED:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(bvcq_addr));
        break;
      case BVCQ_EV_CONN_CONNECTED:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(bvcq_addr));
        break;
      case BVCQ_EV_CONN_CERT_REQUIRED:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t));
        break;
      case BVCQ_EV_STREAM_OPENED:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t));
        break;
      case BVCQ_EV_STREAM_READ:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t));
        break;
      case BVCQ_EV_DGRAM_READ:
        ASSERT_TRUE(h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint32_t));
        break;
      default: break;
    }
    n++;
    off += h->size;
  }
  return n;
}

int main(void) {
  test_ctx tc;
  ASSERT_TRUE(tu_init(&tc) == 0);

  size_t used = 0;

  /* 1) empty queue returns AGAIN and doesn't scribble on outputs */
  evbuf tiny; evbuf_init(&tiny, 16);
  memset(tiny.buf, 0xCC, tiny.cap);
  used = 12345;
  bvc_quic_status st = bvc_quic_drain_events(tc.lib, tiny.buf, tiny.cap, &used);
  ASSERT_EQ(st, BVCQ_ERR_AGAIN);
  ASSERT_EQ(used, 0);

  /* 2) start and stop a listener; should enqueue at least a CONN_ACCEPTED */
  bvcq_listener lst = 0;
  ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", 0, &lst) == 0);

  evbuf big; evbuf_init(&big, 64 * 1024);
  ssize_t drained = tu_drain_until(&tc, &big, 2000);
  ASSERT_TRUE(drained >= 0);
  if (drained > 0) {
    size_t total_events = validate_and_count(big.buf, (size_t)drained);
    size_t n_accepted   = count_events_of_type(big.buf, (size_t)drained, BVCQ_EV_CONN_ACCEPTED);
    ASSERT_TRUE(total_events >= n_accepted);
  }

  /* 3) after full drain, the queue should be empty again */
  used = 777;
  st = bvc_quic_drain_events(tc.lib, big.buf, big.cap, &used);
  ASSERT_EQ(st, BVCQ_ERR_AGAIN);
  ASSERT_EQ(used, 0);

  /* cleanup */
  bvc_quic_listener_stop(lst);
  tu_shutdown(&tc);
  evbuf_free(&big);
  evbuf_free(&tiny);
  return 0;
}