#include "test_util.h"
#include "bvc_quic.h"
#include <string.h>

int main(void){
  test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

  /* 1) Start server on ephemeral port and discover the actual port */
  bvcq_listener lst = 0;
  ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", 0, &lst) == 0);

  uint16_t port = 0;
  ASSERT_EQ(bvc_quic_listener_get_port(lst, &port), BVCQ_OK);
  ASSERT_TRUE(port != 0);

  /* 2) Connect a loopback client */
  bvcq_conn cli = 0;
  ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", port, &cli) == 0);

  /* 3) Give the connection a moment to settle; tolerate empty drain */
  evbuf eb; evbuf_init(&eb, 64 * 1024);
  (void)tu_drain_until(&tc, &eb, 3000);

  /* 4) Query stats and sanity-check basic readability */
  bvcq_conn_stats stats;
  memset(&stats, 0, sizeof(stats));
  stats.size = sizeof(stats);

  ASSERT_OK(bvc_quic_get_conn_stats(cli, &stats));

  /* Sanity: fields exist and are readable; no specific values asserted */
  (void)stats.rtt_ms_ewma;
  (void)stats.cwnd_bytes;
  (void)stats.bytes_sent;
  (void)stats.bytes_recv;

  /* 5) Cleanup */
  bvc_quic_conn_close(cli, 0);
  bvc_quic_listener_stop(lst);
  evbuf_free(&eb);
  tu_shutdown(&tc);
  return 0;
}