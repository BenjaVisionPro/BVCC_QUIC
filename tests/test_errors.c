#include "test_util.h"

int main(void){
  test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

  // bad args
  size_t used=0;
  ASSERT_EQ(bvc_quic_drain_events(tc.lib, NULL, 0, &used), BVCQ_ERR_BADARG);

  // notfound handles
  bvcq_conn bogus_conn = (bvcq_conn)9999;
  bvcq_stream bogus_stream = (bvcq_stream)9999;
  uint8_t d[1] = {0};

  ASSERT_EQ(bvc_quic_dgram_send(bogus_conn, d, 1), BVCQ_ERR_NOTFOUND);
  ASSERT_EQ(bvc_quic_stream_send(bogus_stream, d, 1, 0, 0), BVCQ_ERR_NOTFOUND);

  tu_shutdown(&tc);
  return 0;
}