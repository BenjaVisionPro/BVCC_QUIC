#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>

/*
  Validates:
    - stream shutdown is safe before connection shutdown
    - subsequent ops on a shut stream return NOTFOUND (no UAF)
    - draining after shutdown doesn't crash and eventually empties
    - connection shutdown then listener stop is clean and idempotent
*/

int main(void){
    test_ctx tc; ASSERT_TRUE(tu_init(&tc)==0);

    const uint16_t port = 40116;
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", port, &lst) == 0);

    bvcq_conn conn = 0;
    ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", port, &conn) == 0);

    // Open a bidi stream and immediately shut it down (no pre-shutdown sends).
    bvcq_stream s = 0;
    ASSERT_EQ(bvc_quic_stream_open(conn, /*bidi=*/1, &s), BVCQ_OK);

    bvc_quic_stream_shutdown(s);

    // Further sends should fail with NOTFOUND (guard against UAF/double-close).
    static const uint8_t kPing[1] = { 0x00 };
    ASSERT_EQ(bvc_quic_stream_send(s, kPing, sizeof(kPing), /*fin=*/0, 0), BVCQ_ERR_NOTFOUND);

    // Drain whatever events were produced so far (may be zero if very fast).
    evbuf big; evbuf_init(&big, 64 * 1024);
    (void)tu_drain_until(&tc, &big, 1000);

    // Close the connection next and drain once more.
    bvc_quic_conn_close(conn, /*app_error_code=*/0);
    (void)tu_drain_until(&tc, &big, 1000);

    // Stop the listener; doing it twice should be harmless.
    bvc_quic_listener_stop(lst);
    bvc_quic_listener_stop(lst);

    // Final drain: queue should be empty (AGAIN) and not scribble on outputs.
    size_t used = (size_t)0xDEADBEEF;
    memset(big.buf, 0xCD, big.cap);
    bvc_quic_status st = bvc_quic_drain_events(tc.lib, big.buf, big.cap, &used);
    ASSERT_EQ(st, BVCQ_ERR_AGAIN);
    ASSERT_EQ(used, 0);

    evbuf_free(&big);
    tu_shutdown(&tc);
    return 0;
}