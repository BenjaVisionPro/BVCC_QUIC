#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>

int main(void){
    test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

    /* 1) Start server on ephemeral port (0) */
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", 0, &lst) == 0);

    /* 2) Discover the actual bound port */
    uint16_t port = 0;
    ASSERT_EQ(bvc_quic_listener_get_port(lst, &port), BVCQ_OK);
    ASSERT_TRUE(port != 0);

    /* 3) Connect a loopback client to the discovered port */
    bvcq_conn conn = 0;
    ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", port, &conn) == 0);

    /* Optional: let handshake settle (tolerates empty drain) */
    evbuf tmp; evbuf_init(&tmp, 32 * 1024);
    (void)tu_drain_until(&tc, &tmp, 1000);
    evbuf_free(&tmp);

    /* 4) Query stats and assert minimal invariants */
    bvcq_conn_stats st;
    memset(&st, 0, sizeof(st));
    st.size = sizeof(st);

    ASSERT_EQ(bvc_quic_get_conn_stats(conn, &st), BVCQ_OK);
    ASSERT_TRUE(st.rtt_ms_ewma >= 0.0);

    /* 5) Cleanup */
    bvc_quic_conn_close(conn, 0);
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}