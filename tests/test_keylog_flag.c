#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>

int main(void){
    test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

    /* 1) Calling on a bogus handle should just report UNSUPPORTED (build-time) */
    ASSERT_EQ(bvc_quic_conn_enable_keylog((bvcq_conn)0xDEADBEEF, 1, NULL), BVCQ_ERR_UNSUPPORTED);
    ASSERT_EQ(bvc_quic_conn_enable_keylog((bvcq_conn)0xDEADBEEF, 0, NULL), BVCQ_ERR_UNSUPPORTED);

    /* 2) Bring up a real connection so symbol resolution/linkage is exercised */
    const uint16_t port = 0;
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", port, &lst) == 0);

    uint16_t bound = 0;
    ASSERT_EQ(bvc_quic_listener_get_port(lst, &bound), BVCQ_OK);
    ASSERT_TRUE(bound != 0);

    bvcq_conn conn = 0;
    ASSERT_TRUE(tu_connect(&tc, "127.0.0.1", bound, &conn) == 0);

    /* 3) With keylog feature built out as disabled-by-default, the API should
          return UNSUPPORTED on both enable and disable calls when not compiled
          with -DBVCQ_ENABLE_KEYLOG=ON. The path argument is optional. */
    ASSERT_EQ(bvc_quic_conn_enable_keylog(conn, 1, NULL), BVCQ_ERR_UNSUPPORTED);
    ASSERT_EQ(bvc_quic_conn_enable_keylog(conn, 0, NULL), BVCQ_ERR_UNSUPPORTED);

    /* Cleanup */
    bvc_quic_conn_close(conn, 0);
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}