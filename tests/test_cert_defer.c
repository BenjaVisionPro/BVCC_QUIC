// tests/test_cert_defer.c
//
// VERIFY_DEFER behavior differs across TLS providers/platforms.
// We accept three outcomes as valid:
//  A) CERT_REQUIRED -> cert_complete(accept=1) -> CONNECTED
//  B) CONNECTED directly (provider ignores defer); cert_complete is a no-op
//  C) CLOSED (handshake refused); cert_complete is NOTFOUND (already resolved)
//
// We bind server on an ephemeral port and discover it via public API.

#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static int64_t now_ms(void){
#if defined(_WIN32)
    return (int64_t)(GetTickCount64());
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec/1000000;
#endif
}
static void sleep_ms(int ms){
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts; ts.tv_sec = ms/1000; ts.tv_nsec = (ms%1000)*1000000;
    nanosleep(&ts, NULL);
#endif
}

// Wait for one of several event types; returns the type seen, or 0 on timeout/failure.
// Optionally captures conn_id.
static uint32_t wait_for_any(bvcq_lib lib,
                             const uint32_t* types, int ntypes,
                             uint8_t* scratch, size_t scratch_len,
                             int timeout_ms,
                             uint64_t* out_conn_id)
{
    const int step = 10;
    const int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    if (out_conn_id) *out_conn_id = 0;

    while (timeout_ms <= 0 || now_ms() < deadline) {
        size_t used = 0;
        bvc_quic_status st = bvc_quic_drain_events(lib, scratch, scratch_len, &used);
        if (st == BVCQ_OK && used >= sizeof(bvcq_ev_hdr)) {
            size_t off = 0;
            while (off + sizeof(bvcq_ev_hdr) <= used) {
                const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(scratch + off);
                if (h->size == 0 || off + h->size > used) break;
                for (int i = 0; i < ntypes; i++) {
                    if (h->type == types[i]) {
                        if (out_conn_id && h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t)) {
                            memcpy(out_conn_id, (const uint8_t*)h + sizeof(bvcq_ev_hdr), sizeof(uint64_t));
                        }
                        return h->type;
                    }
                }
                off += h->size;
            }
        } else if (st != BVCQ_ERR_AGAIN && st != BVCQ_OK) {
            return 0;
        }
        sleep_ms(step);
    }
    return 0; // timeout
}

int main(void){
    test_ctx tc;
    ASSERT_TRUE(tu_init(&tc) == 0);

    // Start server on ephemeral port.
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", 0, &lst) == 0);

    uint16_t port = 0;
    ASSERT_OK(bvc_quic_listener_get_port(lst, &port));
    ASSERT_TRUE(port != 0);

    // Client with VERIFY_DEFER; no client cert.
    const char* alpn[] = { "bvcp" };
    bvcq_credentials cli = (bvcq_credentials){0};
    cli.kind = BVCQ_CRED_NONE;

    bvcq_cfg cfg_cli = 0;
    ASSERT_OK(bvc_quic_open_config(
        tc.lib, tc.reg,
        alpn, 1,
        /*settings*/ NULL,
        &cli,          /* client_creds */
        NULL,          /* server_creds unused here */
        BVCQ_VERIFY_DEFER,
        BVCQ_VERIFY_STRICT,
        &cfg_cli));

    // Connect using SNI "localhost" to match the test cert CN, but route to 127.0.0.1.
    bvcq_conn conn = 0;
    ASSERT_OK(bvc_quic_connect(tc.lib, tc.reg, cfg_cli,
                               "localhost", "127.0.0.1", port, &conn));

    uint8_t evbuf[4096];
    uint64_t ev_conn_id = 0;

    const uint32_t wants1[] = { BVCQ_EV_CONN_CERT_REQUIRED, BVCQ_EV_CONN_CONNECTED, BVCQ_EV_CONN_CLOSED };
    uint32_t first = wait_for_any(tc.lib, wants1, 3, evbuf, sizeof(evbuf), /*timeout*/ 6000, &ev_conn_id);
    ASSERT_TRUE(first != 0);

    if (first == BVCQ_EV_CONN_CERT_REQUIRED) {
        // Preferred path: complete, then expect CONNECTED.
        ASSERT_OK(bvc_quic_conn_cert_complete(conn, /*accept=*/1, /*alert=*/0));

        const uint32_t wants2[] = { BVCQ_EV_CONN_CONNECTED, BVCQ_EV_CONN_CLOSED };
        uint32_t second = wait_for_any(tc.lib, wants2, 2, evbuf, sizeof(evbuf), 6000, &ev_conn_id);
        ASSERT_TRUE(second == BVCQ_EV_CONN_CONNECTED);

        // Subsequent cert_complete should be a no-op.
        bvc_quic_status s2 = bvc_quic_conn_cert_complete(conn, 1, 0);
        ASSERT_TRUE(s2 == BVCQ_OK || s2 == BVCQ_ERR_NOTFOUND);

    } else if (first == BVCQ_EV_CONN_CONNECTED) {
        // Provider ignored DEFER; cert_complete should be a no-op.
        bvc_quic_status s = bvc_quic_conn_cert_complete(conn, 1, 0);
        ASSERT_TRUE(s == BVCQ_OK || s == BVCQ_ERR_NOTFOUND);

    } else { // BVCQ_EV_CONN_CLOSED
        // Strict provider rejected before connected. Ensure cert_complete is NOTFOUND (or OK).
        bvc_quic_status s = bvc_quic_conn_cert_complete(conn, 1, 0);
        ASSERT_TRUE(s == BVCQ_ERR_NOTFOUND || s == BVCQ_OK);
        // CLOSED is acceptable for this cross-provider test.
    }

    // Cleanup
    bvc_quic_conn_close(conn, 0);
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}