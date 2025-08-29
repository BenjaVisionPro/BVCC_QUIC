// tests/test_smoke.c
//
// Smoke test using only public bvc_quic API + test_util helpers.
// - Server binds to port 0 (ephemeral) and we query the actual port.
// - Client connects, waits for CONN_CONNECTED, opens a bidi stream,
//   waits for STREAM_OPENED, then sends a tiny FIN.
//
// This avoids fixed-port collisions and doesn't depend on test_ctx internals.

#include "bvc_quic.h"
#include "test_util.h"   // ASSERT_OK / ASSERT_TRUE / ASSERT_EQ, test_ctx, evbuf, tu_init, tu_shutdown, etc.
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

static int wait_for_event(bvcq_lib lib, uint32_t want_type,
                          uint8_t* scratch, size_t scratch_len,
                          int timeout_ms,
                          /* optional outs */
                          uint64_t* out_conn_id,
                          uint64_t* out_stream_id)
{
    const int step_ms = 10;
    const int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    size_t used = 0;

    if (out_conn_id)   *out_conn_id = 0;
    if (out_stream_id) *out_stream_id = 0;

    for (;;) {
        bvc_quic_status st = bvc_quic_drain_events(lib, scratch, scratch_len, &used);
        if ((st == BVCQ_OK) && used >= sizeof(bvcq_ev_hdr)) {
            size_t off = 0;
            while (off + sizeof(bvcq_ev_hdr) <= used) {
                const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(scratch + off);
                if (h->size == 0 || off + h->size > used) break; // partial/corrupt guard

                if (h->type == want_type) {
                    const uint8_t* p = scratch + off + sizeof(bvcq_ev_hdr);
                    if (want_type == BVCQ_EV_CONN_CONNECTED) {
                        if (out_conn_id && h->size >= sizeof(bvcq_ev_hdr)+sizeof(uint64_t)) {
                            memcpy(out_conn_id, p, sizeof(uint64_t));
                        }
                    } else if (want_type == BVCQ_EV_STREAM_OPENED) {
                        // payload: conn_id (u64) + stream_id (u64) + bidi (u8)
                        if (h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t)*2 + sizeof(uint8_t)) {
                            if (out_conn_id)   memcpy(out_conn_id,  p,                            sizeof(uint64_t));
                            if (out_stream_id) memcpy(out_stream_id, p + sizeof(uint64_t),        sizeof(uint64_t));
                        }
                    }
                    return 1; // got it
                }

                off += h->size;
            }
        } else if (st != BVCQ_ERR_AGAIN && st != BVCQ_OK) {
            return 0; // unexpected failure
        }

        if (timeout_ms > 0 && now_ms() >= deadline) break;
        sleep_ms(step_ms);
    }
    return 0; // timeout
}

int main(void) {
    test_ctx tc;
    ASSERT_TRUE(tu_init(&tc) == 0);

    // Start a listener on ephemeral port 0, then query the actual port.
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", /*port=*/0, &lst) == 0);

    uint16_t port = 0;
    ASSERT_OK(bvc_quic_listener_get_port(lst, &port));
    ASSERT_TRUE(port != 0);

    // Client-only config: no client cert, skip server verify (OK for loopback tests).
    const char* alpn[] = { "bvcp" };
    bvcq_credentials cli = {0};
    cli.kind = BVCQ_CRED_NONE;

    bvcq_cfg cfg_cli = 0;
    ASSERT_OK(bvc_quic_open_config(tc.lib, tc.reg,
                                   alpn, 1,
                                   NULL,           // settings (unused)
                                   &cli,           // client creds
                                   NULL,           // server creds (not used by client config)
                                   BVCQ_VERIFY_INSECURE_NO_VERIFY,
                                   BVCQ_VERIFY_STRICT,
                                   &cfg_cli));

    // Connect to loopback using the discovered port.
    bvcq_conn conn = 0;
    ASSERT_OK(bvc_quic_connect(tc.lib, tc.reg, cfg_cli,
                               "127.0.0.1", "127.0.0.1", port, &conn));

    // Wait until the connection is established before touching streams.
    uint8_t evbuf[4096];
    uint64_t got_conn = 0;
    ASSERT_TRUE(wait_for_event(tc.lib, BVCQ_EV_CONN_CONNECTED, evbuf, sizeof(evbuf), 2000, &got_conn, NULL));

    // Open a bidi stream from the client.
    bvcq_stream s = 0;
    ASSERT_OK(bvc_quic_stream_open(conn, /*bidi=*/1, &s));

    // Wait for the server to observe the peer stream start.
    uint64_t sv_conn = 0, sv_stream = 0;
    ASSERT_TRUE(wait_for_event(tc.lib, BVCQ_EV_STREAM_OPENED, evbuf, sizeof(evbuf), 2000, &sv_conn, &sv_stream));
    ASSERT_TRUE(sv_stream != 0);

    // Send a tiny FIN to exercise the path.
    const char* msg = "hi";
    ASSERT_OK(bvc_quic_stream_send(s, msg, (uint32_t)strlen(msg), /*fin=*/1, 0));

    // Cleanup
    bvc_quic_conn_close(conn, 0);
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}