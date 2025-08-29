// tests/test_alpn_mismatch.c
//
// Strict version:
// - Prove we do NOT become CONNECTED within a short window.
// - Then proactively close and REQUIRE we see CLOSED promptly.

#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

/* --- tiny helpers --------------------------------------------------------- */
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

/* Drain until we see a given type; returns 1 if seen, 0 on timeout/fail. */
static int wait_for_event_type(bvcq_lib lib, uint32_t want_type,
                               uint8_t* scratch, size_t scratch_len,
                               int timeout_ms)
{
    const int step = 2; /* tighter polling */
    const int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);

    for (;;) {
        size_t used = 0;
        bvc_quic_status st = bvc_quic_drain_events(lib, scratch, scratch_len, &used);

        if (st == BVCQ_OK && used >= sizeof(bvcq_ev_hdr)) {
            size_t off = 0;
            while (off + sizeof(bvcq_ev_hdr) <= used) {
                const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(scratch + off);
                if (h->size == 0 || off + h->size > used) break; // guard
                if (h->type == want_type) return 1;
                off += h->size;
            }
            /* continue immediately after consuming a batch */
            continue;
        } else if (st != BVCQ_ERR_AGAIN && st != BVCQ_OK) {
            return 0; // unexpected failure
        }

        if (timeout_ms > 0 && now_ms() >= deadline) break;
        sleep_ms(step);
    }
    return 0; // timeout
}

int main(void){
    test_ctx tc;
    ASSERT_TRUE(tu_init(&tc) == 0);

    /* Start server on ephemeral port; discover the port via the public API. */
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", 0, &lst) == 0);

    uint16_t port = 0;
    ASSERT_OK(bvc_quic_listener_get_port(lst, &port));
    ASSERT_TRUE(port != 0);

    /* Prepare a client config with the WRONG ALPN. */
    const char* wrong_alpn[] = { "wrong" };
    bvcq_credentials cli = {0};
    cli.kind = BVCQ_CRED_NONE;

    bvcq_cfg cfg = 0;
    ASSERT_OK(bvc_quic_open_config(
        tc.lib, tc.reg,
        wrong_alpn, 1,
        /*settings*/ NULL,
        /*client_creds*/ &cli,
        /*server_creds*/ NULL,   // client-only
        BVCQ_VERIFY_INSECURE_NO_VERIFY,
        BVCQ_VERIFY_STRICT,
        &cfg));

    /* Attempt to connect. */
    bvcq_conn conn = 0;
    ASSERT_OK(bvc_quic_connect(tc.lib, tc.reg, cfg,
                               "127.0.0.1", "127.0.0.1", port, &conn));

    uint8_t evbuf[2048];

    /* 1) MUST NOT see CONNECTED quickly (ALPN mismatch). */
    {
        int saw_connected = wait_for_event_type(tc.lib, BVCQ_EV_CONN_CONNECTED,
                                                evbuf, sizeof(evbuf), /*timeout_ms*/ 300);
        ASSERT_TRUE(saw_connected == 0);
    }

    /* 2) Proactively close and REQUIRE CLOSED promptly. */
    bvc_quic_conn_close(conn, 0);

    {
        int saw_closed = wait_for_event_type(tc.lib, BVCQ_EV_CONN_CLOSED,
                                             evbuf, sizeof(evbuf), /*timeout_ms*/ 10000);
        ASSERT_TRUE(saw_closed == 1);
    }

    /* Cleanup */
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}