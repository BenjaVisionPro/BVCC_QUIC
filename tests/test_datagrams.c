// tests/test_datagrams.c
#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
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
                          uint64_t* out_conn_id)
{
    const int step_ms = 10;
    const int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    size_t used = 0;
    if (out_conn_id) *out_conn_id = 0;

    for (;;) {
        bvc_quic_status st = bvc_quic_drain_events(lib, scratch, scratch_len, &used);
        if ((st == BVCQ_OK) && used >= sizeof(bvcq_ev_hdr)) {
            size_t off = 0;
            while (off + sizeof(bvcq_ev_hdr) <= used) {
                const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(scratch + off);
                if (h->size == 0 || off + h->size > used) break;
                if (h->type == want_type) {
                    if (out_conn_id && h->size >= sizeof(bvcq_ev_hdr)+sizeof(uint64_t)) {
                        memcpy(out_conn_id, scratch + off + sizeof(bvcq_ev_hdr), sizeof(uint64_t));
                    }
                    return 1;
                }
                off += h->size;
            }
        } else if (st != BVCQ_ERR_AGAIN && st != BVCQ_OK) {
            return 0;
        }
        if (timeout_ms > 0 && now_ms() >= deadline) break;
        sleep_ms(step_ms);
    }
    return 0;
}

int main(void){
    test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

    // Start server (self-signed creds handled internally).
    const uint16_t port = 40072;
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", port, &lst) == 0);

    // Client-only config with insecure verify (OK for test).
    const char* alpn[] = { "bvcp" };
    bvcq_credentials cli = {0};
    cli.kind = BVCQ_CRED_NONE;

    bvcq_cfg cfg_cli = 0;
    ASSERT_OK(bvc_quic_open_config(tc.lib, tc.reg,
                                   alpn, 1,
                                   NULL,
                                   &cli,
                                   NULL,
                                   BVCQ_VERIFY_INSECURE_NO_VERIFY,
                                   BVCQ_VERIFY_STRICT,
                                   &cfg_cli));

    // Connect
    bvcq_conn conn = 0;
    ASSERT_OK(bvc_quic_connect(tc.lib, tc.reg, cfg_cli,
                               "127.0.0.1", "127.0.0.1", port, &conn));

    // Wait for connected before sending a datagram.
    uint8_t evbuf[4096];
    uint64_t got_conn = 0;
    ASSERT_TRUE(wait_for_event(tc.lib, BVCQ_EV_CONN_CONNECTED, evbuf, sizeof(evbuf), 2000, &got_conn));

    // Send a small datagram.
    const char* d = "hello dgram";
    ASSERT_OK(bvc_quic_dgram_send(conn, d, strlen(d)));

    // Give the loop a moment to process (receiver side event isn’t strictly required here).
    sleep_ms(50);

    // Cleanup
    bvc_quic_conn_close(conn, 0);
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}