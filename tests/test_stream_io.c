// tests/test_stream_io.c
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

/* Drain until we see BVCQ_EV_CONN_CONNECTED. */
static int wait_connected(bvcq_lib lib, int timeout_ms, uint64_t* out_conn_id){
    const int step_ms = 10;
    const int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    uint8_t buf[4096];
    size_t used = 0;
    if (out_conn_id) *out_conn_id = 0;

    for (;;) {
        bvc_quic_status st = bvc_quic_drain_events(lib, buf, sizeof(buf), &used);
        if ((st == BVCQ_OK) && used >= sizeof(bvcq_ev_hdr)) {
            size_t off = 0;
            while (off + sizeof(bvcq_ev_hdr) <= used) {
                const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
                if (h->size == 0 || off + h->size > used) break;
                if (h->type == BVCQ_EV_CONN_CONNECTED) {
                    if (out_conn_id && h->size >= sizeof(bvcq_ev_hdr)+sizeof(uint64_t)) {
                        memcpy(out_conn_id, buf + off + sizeof(bvcq_ev_hdr), sizeof(uint64_t));
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

/* After opening the stream, drain and capture both STREAM_OPENED and STREAM_WRITABLE.
   We match on the bvcq_stream id we received from the API to avoid mixing streams. */
static int wait_stream_ready(bvcq_lib lib, uint64_t want_sid, int timeout_ms){
    const int step_ms = 10;
    const int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    uint8_t buf[8192];
    size_t used = 0;
    int got_opened = 0;
    int got_writable = 0;

    for (;;) {
        bvc_quic_status st = bvc_quic_drain_events(lib, buf, sizeof(buf), &used);
        if ((st == BVCQ_OK) && used >= sizeof(bvcq_ev_hdr)) {
            size_t off = 0;
            while (off + sizeof(bvcq_ev_hdr) <= used) {
                const bvcq_ev_hdr* h = (const bvcq_ev_hdr*)(buf + off);
                if (h->size == 0 || off + h->size > used) break;

                if (h->type == BVCQ_EV_STREAM_OPENED) {
                    if (h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t)*2 + sizeof(uint8_t)) {
                        uint64_t sid = 0;
                        memcpy(&sid, buf + off + sizeof(bvcq_ev_hdr) + sizeof(uint64_t), sizeof(uint64_t));
                        if (sid == want_sid) got_opened = 1;
                    }
                } else if (h->type == BVCQ_EV_STREAM_WRITABLE) {
                    if (h->size >= sizeof(bvcq_ev_hdr) + sizeof(uint64_t)) {
                        uint64_t sid = 0;
                        memcpy(&sid, buf + off + sizeof(bvcq_ev_hdr), sizeof(uint64_t));
                        if (sid == want_sid) got_writable = 1;
                    }
                }

                if (got_opened && got_writable) return 1;
                off += h->size;
            }
        } else if (st != BVCQ_ERR_AGAIN && st != BVCQ_OK) {
            return 0;
        }
        if (timeout_ms > 0 && now_ms() >= deadline) break;
        sleep_ms(step_ms);
    }
    return (got_opened && got_writable);
}

int main(void){
    test_ctx tc; ASSERT_TRUE(tu_init(&tc) == 0);

    const uint16_t port = 40071;
    bvcq_listener lst = 0;
    ASSERT_TRUE(tu_open_server(&tc, "0.0.0.0", port, &lst) == 0);

    const char* alpn[] = { "bvcp" };
    bvcq_credentials cli = {0};
    cli.kind = BVCQ_CRED_NONE;

    bvcq_cfg cfg_cli = 0;
    ASSERT_OK(bvc_quic_open_config(tc.lib, tc.reg,
                                   alpn, 1, NULL,
                                   &cli, NULL,
                                   BVCQ_VERIFY_INSECURE_NO_VERIFY,
                                   BVCQ_VERIFY_STRICT,
                                   &cfg_cli));

    bvcq_conn conn = 0;
    ASSERT_OK(bvc_quic_connect(tc.lib, tc.reg, cfg_cli,
                               "127.0.0.1", "127.0.0.1", port, &conn));

    // Wait for connection before manipulating streams
    uint64_t cid = 0;
    ASSERT_TRUE(wait_connected(tc.lib, 2000, &cid));

    // Open bidi stream
    bvcq_stream sid = 0;
    ASSERT_OK(bvc_quic_stream_open(conn, /*bidi=*/1, &sid));

    // Drain once to collect both OPENED and WRITABLE (coalesced delivery is common)
    ASSERT_TRUE(wait_stream_ready(tc.lib, (uint64_t)sid, 2000));

    // Send payload and FIN
    const char* msg = "hello stream";
    ASSERT_OK(bvc_quic_stream_send(sid, msg, (uint32_t)strlen(msg), /*fin=*/1, 0));

    // Cleanup
    bvc_quic_conn_close(conn, 0);
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}