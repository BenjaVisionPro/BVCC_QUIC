// tests/test_datagram_echo.c
#include "bvc_quic.h"
#include "test_util.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#if !defined(_WIN32)
  #include <signal.h>
  #include <execinfo.h>
#endif

/* ===== Crash handler (prints backtrace on SIGSEGV/SIGBUS) ===== */
#if !defined(_WIN32)
static void datagram_echo_crash_handler(int sig){
    void* bt[64]; int n = backtrace(bt, 64);
    fprintf(stderr, "\n[datagram_echo] FATAL: signal %d\n", sig);
    backtrace_symbols_fd(bt, n, 2);
    _Exit(128 + sig);
}
#endif

static void install_crash_handlers(void){
#if !defined(_WIN32)
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = datagram_echo_crash_handler;
    sa.sa_flags   = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS,  &sa, NULL);
#endif
#endif
}

/* ===== Tiny stash with extra sanity checks ===== */
static uint8_t g_stash[64*1024];
static size_t  g_stash_used = 0;

static void stash_assert(void){
    if (g_stash_used > sizeof(g_stash)) {
        fprintf(stderr, "[datagram_echo] stash overflow (used=%zu cap=%zu)\n",
                g_stash_used, sizeof(g_stash));
        fflush(stderr);
        abort();
    }
}

static void stash_append(const uint8_t* data, size_t len){
    size_t room = sizeof(g_stash) - g_stash_used;
    if (len > room) len = room;
    if (len) {
        memcpy(g_stash + g_stash_used, data, len);
        g_stash_used += len;
        stash_assert();
    }
}
static void stash_consume_prefix(size_t n){
    if (n >= g_stash_used) { g_stash_used = 0; return; }
    memmove(g_stash, g_stash + n, g_stash_used - n);
    g_stash_used -= n;
}

static void drain_once_into_stash(bvcq_lib lib){
    uint8_t tmp[32*1024];
    size_t used = 0;
    bvc_quic_status st = bvc_quic_drain_events(lib, tmp, sizeof(tmp), &used);
    if (st == BVCQ_OK && used) stash_append(tmp, used);
}

/* ===== Safe header/payload parsing (no unaligned struct deref) ===== */
static int read_u32(const uint8_t* p, size_t n, uint32_t* out){
    if (n < 4) return 0; memcpy(out, p, 4); return 1;
}
static int read_u64(const uint8_t* p, size_t n, uint64_t* out){
    if (n < 8) return 0; memcpy(out, p, 8); return 1;
}

/* Scan stash for first event of type want_type, return 1 if found (and popped). */
static int pop_event_from_stash(bvcq_lib lib, uint32_t want_type, int timeout_ms,
                                uint64_t* out_cid,
                                uint8_t* out_payload, uint32_t* inout_plen)
{
    if (out_cid) *out_cid = 0;
    const int step = 10;

    for (int waited=0; waited < timeout_ms; waited += step) {
        drain_once_into_stash(lib);

        size_t off = 0;
        while (1) {
            if (g_stash_used - off < sizeof(bvcq_ev_hdr)) break;

            const uint8_t* bp = g_stash + off;
            size_t remain = g_stash_used - off;

            uint32_t type=0, flags=0, size=0;
            if (!read_u32(bp + 0, remain, &type)) break;
            if (!read_u32(bp + 4, remain, &flags)) break;
            if (!read_u32(bp + 8, remain, &size))  break;

            if (size < sizeof(bvcq_ev_hdr)) {
                fprintf(stderr, "[datagram_echo] bad rec size=%u < hdr (%zu). waiting…\n",
                        (unsigned)size, sizeof(bvcq_ev_hdr));
                break;
            }
            if (size > remain) {
                fprintf(stderr, "[datagram_echo] partial rec need=%u have=%zu. waiting…\n",
                        (unsigned)size, remain);
                break;
            }

            fprintf(stderr, "[datagram_echo] stash ev type=%u size=%u off=%zu used=%zu\n",
                    (unsigned)type, (unsigned)size, off, g_stash_used);

            const uint8_t* payload = bp + sizeof(bvcq_ev_hdr);
            size_t plen = size - sizeof(bvcq_ev_hdr);

            if (type == want_type) {
                if ((type == BVCQ_EV_CONN_ACCEPTED || type == BVCQ_EV_CONN_CONNECTED) && out_cid) {
                    if (plen >= 8) memcpy(out_cid, payload, 8);
                } else if (type == BVCQ_EV_DGRAM_READ) {
                    if (plen >= 12) {
                        uint64_t cid=0; uint32_t dlen=0;
                        memcpy(&cid,  payload + 0, 8);
                        memcpy(&dlen, payload + 8, 4);
                        if (out_cid) *out_cid = cid;
                        if (out_payload && inout_plen) {
                            uint32_t to_copy = *inout_plen;
                            if (to_copy > dlen) to_copy = dlen;
                            if (12 + to_copy <= plen) {
                                memcpy(out_payload, payload + 12, to_copy);
                                *inout_plen = to_copy;
                            } else {
                                *inout_plen = 0;
                            }
                        }
                    }
                }
                stash_consume_prefix(off + size);
                return 1;
            }

            off += size;
            if (off > g_stash_used) { fprintf(stderr, "[datagram_echo] internal off>%zu\n", g_stash_used); abort(); }
        }

        SLEEP_MS(step);
    }
    return 0; /* timeout */
}

static void hex_dump(const char* tag, const uint8_t* p, size_t n){
    fprintf(stderr, "%s len=%zu : [", tag, n);
    for (size_t i=0;i<n;i++){
        fprintf(stderr, "%02X%s", p[i], (i+1==n) ? "" : " ");
        if (i+1>=64 && n>64) { fprintf(stderr, " ..."); break; }
    }
    fprintf(stderr, "]\n");
}

int main(void){
    install_crash_handlers();

    test_ctx tc; ASSERT_TRUE(tu_init(&tc)==0);

    /* Bind server on ephemeral port (0) to dodge reuse collisions. */
    bvcq_listener lst=0; ASSERT_TRUE(tu_open_server(&tc,"0.0.0.0",0,&lst)==0);
    const uint16_t port = tc.port;
    fprintf(stderr, "[datagram_echo] server bound on port %u\n", (unsigned)port);

    /* Connect client */
    bvcq_conn conn=0; ASSERT_TRUE(tu_connect(&tc,"127.0.0.1",port,&conn)==0);

    /* Establishment: accept → connected. */
    ASSERT_TRUE(pop_event_from_stash(tc.lib, BVCQ_EV_CONN_ACCEPTED,  3000, NULL, NULL, NULL) == 1);
    ASSERT_TRUE(pop_event_from_stash(tc.lib, BVCQ_EV_CONN_CONNECTED, 3000, NULL, NULL, NULL) == 1);

    /* Send one datagram with edgey bytes */
    const uint8_t payload[] = { 0x64, 0x67, 0x21, 0x54, 0x00, 0xAA }; /* "dg!T\0\xAA" */
    hex_dump("[datagram_echo] sending", payload, sizeof(payload));
    ASSERT_OK(bvc_quic_dgram_send(conn, payload, (uint32_t)sizeof(payload)));

    /* Expect the echo via the event bridge */
    uint8_t got[64]; uint32_t got_len = sizeof(got);
    uint64_t cid = 0;
    ASSERT_TRUE(pop_event_from_stash(tc.lib, BVCQ_EV_DGRAM_READ, 3000, &cid, got, &got_len) == 1);

    hex_dump("[datagram_echo] received", got, got_len);
    fprintf(stderr, "[datagram_echo] compare: sent=%zu recv=%u\n",
            sizeof(payload), (unsigned)got_len);

    ASSERT_TRUE(got_len == sizeof(payload));
    ASSERT_TRUE(memcmp(got, payload, got_len) == 0);

    bvc_quic_conn_close(conn,0);
    bvc_quic_listener_stop(lst);
    tu_shutdown(&tc);
    return 0;
}