// lib/events.c — Event emitters + drain API (queue lives in evqueue.c)

#include "bvcq_internal.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

/* --------------------------------------------------------------------------
   Emit helpers (serialize records and enqueue)
   -------------------------------------------------------------------------- */

void emit_conn_accepted(uint64_t cid, uint64_t lstid, const bvcq_addr* peer){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(bvcq_addr));
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_CONN_ACCEPTED; h->flags = 0; h->size = sz;
    uint8_t* p = rec + sizeof(*h);
    memcpy(p, &cid, sizeof(cid));   p += sizeof(cid);
    memcpy(p, &lstid, sizeof(lstid)); p += sizeof(lstid);
    memcpy(p, peer, sizeof(*peer));
    evq_push(&G->q, rec, sz);
    free(rec);
}

void emit_conn_connected(uint64_t cid, const bvcq_addr* peer){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(bvcq_addr));
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_CONN_CONNECTED; h->flags = 0; h->size = sz;
    uint8_t* p = rec + sizeof(*h);
    memcpy(p, &cid, sizeof(cid)); p += sizeof(cid);
    memcpy(p, peer, sizeof(*peer));
    evq_push(&G->q, rec, sz);
    free(rec);
}

void emit_conn_closed(uint64_t cid, uint32_t app, uint32_t tcode){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t));
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_CONN_CLOSED; h->flags = 0; h->size = sz;
    uint8_t* p = rec + sizeof(*h);
    memcpy(p, &cid, sizeof(cid)); p += sizeof(cid);
    memcpy(p, &app, sizeof(app)); p += sizeof(app);
    memcpy(p, &tcode, sizeof(tcode));
    evq_push(&G->q, rec, sz);
    free(rec);
}

void emit_conn_cert_required(uint64_t cid){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t));
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_CONN_CERT_REQUIRED; h->flags = 0; h->size = sz;
    memcpy(rec + sizeof(*h), &cid, sizeof(cid));
    evq_push(&G->q, rec, sz);
    free(rec);
}

void emit_stream_opened(uint64_t cid, uint64_t sid, int bidi){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t));
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_STREAM_OPENED; h->flags = 0; h->size = sz;
    uint8_t* p = rec + sizeof(*h);
    memcpy(p, &cid, sizeof(cid)); p += sizeof(cid);
    memcpy(p, &sid, sizeof(sid)); p += sizeof(sid);
    uint8_t f = (uint8_t)(bidi ? 1 : 0);
    memcpy(p, &f, sizeof(f));
    evq_push(&G->q, rec, sz);
    free(rec);
}

void emit_stream_writable(uint64_t sid){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t));
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_STREAM_WRITABLE; h->flags = 0; h->size = sz;
    memcpy(rec + sizeof(*h), &sid, sizeof(sid));
    evq_push(&G->q, rec, sz);
    free(rec);
}

void emit_stream_read(uint64_t sid, int fin, const uint8_t* buf, uint32_t len){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + len);
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_STREAM_READ; h->flags = 0; h->size = sz;
    uint8_t* p = rec + sizeof(*h);
    memcpy(p, &sid, sizeof(sid)); p += sizeof(sid);
    uint32_t fin32 = fin ? 1u : 0u; memcpy(p, &fin32, sizeof(fin32)); p += sizeof(fin32);
    memcpy(p, &len, sizeof(len)); p += sizeof(len);
    memcpy(p, buf, len);
    evq_push(&G->q, rec, sz);
    free(rec);
}

void emit_dgram_read(uint64_t cid, const uint8_t* buf, uint32_t len){
    uint32_t sz = (uint32_t)(sizeof(bvcq_ev_hdr) + sizeof(uint64_t) + sizeof(uint32_t) + len);
    uint8_t* rec = (uint8_t*)malloc(sz); if (!rec) return;
    bvcq_ev_hdr* h = (bvcq_ev_hdr*)rec;
    h->type = BVCQ_EV_DGRAM_READ; h->flags = 0; h->size = sz;
    uint8_t* p = rec + sizeof(*h);
    memcpy(p, &cid, sizeof(cid)); p += sizeof(cid);
    memcpy(p, &len, sizeof(len)); p += sizeof(len);
    memcpy(p, buf, len);
    evq_push(&G->q, rec, sz);

    /* Diagnostics only: brief hexdump of first bytes */
    DIAGF("[dgram] emit cid=%llu len=%u",
          (unsigned long long)cid, (unsigned)len);
    const uint32_t dump_n = len < 64 ? len : 64;
    if (dump_n > 0) {
        DIAGF("[dgram] bytes[0..%u] =", (unsigned)(dump_n - 1));
        dump_bytes(buf, dump_n);
    }

    free(rec);
}

/* --------------------------------------------------------------------------
   Public drain API (uses evqueue.c)
   -------------------------------------------------------------------------- */

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_drain_events(bvcq_lib lib, void* out_buf, size_t buf_bytes, size_t* out_used){
    (void)lib;
    if (!G || !out_buf || !out_used || buf_bytes < sizeof(bvcq_ev_hdr)) return BVCQ_ERR_BADARG;

    size_t n = evq_copy_out(&G->q, out_buf, buf_bytes);
    if (n == 0) {
        *out_used = 0;
        /* No log here — would be noisy in tight polling loops. */
        return BVCQ_ERR_AGAIN;
    }

    *out_used = n;
    /* Minimal flow log: one line per successful drain */
    LOGF_MIN("[api] drain_events -> %zu bytes", n);
    return BVCQ_OK;
}