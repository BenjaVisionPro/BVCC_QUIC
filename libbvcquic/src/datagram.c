// lib/datagram.c — QUIC DATAGRAM send path

#include "bvcq_internal.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

/* best-effort peer address log (diagnostics only) */
static void diag_log_peer_addr(HQUIC h){
#ifdef QUIC_PARAM_CONN_REMOTE_ADDRESS
    QUIC_ADDR ra; uint32_t sz = sizeof(ra); memset(&ra, 0, sizeof(ra));
    if (QUIC_SUCCEEDED(G->api->GetParam(h, QUIC_PARAM_CONN_REMOTE_ADDRESS, &sz, &ra))) {
        char ip[64] = "0.0.0.0"; uint16_t port = 0;
        if (ra.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
            inet_ntop(AF_INET,  &ra.Ipv4.sin_addr, ip, sizeof(ip));
            port = ntohs(ra.Ipv4.sin_port);
        } else if (ra.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
            inet_ntop(AF_INET6, &ra.Ipv6.sin6_addr, ip, sizeof(ip));
            port = ntohs(ra.Ipv6.sin6_port);
        }
        DIAGF("[dgram] peer=%s:%u", ip, (unsigned)port);
    }
#endif
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_dgram_send(bvcq_conn cid, const void* data, size_t len){
    if (!G || !data || len == 0) return BVCQ_ERR_BADARG;
    conn_t* c = tbl_find_conn(&G->tbl, (uint64_t)cid);
    if (!c || !c->h) return BVCQ_ERR_NOTFOUND;
    if (c->closing) {
        LOGF_MIN("[api] dgram_send ignored: conn closing cid=%llu",
                 (unsigned long long)c->id);
        return BVCQ_ERR_BADARG;
    }

    /* Minimal flow log: one line per API call */
    LOGF_MIN("[api] dgram_send cid=%llu len=%zu",
             (unsigned long long)c->id, len);

#ifdef QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED
    {
        uint8_t tx = 0; uint32_t txsz = sizeof(tx);
        QUIC_STATUS st = G->api->GetParam(c->h, QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED, &txsz, &tx);
        DIAGF("[dgram] SEND_ENABLED st=%s(0x%x) tx_enabled=%u",
              quic_status_name(st), (unsigned)st, (unsigned)tx);
    }
#endif
#ifdef QUIC_PARAM_CONN_DATAGRAM_MAX_LEN
    {
        uint16_t ml = 0; uint32_t mlsz = sizeof(ml);
        QUIC_STATUS st = G->api->GetParam(c->h, QUIC_PARAM_CONN_DATAGRAM_MAX_LEN, &mlsz, &ml);
        if (QUIC_SUCCEEDED(st)) {
            DIAGF("[dgram] MAX_LEN=%u len=%zu", (unsigned)ml, len);
        } else {
            DIAGF("[dgram] GetParam(MAX_LEN) FAILED st=%s(0x%x)",
                  quic_status_name(st), (unsigned)st);
        }
    }
#endif
    diag_log_peer_addr(c->h);

    /* SAFE LIFETIME: copy payload to heap; free on terminal send-state event */
    dgsend_t* ctx = (dgsend_t*)calloc(1, sizeof(dgsend_t));
    if (!ctx) return BVCQ_ERR_NOMEM;
    ctx->len  = (uint32_t)len;
    ctx->data = (uint8_t*)malloc(len);
    if (!ctx->data) { free(ctx); return BVCQ_ERR_NOMEM; }
    memcpy(ctx->data, data, len);

    DIAGF("[dgram] DatagramSend conn=%p buf=%p len=%u flags=0x0 ctx=%p",
          (void*)c->h, (void*)ctx->data, (unsigned)ctx->len, (void*)ctx);
    dump_bytes(ctx->data, ctx->len); /* prints only in DIAG mode */

    QUIC_BUFFER qb; qb.Length = ctx->len; qb.Buffer = ctx->data;
    QUIC_STATUS st = G->api->DatagramSend(c->h, &qb, 1, QUIC_SEND_FLAG_NONE, (void*)ctx);
    if (QUIC_FAILED(st)) {
        LOGF_MIN("[api] dgram_send FAILED cid=%llu st=%s(0x%x)",
                 (unsigned long long)c->id, quic_status_name(st), (unsigned)st);
        free(ctx->data); free(ctx);
        return st_from_quic(st);
    }

    /* Track outstanding send so conn_close() can free if we shut down early. */
    link_dgsend_ctx(c, ctx);

    return BVCQ_OK;
}