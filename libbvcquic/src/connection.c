// lib/connection.c — Client connections & connection callbacks

#include "bvcq_internal.h"
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

/* --------------------------------------------------------------------------
   local helpers
   -------------------------------------------------------------------------- */

/* Opt-in DATAGRAM receive on a connection (MsQuic default is OFF). */
static inline void enable_datagrams_on_conn(const QUIC_API_TABLE* api, HQUIC conn){
#ifdef QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED
    if (!api || !conn) return;
    uint8_t on = 1;
    (void)api->SetParam(
        conn,
        QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
        sizeof(on),
        &on
    );
#else
    (void)api; (void)conn;
#endif
}

/* --------------------------------------------------------------------------
   MsQuic connection callback
   -------------------------------------------------------------------------- */

QUIC_STATUS QUIC_API on_connection(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event){
    (void)Context;
    uint64_t cid = conn_id_from_h(Connection);
    conn_t* c = tbl_find_conn(&G->tbl, cid); /* may be NULL during early races */

    switch (Event->Type) {

    case QUIC_CONNECTION_EVENT_CONNECTED: {
        if (c && c->closing) return QUIC_STATUS_SUCCESS; /* suppress late emits during close */

        /* Minimal flow log: one line with peer address */
        bvcq_addr peer; memset(&peer, 0, sizeof(peer));
        QUIC_ADDR ra; uint32_t sz = sizeof(ra); memset(&ra, 0, sizeof(ra));
        if (QUIC_SUCCEEDED(G->api->GetParam(Connection, QUIC_PARAM_CONN_REMOTE_ADDRESS, &sz, &ra))) {
            if (ra.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
                inet_ntop(AF_INET,  &ra.Ipv4.sin_addr, peer.ip, sizeof(peer.ip));
                peer.port = ntohs(ra.Ipv4.sin_port);
            } else if (ra.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
                inet_ntop(AF_INET6, &ra.Ipv6.sin6_addr, peer.ip, sizeof(peer.ip));
                peer.port = ntohs(ra.Ipv6.sin6_port);
            } else {
                snprintf(peer.ip, sizeof(peer.ip), "%s", "0.0.0.0");
                peer.port = 0;
            }
        }
        LOGF_MIN("[conn] CONNECTED cid=%llu peer=%s:%u",
                 (unsigned long long)cid, peer.ip, (unsigned)peer.port);

        emit_conn_connected(cid, &peer);

#ifdef QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED
        {
            uint8_t rx = 0; uint32_t rxsz = sizeof(rx);
            QUIC_STATUS st = G->api->GetParam(Connection, QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED, &rxsz, &rx);
            DIAGF("[conn] DATAGRAM rx_enabled=%u st=0x%x", (unsigned)rx, (unsigned)st);
        }
#endif
#ifdef QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED
        {
            uint8_t tx = 0; uint32_t txsz = sizeof(tx);
            QUIC_STATUS st = G->api->GetParam(Connection, QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED, &txsz, &tx);
            DIAGF("[conn] DATAGRAM tx_enabled=%u st=0x%x", (unsigned)tx, (unsigned)st);
        }
#endif
#ifdef QUIC_PARAM_CONN_DATAGRAM_MAX_LEN
        {
            uint16_t ml = 0; uint32_t mlsz = sizeof(ml);
            QUIC_STATUS st = G->api->GetParam(Connection, QUIC_PARAM_CONN_DATAGRAM_MAX_LEN, &mlsz, &ml);
            DIAGF("[conn] DATAGRAM max_len=%u st=0x%x", (unsigned)ml, (unsigned)st);
        }
#endif
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
        if (c && c->closing) return QUIC_STATUS_SUCCESS;
        if (c) c->cert_deferred = 1;
        LOGF_MIN("[conn] PEER_CERTIFICATE_RECEIVED cid=%llu (deferring to app)", (unsigned long long)cid);
        emit_conn_cert_required(cid);
        return QUIC_STATUS_PENDING; /* app will call *_cert_complete() */
    }

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        if (c && c->closing) return QUIC_STATUS_SUCCESS;
        HQUIC s = Event->PEER_STREAM_STARTED.Stream;
        int bidi = (Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) ? 0 : 1;
        G->api->SetCallbackHandler(s, (void*)on_stream, (void*)Connection);
        strm_t* st = tbl_add_strm(&G->tbl, s, cid, bidi);
        LOGF_MIN("[conn] PEER_STREAM_STARTED cid=%llu sid=%llu bidi=%d",
                 (unsigned long long)cid, (unsigned long long)st->id, bidi);
        emit_stream_opened(cid, st->id, bidi);
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        if (c && c->closing) return QUIC_STATUS_SUCCESS;
        if (Event->DATAGRAM_RECEIVED.Buffer) {
            DIAGF("[conn] DGRAM_RECEIVED cid=%llu len=%u",
                  (unsigned long long)cid,
                  (unsigned)Event->DATAGRAM_RECEIVED.Buffer->Length);
            emit_dgram_read(cid,
                            Event->DATAGRAM_RECEIVED.Buffer->Buffer,
                            Event->DATAGRAM_RECEIVED.Buffer->Length);
        }
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
        dgsend_t* ctx = (dgsend_t*)Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;

        const char* name = "UNKNOWN";
        switch (Event->DATAGRAM_SEND_STATE_CHANGED.State) {
            case QUIC_DATAGRAM_SEND_SENT:          name = "SENT"; break;
#ifdef QUIC_DATAGRAM_SEND_ACKNOWLEDGED
            case QUIC_DATAGRAM_SEND_ACKNOWLEDGED:  name = "ACKED"; break;
#endif
#ifdef QUIC_DATAGRAM_SEND_CANCELED
            case QUIC_DATAGRAM_SEND_CANCELED:      name = "CANCELED"; break;
#endif
#ifdef QUIC_DATAGRAM_SEND_LOST
            case QUIC_DATAGRAM_SEND_LOST:          name = "LOST"; break;
#endif
            default: break;
        }

        /* If closing, suppress emits but still unlink/free terminal contexts. */
        if (c && c->closing) {
            if (ctx) {
                unlink_dgsend_ctx(c, ctx);
                if (ctx->data) { free(ctx->data); ctx->data = NULL; }
                free(ctx);
            }
            return QUIC_STATUS_SUCCESS;
        }

        DIAGF("[dgram] send_state cid=%llu state=%d(%s) ctx=%p",
              (unsigned long long)cid,
              (int)Event->DATAGRAM_SEND_STATE_CHANGED.State,
              name, (void*)ctx);

        if (ctx) {
            int terminal = 0;
#ifdef QUIC_DATAGRAM_SEND_ACKNOWLEDGED
            if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_ACKNOWLEDGED) terminal = 1;
#endif
#ifdef QUIC_DATAGRAM_SEND_CANCELED
            if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_CANCELED) terminal = 1;
#endif
#ifdef QUIC_DATAGRAM_SEND_LOST
            if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_LOST) terminal = 1;
#endif
            if (terminal) {
                if (c) unlink_dgsend_ctx(c, ctx);
                if (ctx->data) { free(ctx->data); ctx->data = NULL; }
                free(ctx);
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
        /* If we already emitted CLOSED on API close, don’t emit again. */
        if (c && c->closed_emitted) {
            DIAGF("[conn] SHUTDOWN_COMPLETE (suppressed) cid=%llu", (unsigned long long)cid);
            return QUIC_STATUS_SUCCESS;
        }
        LOGF_MIN("[conn] SHUTDOWN_COMPLETE cid=%llu", (unsigned long long)cid);
        emit_conn_closed(cid, 0, 0);
        if (c) c->closed_emitted = 1;
        return QUIC_STATUS_SUCCESS;
    }

    default:
        return QUIC_STATUS_SUCCESS;
    }
}

/* --------------------------------------------------------------------------
   Public API — connect/close/cert/handshake/keylog
   -------------------------------------------------------------------------- */

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_connect(
  bvcq_lib lib, bvcq_reg reg, bvcq_cfg cfg_id,
  const char* server_name,  /* SNI; may be NULL (fall back to ip) */
  const char* ip, uint16_t port,
  bvcq_conn* out_conn)
{
    (void)lib; (void)reg;
    if (!G || !out_conn || !ip) return BVCQ_ERR_BADARG;

    cfg_t* c = tbl_find_cfg(&G->tbl, (uint64_t)cfg_id);
    if (!c) return BVCQ_ERR_NOTFOUND;
    if (!c->allow_client) return BVCQ_ERR_TLS;

    HQUIC conn = NULL;
    QUIC_STATUS st_open = G->api->ConnectionOpen(G->reg, on_connection, NULL, &conn);
    if (QUIC_FAILED(st_open)) return BVCQ_ERR_SYS;

    /* client opt-in to DATAGRAM RX */
    enable_datagrams_on_conn(G->api, conn);

    QUIC_STATUS s = G->api->ConnectionStart(
        conn,
        c->h,
        QUIC_ADDRESS_FAMILY_UNSPEC,
        server_name ? server_name : ip,
        port
    );
    if (QUIC_FAILED(s)) {
        G->api->ConnectionClose(conn);
        return BVCQ_ERR_SYS;
    }

    conn_t* ct = tbl_add_conn(&G->tbl, conn);
    LOGF_MIN("[api] connect started cid=%llu ip=%s port=%u",
             (unsigned long long)ct->id, ip ? ip : "(null)", (unsigned)port);

    *out_conn = (bvcq_conn)ct->id;
    return BVCQ_OK;
}

BVCQ_API void BVCQ_CALL
bvc_quic_conn_close(bvcq_conn c_id, uint32_t app_error_code){
    if (!G) return;
    conn_t* cc = tbl_find_conn(&G->tbl, (uint64_t)c_id);
    if (!cc || !cc->h) return;

    if (cc->closing) {
        DIAGF("[api] conn_close (idempotent) cid=%llu", (unsigned long long)cc->id);
        return;
    }
    cc->closing = 1;

    LOGF_MIN("[api] conn_close cid=%llu app_error=%u",
             (unsigned long long)cc->id, (unsigned)app_error_code);

    /* Emit CLOSED immediately so tests don’t rely on late MsQuic callback. */
	emit_conn_closed(cc->id, app_error_code, 0);
	cc->closed_emitted = 1;

    /* Free any outstanding datagram send contexts now. */
    free_all_dgsends(cc);
    
    /* Graceful shutdown signal, then release the handle immediately. */
    G->api->ConnectionShutdown(cc->h, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, app_error_code);
    G->api->ConnectionClose(cc->h);
    cc->h = NULL;
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_conn_cert_complete(bvcq_conn c, int accept, uint16_t tls_alert_code){
    (void)tls_alert_code;
    if (!G) return BVCQ_ERR_BADARG;
    conn_t* cc = tbl_find_conn(&G->tbl, (uint64_t)c);
    if (!cc || !cc->h || !cc->cert_deferred) return BVCQ_ERR_NOTFOUND;
    if (cc->closing) return BVCQ_ERR_BADARG; /* don’t complete after close */

    LOGF_MIN("[api] cert_complete cid=%llu accept=%d",
             (unsigned long long)cc->id, accept ? 1 : 0);
    QUIC_STATUS s = G->api->ConnectionCertificateValidationComplete(
        cc->h,
        accept ? TRUE : FALSE,
        (QUIC_TLS_ALERT_CODES)tls_alert_code
    );
    if (QUIC_SUCCEEDED(s)) cc->cert_deferred = 0;
    return st_from_quic(s);
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_get_conn_handshake(bvcq_conn c, bvcq_handshake_info* out){
    if (!G || !out || out->size < sizeof(*out)) return BVCQ_ERR_BADARG;
    conn_t* cc = tbl_find_conn(&G->tbl, (uint64_t)c);
    if (!cc || !cc->h) return BVCQ_ERR_NOTFOUND;

    /* Defaults */
    memset(out, 0, out->size);
    out->size        = sizeof(*out);
    out->tls_version = BVCQ_TLS_PROTOCOL_UNKNOWN;
    out->tls_group   = 0;

#if defined(QUIC_PARAM_CONN_HANDSHAKE_INFO) && defined(QUIC_HANDSHAKE_INFO)
    {
        QUIC_HANDSHAKE_INFO hi; uint32_t sz = sizeof(hi);
        memset(&hi, 0, sizeof(hi));
        QUIC_STATUS s = G->api->GetParam(
            cc->h,
            QUIC_PARAM_CONN_HANDSHAKE_INFO,
            &sz,
            &hi
        );
        if (QUIC_SUCCEEDED(s)) {
            uint16_t tls_ver = 0;
            uint32_t group   = 0;

            #ifdef QUIC_HANDSHAKE_INFO_TLS_PROTOCOL_VERSION
              tls_ver = hi.TlsProtocolVersion;
            #endif
            #ifdef QUIC_HANDSHAKE_INFO_KEX_GROUP
              group = hi.KexGroup;
            #endif
            #ifdef QUIC_HANDSHAKE_INFO_TLS_VERSION
              if (!tls_ver) tls_ver = hi.TlsVersion;
            #endif
            #ifdef QUIC_HANDSHAKE_INFO_CRYPTO_CURVE_ID
              if (!group) group = hi.CryptoCurveId;
            #endif

            if (tls_ver == 0x0304u) out->tls_version = BVCQ_TLS_PROTOCOL_1_3;
            if (group != 0) out->tls_group = group;

            LOGF_MIN("[api] handshake_info cid=%llu tls=0x%04x group=%u",
                     (unsigned long long)cc->id, (unsigned)tls_ver, (unsigned)group);
            return BVCQ_OK;
        }
    }
#endif

    /* No known param; return defaults. */
    LOGF_MIN("[api] handshake_info cid=%llu (defaults)", (unsigned long long)cc->id);
    return BVCQ_OK;
}

/* --------------------------------------------------------------------------
   Public API — connection stats (layout-agnostic)
   -------------------------------------------------------------------------- */

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_get_conn_stats(bvcq_conn c, bvcq_conn_stats* out) {
    if (!G || !out || out->size < sizeof(*out)) return BVCQ_ERR_BADARG;
    conn_t* cc = tbl_find_conn(&G->tbl, (uint64_t)c);
    if (!cc || !cc->h) return BVCQ_ERR_NOTFOUND;

    memset(out, 0, out->size);
    out->size = sizeof(*out);

#ifdef QUIC_PARAM_CONN_STATISTICS_V2
    uint8_t buf[sizeof(QUIC_STATISTICS_V2)];
    uint32_t sz = (uint32_t)sizeof(buf);
    (void)G->api->GetParam(cc->h, QUIC_PARAM_CONN_STATISTICS_V2, &sz, buf);
#elif defined(QUIC_PARAM_CONN_STATISTICS)
    uint8_t buf[512];
    uint32_t sz = (uint32_t)sizeof(buf);
    (void)G->api->GetParam(cc->h, QUIC_PARAM_CONN_STATISTICS, &sz, buf);
#endif

    /* Leave fields zero if we cannot map them portably. */
    LOGF_MIN("[api] get_conn_stats cid=%llu", (unsigned long long)cc->id);
    return BVCQ_OK;
}