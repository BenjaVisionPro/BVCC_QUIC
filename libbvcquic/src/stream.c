// lib/stream.c — Stream API & callback glue

#include "bvcq_internal.h"
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

/* --------------------------------------------------------------------------
   MsQuic stream callback
   -------------------------------------------------------------------------- */

QUIC_STATUS QUIC_API on_stream(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event){
    uint64_t sid = strm_id_from_h(Stream);  /* helper comes from bvcq_internal.h */

    /* Try to find parent connection (we set Context to the connection handle). */
    conn_t* parent = NULL;
    if (Context) {
        uint64_t pcid = conn_id_from_h((HQUIC)Context);
        if (pcid) parent = tbl_find_conn(&G->tbl, pcid);
    }

    switch (Event->Type) {

    case QUIC_STREAM_EVENT_RECEIVE: {
        /* Always ack receives so MsQuic can free buffers. */
        G->api->StreamReceiveComplete(Stream, Event->RECEIVE.TotalBufferLength);

        /* If parent conn is closing, suppress user-facing emits. */
        if (parent && parent->closing) return QUIC_STATUS_SUCCESS;

        strm_t* s = tbl_find_strm(&G->tbl, sid);
        if (!s || !s->h) return QUIC_STATUS_SUCCESS;

        LOGF_MIN("[stream] RECEIVE sid=%llu buffers=%u flags=0x%x",
                 (unsigned long long)sid,
                 (unsigned)Event->RECEIVE.BufferCount,
                 (unsigned)Event->RECEIVE.Flags);

        if (s->read_enabled) {
            int fin = (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) ? 1 : 0;
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
                const QUIC_BUFFER* b = &Event->RECEIVE.Buffers[i];
                emit_stream_read(sid,
                                 fin && (i + 1 == Event->RECEIVE.BufferCount),
                                 b->Buffer, b->Length);
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        if (parent && parent->closing) return QUIC_STATUS_SUCCESS;

        LOGF_MIN("[stream] SEND_COMPLETE sid=%llu",
                 (unsigned long long)sid);
        /* App sees writability via our EV_STREAM_WRITABLE */
        emit_stream_writable(sid);
        return QUIC_STATUS_SUCCESS;
    }

    /* No-op cases for our FFI surface */
    case QUIC_STREAM_EVENT_START_COMPLETE:
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
    default:
        return QUIC_STATUS_SUCCESS;
    }
}

/* --------------------------------------------------------------------------
   Public API
   -------------------------------------------------------------------------- */

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_stream_open(bvcq_conn cid, int bidi, bvcq_stream* out_sid){
    if (!G || !out_sid) return BVCQ_ERR_BADARG;
    conn_t* c = tbl_find_conn(&G->tbl, (uint64_t)cid);
    if (!c || !c->h) return BVCQ_ERR_NOTFOUND;
    if (c->closing) return BVCQ_ERR_BADARG;

    HQUIC s = NULL;
    QUIC_STATUS st = G->api->StreamOpen(
        c->h,
        bidi ? QUIC_STREAM_OPEN_FLAG_NONE : QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
        on_stream,
        (void*)c->h,   /* Context = parent connection handle */
        &s
    );
    if (QUIC_FAILED(st)) return BVCQ_ERR_SYS;

    strm_t* ss = tbl_add_strm(&G->tbl, s, c->id, bidi ? 1 : 0);

    QUIC_STATUS st_start = G->api->StreamStart(s, QUIC_STREAM_START_FLAG_IMMEDIATE);
    if (QUIC_FAILED(st_start)) {
        G->api->StreamClose(s);
        return BVCQ_ERR_SYS;
    }

    emit_stream_opened(c->id, ss->id, ss->bidi);
    emit_stream_writable(ss->id); /* initial writable edge */
    *out_sid = (bvcq_stream)ss->id;

    LOGF_MIN("[stream] OPEN cid=%llu sid=%llu bidi=%d",
             (unsigned long long)c->id,
             (unsigned long long)ss->id,
             ss->bidi);

    return BVCQ_OK;
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_stream_send(bvcq_stream sid, const void* data, size_t len, int fin, uint32_t flags){
    (void)flags;
    if (!G || !data || len == 0) return BVCQ_ERR_BADARG;
    strm_t* s = tbl_find_strm(&G->tbl, (uint64_t)sid);
    if (!s || !s->h) return BVCQ_ERR_NOTFOUND;

    /* If parent conn is closing, reject sends. */
    conn_t* c = tbl_find_conn(&G->tbl, s->conn_id);
    if (c && c->closing) return BVCQ_ERR_BADARG;

    LOGF_MIN("[stream] SEND sid=%llu len=%zu fin=%d",
             (unsigned long long)sid, len, fin ? 1 : 0);

    QUIC_BUFFER qb; qb.Length = (uint32_t)len; qb.Buffer = (uint8_t*)data;
    QUIC_STATUS st = G->api->StreamSend(
        s->h,
        &qb, 1,
        fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE,
        NULL
    );
    return st_from_quic(st);
}

BVCQ_API void BVCQ_CALL
bvc_quic_stream_shutdown(bvcq_stream sid){
    if (!G) return;
    strm_t* s = tbl_find_strm(&G->tbl, (uint64_t)sid);
    if (s && s->h) {
        LOGF_MIN("[stream] SHUTDOWN sid=%llu", (unsigned long long)s->id);
        G->api->StreamShutdown(s->h, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        G->api->StreamClose(s->h);
        s->h = NULL;
    }
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_stream_set_read_enabled(bvcq_stream sid, int enabled){
    if (!G) return BVCQ_ERR_BADARG;
    strm_t* s = tbl_find_strm(&G->tbl, (uint64_t)sid);
    if (!s || !s->h) return BVCQ_ERR_NOTFOUND;

    /* If parent conn is closing, don’t toggle. */
    conn_t* c = tbl_find_conn(&G->tbl, s->conn_id);
    if (c && c->closing) return BVCQ_ERR_BADARG;

    s->read_enabled = enabled ? 1 : 0;
    LOGF_MIN("[stream] READ_ENABLE sid=%llu -> %d",
             (unsigned long long)s->id, s->read_enabled);

    QUIC_STATUS st = G->api->StreamReceiveSetEnabled(s->h, enabled ? TRUE : FALSE);
    return st_from_quic(st);
}