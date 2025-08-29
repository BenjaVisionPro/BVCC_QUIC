// lib/listener.c — Server listener: open/start/stop/get_port

#include "bvcq_internal.h"
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

/* ---- forward decls provided by connection.c ---- */
extern QUIC_STATUS QUIC_API on_connection(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event);

/* ---- tiny helper: enable DATAGRAM RX on a connection ---- */
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

/* ---- listener callback ---- */
static QUIC_STATUS QUIC_API on_listener(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event){
    (void)Context;

    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        HQUIC conn = Event->NEW_CONNECTION.Connection;
        if (!G || !G->api) return QUIC_STATUS_INTERNAL_ERROR;

        /* hand off connection callback */
        G->api->SetCallbackHandler(conn, (void*)on_connection, NULL);

        /* find our listener id */
        uint64_t lstid = 0;
        for (size_t i = 0; i < G->tbl.lsts_len; i++) {
            if (G->tbl.lsts[i].h == Listener) { lstid = G->tbl.lsts[i].id; break; }
        }
        if (!lstid) return QUIC_STATUS_INTERNAL_ERROR;

        /* get the cfg from the listener entry */
        lst_t* l = tbl_find_lst(&G->tbl, lstid);
        if (!l) return QUIC_STATUS_INVALID_PARAMETER;
        cfg_t* c = tbl_find_cfg(&G->tbl, l->cfg_id);
        if (!c) return QUIC_STATUS_INVALID_PARAMETER;

        /* attach configuration to the incoming connection */
        QUIC_STATUS s = G->api->ConnectionSetConfiguration(conn, c->h);
        if (QUIC_FAILED(s)) return s;

        /* enable datagrams on server-side connections */
        enable_datagrams_on_conn(G->api, conn);

        /* track the connection & emit ACCEPTED */
        conn_t* cc = tbl_add_conn(&G->tbl, conn);

        bvcq_addr peer; memset(&peer, 0, sizeof(peer));
        if (Event->NEW_CONNECTION.Info && Event->NEW_CONNECTION.Info->RemoteAddress) {
            const QUIC_ADDR* ra = Event->NEW_CONNECTION.Info->RemoteAddress;
            if (ra->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
                inet_ntop(AF_INET,  &ra->Ipv4.sin_addr, peer.ip, sizeof(peer.ip));
                peer.port = ntohs(ra->Ipv4.sin_port);
            } else if (ra->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
                inet_ntop(AF_INET6, &ra->Ipv6.sin6_addr, peer.ip, sizeof(peer.ip));
                peer.port = ntohs(ra->Ipv6.sin6_port);
            } else {
                snprintf(peer.ip, sizeof(peer.ip), "%s", "0.0.0.0");
                peer.port = 0;
            }
        }

        emit_conn_accepted(cc->id, lstid, &peer);
        return QUIC_STATUS_SUCCESS;
    }
    default:
        return QUIC_STATUS_SUCCESS;
    }
}

/* ---- public API ---- */

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_listener_start(
  bvcq_lib lib, bvcq_reg reg, bvcq_cfg cfg_id,
  const char* bind_ip, uint16_t bind_port,
  bvcq_listener* out_listener)
{
    (void)lib; (void)reg;
    if (!G || !out_listener || !bind_ip) return BVCQ_ERR_BADARG;

    cfg_t* c = tbl_find_cfg(&G->tbl, (uint64_t)cfg_id);
    if (!c) return BVCQ_ERR_NOTFOUND;

    HQUIC lst = NULL;
    QUIC_STATUS s_open = G->api->ListenerOpen(G->reg, on_listener, NULL, &lst);
    if (QUIC_FAILED(s_open)) {
        LOGF_MIN("[listener] ListenerOpen failed: %s (0x%x)", quic_status_name(s_open), (unsigned)s_open);
        return BVCQ_ERR_SYS;
    }

    QUIC_ADDR addr; memset(&addr, 0, sizeof(addr));
    unsigned a=0, b=0, c4=0, d=0;
    if (sscanf(bind_ip, "%u.%u.%u.%u", &a, &b, &c4, &d) == 4) {
        addr.Ip.sa_family        = QUIC_ADDRESS_FAMILY_INET;
        addr.Ipv4.sin_family     = QUIC_ADDRESS_FAMILY_INET;
        addr.Ipv4.sin_port       = htons(bind_port);
        addr.Ipv4.sin_addr.s_addr = htonl((a<<24)|(b<<16)|(c4<<8)|d);
    } else {
        /* Let the OS resolve/bind (supports IPv6/ANY) */
        addr.Ip.sa_family = QUIC_ADDRESS_FAMILY_UNSPEC;
        addr.Ipv4.sin_port = htons(bind_port);
    }

    LOGF_MIN("[listener] starting ip=%s port=%u (server=%d alpn_count=%u)",
             bind_ip, (unsigned)bind_port, (int)c->allow_server, (unsigned)c->alpn_count);

    QUIC_STATUS s = G->api->ListenerStart(lst, c->alpns, c->alpn_count, &addr);
    if (QUIC_FAILED(s)) {
        LOGF_MIN("[listener] ListenerStart failed: %s (0x%x)", quic_status_name(s), (unsigned)s);
        G->api->ListenerClose(lst);
        return BVCQ_ERR_SYS;
    }

    bvcq_addr baddr; memset(&baddr, 0, sizeof(baddr));
    snprintf(baddr.ip, sizeof(baddr.ip), "%s", bind_ip);
    baddr.port = bind_port;

    lst_t* l = tbl_add_lst(&G->tbl, lst, &baddr, (uint64_t)cfg_id);
    *out_listener = (bvcq_listener)l->id;

    LOGF_MIN("[listener] started on %s:%u (id=%llu)",
             bind_ip, (unsigned)bind_port, (unsigned long long)l->id);

    return BVCQ_OK;
}

BVCQ_API void BVCQ_CALL
bvc_quic_listener_stop(bvcq_listener lst_id){
    if (!G) return;
    lst_t* l = tbl_find_lst(&G->tbl, (uint64_t)lst_id);
    if (l && l->h) {
        G->api->ListenerStop(l->h);
        G->api->ListenerClose(l->h);
        l->h = NULL;
    }
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_listener_get_port(bvcq_listener lst_id, uint16_t* out_port){
    if (!G || !out_port) return BVCQ_ERR_BADARG;
    lst_t* l = tbl_find_lst(&G->tbl, (uint64_t)lst_id);
    if (!l || !l->h) return BVCQ_ERR_NOTFOUND;

#ifdef QUIC_PARAM_LISTENER_LOCAL_ADDRESS
    QUIC_ADDR addr; uint32_t sz = sizeof(addr); memset(&addr, 0, sizeof(addr));
    QUIC_STATUS s = G->api->GetParam(l->h, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &sz, &addr);
    if (QUIC_FAILED(s)) return BVCQ_ERR_SYS;

    switch (addr.Ip.sa_family) {
        case QUIC_ADDRESS_FAMILY_INET:
            *out_port = ntohs(addr.Ipv4.sin_port);
            return BVCQ_OK;
        case QUIC_ADDRESS_FAMILY_INET6:
            *out_port = ntohs(addr.Ipv6.sin6_port);
            return BVCQ_OK;
        default:
            return BVCQ_ERR_SYS;
    }
#else
    (void)lst_id;
    return BVCQ_ERR_UNSUPPORTED;
#endif
}