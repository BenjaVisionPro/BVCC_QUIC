// lib/config.c — Configuration (ALPN + credentials + verify policy)
//
// Notes:
//  - Zero settings are passed to MsQuic::ConfigurationOpen to avoid any
//    header/runtime skew. We keep the "settings" struct in the public API
//    for forward-compat but ignore it today.
//  - We *own* the ALPN byte buffers for the lifetime of the configuration.
//  - Client credentials default to NONE if omitted (keeps client role usable).
//  - Server credentials are optional; if omitted or NONE, server role disabled.

#include "bvcq_internal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---------- local helpers ---------- */

static int alpn_to_buffers(const char* const* alpn, int alpn_count, QUIC_BUFFER** out_bufs) {
    *out_bufs = NULL;
    if (!alpn || alpn_count <= 0) return 0;

    QUIC_BUFFER* arr = (QUIC_BUFFER*)calloc((size_t)alpn_count, sizeof(QUIC_BUFFER));
    if (!arr) return 0;

    for (int i = 0; i < alpn_count; i++) {
        if (!alpn[i]) { free(arr); return 0; }
        size_t L = strlen(alpn[i]);
        if (L == 0) { free(arr); return 0; }

        uint8_t* p = (uint8_t*)malloc(L);
        if (!p) {
            for (int j = 0; j < i; j++) free(arr[j].Buffer);
            free(arr);
            return 0;
        }
        memcpy(p, alpn[i], L); /* ALPN is raw bytes (no NUL) */
        arr[i].Buffer = p;
        arr[i].Length = (uint32_t)L;
    }

    *out_bufs = arr;
    return 1;
}

static QUIC_STATUS load_creds(HQUIC cfg, int is_client,
                              const bvcq_credentials* creds,
                              bvcq_verify_mode verify)
{
    QUIC_CREDENTIAL_CONFIG c; memset(&c, 0, sizeof(c));
    LOGF_MIN("config: load_creds role=%s", is_client ? "client" : "server");

    /* NONE: allowed for client; invalid for server */
    if (!creds || creds->kind == BVCQ_CRED_NONE) {
        if (!is_client) {
            LOGF_MIN("config: server credentials=NONE is invalid");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        c.Type = QUIC_CREDENTIAL_TYPE_NONE;
        c.Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;

        switch (verify) {
            case BVCQ_VERIFY_INSECURE_NO_VERIFY:
                c.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
                break;
            case BVCQ_VERIFY_DEFER:
                c.Flags |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
                break;
            case BVCQ_VERIFY_STRICT:
            default:
                break;
        }

#if BVCQ_FEATURE_KEYLOG
  #ifdef QUIC_CREDENTIAL_FLAG_ENABLE_TLS_KEYLOGGING
        if (g_keylog_enable) {
            c.Flags |= QUIC_CREDENTIAL_FLAG_ENABLE_TLS_KEYLOGGING;
            LOGF_MIN("config: TLS key logging enabled via credential flag");
        }
  #endif
#endif

        QUIC_STATUS s = G->api->ConfigurationLoadCredential(cfg, &c);
        LOGF_MIN("config: load_creds(client=1, kind=NONE) -> %s(0x%x)", quic_status_name(s), (unsigned)s);
        return s;
    }

    /* PEM files */
    if (creds->kind == BVCQ_CRED_PEM_FILES) {
        const char* cert = creds->cert_file;
        const char* key  = creds->key_file;

        LOGF_MIN("config: loading PEM files (role=%s)", is_client ? "client" : "server");
        DIAGF("config: PEM paths cert='%s' key='%s'", cert ? cert : "(null)", key ? key : "(null)");

        if (!cert || !key) {
            LOGF_MIN("config: ERROR: cert or key path is NULL");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        FILE* fc = fopen(cert, "rb");
        if (!fc) { LOGF_MIN("config: ERROR: fopen(cert) failed for '%s'", cert); return QUIC_STATUS_INVALID_PARAMETER; }
        FILE* fk = fopen(key,  "rb");
        if (!fk) { fclose(fc); LOGF_MIN("config: ERROR: fopen(key) failed for '%s'", key); return QUIC_STATUS_INVALID_PARAMETER; }

        char line[128];
        line[0] = 0; if (fgets(line, (int)sizeof(line), fc)) { size_t L=strlen(line); while(L && (line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0; DIAGF("config: cert head: %s", line); }
        line[0] = 0; if (fgets(line, (int)sizeof(line), fk)) { size_t L=strlen(line); while(L && (line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0; DIAGF("config: key  head: %s", line); }
        fclose(fc); fclose(fk);

        QUIC_CERTIFICATE_FILE cert_files; memset(&cert_files, 0, sizeof(cert_files));
        cert_files.PrivateKeyFile  = key;
        cert_files.CertificateFile = cert;

        c.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        c.CertificateFile = &cert_files;

        if (is_client) {
            c.Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;
            switch (verify) {
                case BVCQ_VERIFY_INSECURE_NO_VERIFY:
                    c.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
                    break;
                case BVCQ_VERIFY_DEFER:
                    c.Flags |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
                    break;
                case BVCQ_VERIFY_STRICT:
                default:
                    break;
            }
        } else {
            if (verify != BVCQ_VERIFY_STRICT) {
                DIAGF("config: note: server verify=%d ignored (server doesn’t validate server cert)", (int)verify);
            }
        }

#if BVCQ_FEATURE_KEYLOG
  #ifdef QUIC_CREDENTIAL_FLAG_ENABLE_TLS_KEYLOGGING
        if (g_keylog_enable) {
            c.Flags |= QUIC_CREDENTIAL_FLAG_ENABLE_TLS_KEYLOGGING;
            LOGF_MIN("config: TLS key logging enabled via credential flag");
        }
  #endif
#endif

        QUIC_STATUS s = G->api->ConfigurationLoadCredential(cfg, &c);
        LOGF_MIN("config: load_creds(role=%s, kind=PEM_FILES) -> %s(0x%x)",
                 is_client ? "client" : "server", quic_status_name(s), (unsigned)s);
        return s;
    }

    LOGF_MIN("config: ERROR: unsupported credential kind=%d", (int)creds->kind);
    return QUIC_STATUS_INVALID_PARAMETER;
}

/* ---------- public: open config ---------- */

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_open_config(
  bvcq_lib lib,
  bvcq_reg reg,
  const char* const* alpn, int alpn_count,
  const bvcq_settings* settings, /* currently ignored (reserved) */
  const bvcq_credentials* client_creds,
  const bvcq_credentials* server_creds,
  bvcq_verify_mode verify_client,
  bvcq_verify_mode verify_server,
  bvcq_cfg* out_cfg)
{
    (void)lib; (void)reg; (void)settings;

    if (!G || !out_cfg || !alpn || alpn_count <= 0) {
        LOGF_MIN("config: open_config bad args (G=%p out_cfg=%p alpn=%p count=%d)", (void*)G, (void*)out_cfg, (void*)alpn, alpn_count);
        return BVCQ_ERR_BADARG;
    }
    if (!G->reg) {
        LOGF_MIN("config: MsQuic registration handle is NULL (init/RegistrationOpen required)");
        return BVCQ_ERR_SYS;
    }

    for (int i = 0; i < alpn_count; i++) {
        if (!alpn[i]) { LOGF_MIN("config: ALPN[%d] is NULL (invalid)", i); return BVCQ_ERR_BADARG; }
        size_t L = strlen(alpn[i]);
        if (L == 0 || L > 255) { LOGF_MIN("config: invalid ALPN[%d] length=%zu (must be 1..255)", i, L); return BVCQ_ERR_BADARG; }
        DIAGF("config: ALPN[%d] len=%zu value='%.*s'", i, L, (int)L, alpn[i]);
    }

    QUIC_BUFFER* alpns = NULL;
    if (!alpn_to_buffers(alpn, alpn_count, &alpns)) {
        LOGF_MIN("config: failed to allocate ALPN buffers");
        return BVCQ_ERR_NOMEM;
    }

    LOGF_MIN("config: ConfigurationOpen reg=%p alpn_count=%d settings=NONE", (void*)G->reg, alpn_count);

    HQUIC cfg = NULL;
    QUIC_STATUS s = G->api->ConfigurationOpen(
        G->reg,
        alpns, (uint32_t)alpn_count,
        NULL, 0,
        NULL, &cfg);

    if (QUIC_FAILED(s)) {
        LOGF_MIN("config: MsQuic ConfigurationOpen failed: %s(0x%x)", quic_status_name(s), (unsigned)s);
        for (int j = 0; j < alpn_count; j++) free(alpns[j].Buffer);
        free(alpns);
        return BVCQ_ERR_SYS;
    }

    /* Roles:
       - Client: default to NONE if omitted (keeps client role usable).
       - Server: optional; enable only if provided and not NONE.
    */
    QUIC_STATUS s_client = QUIC_STATUS_NOT_SUPPORTED;
    QUIC_STATUS s_server = QUIC_STATUS_NOT_SUPPORTED;

    /* Default client role to NONE when null */
    bvcq_credentials none_client = {0};
    if (!client_creds) {
        none_client.kind = BVCQ_CRED_NONE;
        client_creds = &none_client;
    }

    s_client = load_creds(cfg, /*is_client*/1, client_creds, verify_client);
    if (QUIC_FAILED(s_client)) {
        LOGF_MIN("config: client credential load failed: %s(0x%x)", quic_status_name(s_client), (unsigned)s_client);
        G->api->ConfigurationClose(cfg);
        for (int j = 0; j < alpn_count; j++) free(alpns[j].Buffer);
        free(alpns);
        return BVCQ_ERR_TLS;
    }

    if (server_creds && server_creds->kind != BVCQ_CRED_NONE) {
        s_server = load_creds(cfg, /*is_client*/0, server_creds, verify_server);
        if (QUIC_FAILED(s_server)) {
            LOGF_MIN("config: server credential load failed; server role disabled: %s(0x%x)",
                     quic_status_name(s_server), (unsigned)s_server);
        }
    }

    cfg_t* c = tbl_add_cfg(&G->tbl, cfg);
    c->alpn_count    = (uint32_t)alpn_count;
    c->alpns         = alpns;
    c->allow_client  = QUIC_SUCCEEDED(s_client) ? 1 : 0;
    c->allow_server  = QUIC_SUCCEEDED(s_server) ? 1 : 0;
    c->verify_client = verify_client;
    c->verify_server = verify_server;

    *out_cfg = (bvcq_cfg)c->id;
    LOGF_MIN("config: ConfigurationOpen OK (cfg_id=%llu) roles: client=%d server=%d",
             (unsigned long long)c->id, c->allow_client, c->allow_server);
    return BVCQ_OK;
}