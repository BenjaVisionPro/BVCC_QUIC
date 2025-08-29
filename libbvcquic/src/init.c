// lib/init.c — library lifecycle & global state

#include "bvcq_internal.h"
#include <stdio.h>
#include <string.h>

// Single definitions of module-wide globals
lib_s*      G          = NULL;  // global library state

#if BVCQ_FEATURE_KEYLOG
int g_keylog_enable = 0;
#endif

static void log_tls_provider_once(void){
#ifdef QUIC_PARAM_GLOBAL_TLS_PROVIDER
    if (!G || !G->api) return;
    uint32_t prov = 0; uint32_t sz = sizeof(prov);
    QUIC_STATUS s = G->api->GetParam(NULL, QUIC_PARAM_GLOBAL_TLS_PROVIDER, &sz, &prov);
    if (QUIC_SUCCEEDED(s)) {
        const char* name = "UNKNOWN";
        /* These enums are defined by msquic.h; guard for portability. */
        #ifdef QUIC_TLS_PROVIDER_OPENSSL
        if (prov == QUIC_TLS_PROVIDER_OPENSSL) name = "OpenSSL";
        #endif
        #ifdef QUIC_TLS_PROVIDER_SCHANNEL
        if (prov == QUIC_TLS_PROVIDER_SCHANNEL) name = "Schannel";
        #endif
        #ifdef QUIC_TLS_PROVIDER_PLATFORM
        if (prov == QUIC_TLS_PROVIDER_PLATFORM) name = "Platform";
        #endif
        LOGF_MIN("[init] TLS provider: %s (%u)", name, (unsigned)prov);
    } else {
        LOGF_MIN("[init] TLS provider query failed: 0x%x", (unsigned)s);
    }
#endif
}

BVCQ_API const char* BVCQ_CALL
bvc_quic_version(int* out_major, int* out_minor) {
    if (out_major) *out_major = BVCQ_HEADER_VERSION_MAJOR;
    if (out_minor) *out_minor = BVCQ_HEADER_VERSION_MINOR;
    /* Keep this string stable for tests and diagnostics. */
    return "bvcquic-msquic/2.0";
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_init(bvcq_lib* out_lib, int* out_wakeup_fd) {
    if (!out_lib || !out_wakeup_fd) return BVCQ_ERR_BADARG;

    if (G) {
#ifndef _WIN32
        *out_wakeup_fd = G->q.pipe_r;
        LOGF_MIN("[init] already initialized (reuse); wake_fd=%d", G->q.pipe_r);
#else
        *out_wakeup_fd = -1;
        LOGF_MIN("[init] already initialized (reuse); wake_handle=%p", (void*)G->q.wake);
#endif
        *out_lib = 1;
        return BVCQ_OK;
    }

    LOGF_MIN("[init] starting");

    G = (lib_s*)calloc(1, sizeof(lib_s));
    if (!G) return BVCQ_ERR_NOMEM;

    evq_init(&G->q);

    if (QUIC_FAILED(MsQuicOpen2(&G->api))) {
        LOGF_MIN("[init] MsQuicOpen2 failed");
        evq_free(&G->q);
        free(G); G = NULL;
        return BVCQ_ERR_SYS;
    }

    /* REQUIRED: open a Registration and keep it for all future calls */
    QUIC_REGISTRATION_CONFIG rc = { "bvcquic", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    QUIC_STATUS rs = G->api->RegistrationOpen(&rc, &G->reg);
    if (QUIC_FAILED(rs)) {
        LOGF_MIN("[init] RegistrationOpen failed: 0x%x", (unsigned)rs);
        MsQuicClose(G->api);
        evq_free(&G->q);
        free(G); G = NULL;
        return BVCQ_ERR_SYS;
    }

    /* One-time TLS provider log if supported by this MsQuic build. */
    log_tls_provider_once();

    tbl_init(&G->tbl);

#ifndef _WIN32
    *out_wakeup_fd = G->q.pipe_r;
    LOGF_MIN("[init] complete; wake_fd=%d", G->q.pipe_r);
#else
    *out_wakeup_fd = -1; /* use bvc_quic_get_wakeup_handle() on Windows */
    LOGF_MIN("[init] complete; wake_handle=%p", (void*)G->q.wake);
#endif
    *out_lib = 1;
    return BVCQ_OK;
}

BVCQ_API void BVCQ_CALL
bvc_quic_shutdown(bvcq_lib lib) {
    (void)lib;
    if (!G) return;

    LOGF_MIN("[shutdown] begin");

    /* Close streams, connections, listeners */
    size_t n_streams = 0, n_conns = 0, n_lsts = 0, n_cfgs = 0;

    for (size_t i = 0; i < G->tbl.strms_len; i++) {
        if (G->tbl.strms[i].h) {
            G->api->StreamClose(G->tbl.strms[i].h);
            G->tbl.strms[i].h = NULL;
            n_streams++;
        }
    }
    for (size_t i = 0; i < G->tbl.conns_len; i++) {
        if (G->tbl.conns[i].h) {
            G->api->ConnectionClose(G->tbl.conns[i].h);
            G->tbl.conns[i].h = NULL;
            n_conns++;
        }
    }
    for (size_t i = 0; i < G->tbl.lsts_len; i++) {
        if (G->tbl.lsts[i].h) {
            G->api->ListenerClose(G->tbl.lsts[i].h);
            G->tbl.lsts[i].h = NULL;
            n_lsts++;
        }
    }

    /* Close configurations and free ALPN buffers */
    for (size_t i = 0; i < G->tbl.cfgs_len; i++) {
        if (G->tbl.cfgs[i].h) {
            G->api->ConfigurationClose(G->tbl.cfgs[i].h);
            G->tbl.cfgs[i].h = NULL;
            n_cfgs++;
        }
        if (G->tbl.cfgs[i].alpns) {
            for (uint32_t j = 0; j < G->tbl.cfgs[i].alpn_count; j++) {
                free(G->tbl.cfgs[i].alpns[j].Buffer);
            }
            free(G->tbl.cfgs[i].alpns);
            G->tbl.cfgs[i].alpns = NULL;
            G->tbl.cfgs[i].alpn_count = 0;
        }
    }

    if (G->reg) {
        G->api->RegistrationClose(G->reg);
        G->reg = NULL;
    }

    MsQuicClose(G->api);
    evq_free(&G->q);

    free(G->tbl.conns);
    free(G->tbl.strms);
    free(G->tbl.lsts);
    free(G->tbl.cfgs);

    LOGF_MIN("[shutdown] closed: streams=%zu conns=%zu listeners=%zu cfgs=%zu", n_streams, n_conns, n_lsts, n_cfgs);

    free(G);
    G = NULL;

    LOGF_MIN("[shutdown] complete");
}