// lib/keylog.c — TLS keylog enable/disable (build-guarded)

#include "bvcq_internal.h"
#include <string.h>

#if defined(BVCQ_ENABLE_KEYLOG)

static bvc_quic_status set_global_keylog_path(const char* path) {
    /* Try well-known MsQuic global parameters if present; otherwise UNSUPPORTED. */

    /* Variant A: explicit string path (if available) */
#if defined(QUIC_PARAM_GLOBAL_TLS_KEYLOG_FILE)
    if (!G || !G->api) return BVCQ_ERR_SYS;
    const char* p = (path && *p) ? path : getenv("SSLKEYLOGFILE");
    if (!p || !*p) return BVCQ_ERR_BADARG;
    uint32_t sz = (uint32_t)(strlen(p) + 1);
    QUIC_STATUS s = G->api->SetParam(NULL, QUIC_PARAM_GLOBAL_TLS_KEYLOG_FILE, sz, (void*)p);
    return QUIC_SUCCEEDED(s) ? BVCQ_OK : BVCQ_ERR_SYS;
#endif

    /* Variant B: boolean on/off; path picked up from SSLKEYLOGFILE env */
#if defined(QUIC_PARAM_GLOBAL_TLS_KEYLOG)
    if (!G || !G->api) return BVCQ_ERR_SYS;
    const char* p = (path && *p) ? path : getenv("SSLKEYLOGFILE");
    if (!p || !*p) return BVCQ_ERR_BADARG;
    /* export env so provider can find it */
#if defined(_WIN32)
    _putenv_s("SSLKEYLOGFILE", p);
#else
    setenv("SSLKEYLOGFILE", p, 1);
#endif
    uint8_t on = 1;
    QUIC_STATUS s = G->api->SetParam(NULL, QUIC_PARAM_GLOBAL_TLS_KEYLOG, sizeof(on), &on);
    return QUIC_SUCCEEDED(s) ? BVCQ_OK : BVCQ_ERR_SYS;
#endif

    (void)path;
    return BVCQ_ERR_UNSUPPORTED;
}

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_conn_enable_keylog(bvcq_conn c, int enable, const char* path) {
    (void)c;
    if (!G) return BVCQ_ERR_BADARG;

    if (enable) {
        bvc_quic_status st = set_global_keylog_path(path);
        if (st != BVCQ_OK) return st;
        LOGF_MIN("[keylog] ENABLED file=%s",
                 (path && *path) ? path :
                 (getenv("SSLKEYLOGFILE") ? getenv("SSLKEYLOGFILE") : "(env not set)"));
        return BVCQ_OK;
    } else {
#if defined(QUIC_PARAM_GLOBAL_TLS_KEYLOG)
        uint8_t off = 0;
        QUIC_STATUS s = G->api->SetParam(NULL, QUIC_PARAM_GLOBAL_TLS_KEYLOG, sizeof(off), &off);
        return QUIC_SUCCEEDED(s) ? BVCQ_OK : BVCQ_ERR_SYS;
#else
        return BVCQ_OK; /* no portable disable */
#endif
    }
}

#else /* !BVCQ_ENABLE_KEYLOG */

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_conn_enable_keylog(bvcq_conn c, int enable, const char* path) {
    (void)c; (void)enable; (void)path;
    return BVCQ_ERR_UNSUPPORTED;
}

#endif /* BVCQ_ENABLE_KEYLOG */