// lib/registration.c — Registration facade
//
// We maintain a single MsQuic Registration opened during bvc_quic_init().
// This file exposes the public bvc_quic_open_registration() entry point
// which currently just returns a trivial opaque handle for API symmetry.

#include "bvcq_internal.h"

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_open_registration(bvcq_lib lib, const char* app_name, bvcq_reg* out_reg) {
    (void)lib; /* single global registration model */

    if (!G || !out_reg) return BVCQ_ERR_BADARG;

    if (!G->reg) {
        /* init was supposed to create the registration; treat as system error */
        LOGF_MIN("[reg] open failed: global MsQuic Registration handle is NULL (init required)");
        return BVCQ_ERR_SYS;
    }

    /* Single global registration model: return a trivial opaque handle. */
    *out_reg = (bvcq_reg)1;

    LOGF_MIN("[reg] open ok (app=%s)", app_name ? app_name : "(null)");
    return BVCQ_OK;
}