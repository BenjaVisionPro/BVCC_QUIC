// lib/platform.c — platform-specific helpers

#include "bvcq_internal.h"

BVCQ_API void* BVCQ_CALL
bvc_quic_get_wakeup_handle(bvcq_lib lib) {
#ifdef _WIN32
    (void)lib;
    if (!G) return NULL;
    // evqueue.c creates an auto-reset event in q.wake
    return (void*)G->q.wake;
#else
    (void)lib;
    // POSIX: use the wakeup pipe FD from bvc_quic_init(); no HANDLE to return
    return NULL;
#endif
}