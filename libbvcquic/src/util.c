#include "bvcq_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/* --------- Status mapping (kept as-is) ----------------------------------- */
bvc_quic_status st_from_quic(QUIC_STATUS s){
    return QUIC_SUCCEEDED(s) ? BVCQ_OK : BVCQ_ERR_SYS;
}

const char* quic_status_name(QUIC_STATUS s) {
    switch ((uint32_t)s) {
        case QUIC_STATUS_SUCCESS:           return "SUCCESS";
        case QUIC_STATUS_PENDING:           return "PENDING";
        case QUIC_STATUS_CONTINUE:          return "CONTINUE";
        case QUIC_STATUS_OUT_OF_MEMORY:     return "OOM";
        case QUIC_STATUS_INVALID_PARAMETER: return "INVALID_PARAM";
        case QUIC_STATUS_INVALID_STATE:     return "INVALID_STATE";
        case QUIC_STATUS_NOT_SUPPORTED:     return "NOT_SUPPORTED";
        case QUIC_STATUS_NOT_FOUND:         return "NOT_FOUND";
        case QUIC_STATUS_BUFFER_TOO_SMALL:  return "BUFFER_TOO_SMALL";
        case QUIC_STATUS_HANDSHAKE_FAILURE: return "HANDSHAKE_FAILURE";
        case QUIC_STATUS_ABORTED:           return "ABORTED";
        case QUIC_STATUS_ADDRESS_IN_USE:    return "ADDR_IN_USE";
        default:                            return "UNKNOWN";
    }
}

/* --------- Hex dump (shared tiny helper) --------------------------------- */
void dump_bytes(const void* p, size_t n) {
    if (bvcq_log_level() < 2) return; /* only dump in DIAG mode */
    const unsigned char* b = (const unsigned char*)p;
    char line[512]; size_t pos = 0;
    pos += snprintf(line+pos, sizeof(line)-pos, "    [");
    for (size_t i = 0; i < n && pos < sizeof(line)-4; ++i) {
        pos += snprintf(line+pos, sizeof(line)-pos, "%02X%s",
                        b[i], (i + 1 == n) ? "" : " ");
    }
    snprintf(line+pos, sizeof(line)-pos, "]");
    bvcq_logf_internal(2, "%s", line);
}

/* --------- Unified logging gate ------------------------------------------ */
/* Level cache:
     -2 = uninitialized
      0 = OFF
      1 = MIN
      2 = DIAG
*/
static int g_log_level_cached = -2;

static int parse_level(const char* s){
    if (!s || !*s) return 0; /* default OFF */
    if (!strcmp(s, "0") || strcasecmp(s, "off") == 0)   return 0;
    if (!strcmp(s, "1") || strcasecmp(s, "min") == 0
                         || strcasecmp(s, "info") == 0)  return 1;
    if (!strcmp(s, "2") || strcasecmp(s, "diag") == 0
                         || strcasecmp(s, "debug") == 0) return 2;
    /* numbers >2 clamp to 2 */
    return 2;
}

int bvcq_log_level(void){
    if (g_log_level_cached == -2) {
        const char* env = getenv("BVCQ_LOG");   /* "off|min|diag" or "0|1|2" */
        g_log_level_cached = parse_level(env);
    }
    return g_log_level_cached;
}

void bvcq_logf_internal(int level, const char* fmt, ...){
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    /* default to stderr */
    const char* tag = (level >= 2) ? "diag" : "min";
    fprintf(stderr, "[bvcq/%s] %s\n", tag, buf);
}