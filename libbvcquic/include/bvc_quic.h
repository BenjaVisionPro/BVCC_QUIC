// bvc_quic.h — BVCC QUIC API v2.0 (clean slate)
#ifndef BVC_QUIC_H
#define BVC_QUIC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Export / Calling convention ===== */
#if defined(_WIN32) && !defined(BVCQ_STATIC)
  #if defined(BVCQ_BUILD)
    #define BVCQ_API __declspec(dllexport)
  #else
    #define BVCQ_API __declspec(dllimport)
  #endif
#else
  #define BVCQ_API __attribute__((visibility("default")))
#endif
#define BVCQ_CALL /* empty; reserve if stdcall ever needed */

/* ===== Version ===== */
#define BVCQ_HEADER_VERSION_MAJOR 2
#define BVCQ_HEADER_VERSION_MINOR 0

/* ===== Opaque handles ===== */
typedef uint64_t bvcq_lib;
typedef uint64_t bvcq_reg;
typedef uint64_t bvcq_cfg;
typedef uint64_t bvcq_listener;
typedef uint64_t bvcq_conn;
typedef uint64_t bvcq_stream;

/* ===== Status ===== */
typedef enum {
  BVCQ_OK = 0,
  BVCQ_ERR_SYS = -1,
  BVCQ_ERR_NOMEM = -2,
  BVCQ_ERR_BADARG = -3,
  BVCQ_ERR_NOTFOUND = -4,
  BVCQ_ERR_UNSUPPORTED = -5,
  BVCQ_ERR_TLS = -6,
  BVCQ_ERR_AGAIN = -7
} bvc_quic_status;

/* ===== Common structs ===== */
typedef struct {
  char     ip[64];
  uint16_t port;
} bvcq_addr;

typedef enum {
  BVCQ_TLS_PROTOCOL_UNKNOWN = 0,
  BVCQ_TLS_PROTOCOL_1_3     = 0x3000
} bvcq_tls_protocol;

/* Minimal handshake surface (extendable via .size) */
typedef struct {
  size_t            size;        /* set by caller */
  bvcq_tls_protocol tls_version; /* negotiated TLS version */
  uint32_t          tls_group;   /* IANA group (e.g., 29=X25519) */
} bvcq_handshake_info;

typedef struct {
  size_t   size;           /* set by caller */
  double   rtt_ms_ewma;
  uint64_t cwnd_bytes;
  uint64_t bytes_sent;
  uint64_t bytes_recv;
} bvcq_conn_stats;

/* ===== Settings & Credentials ===== */
typedef enum {
  BVCQ_CC_CUBIC = 0,
  BVCQ_CC_BBR   = 1
} bvcq_cc;

/* NOTE: Settings are currently accepted but ignored (reserved for future use). */
typedef struct {
  size_t    size;                   /* set by caller */
  /* timeouts/keepalive */
  uint64_t  idle_timeout_ms;        /* 0=library default */
  uint64_t  keepalive_interval_ms;  /* 0=disabled */
  /* transport */
  uint32_t  max_udp_payload;        /* 0=default; else <= path MTU */
  uint16_t  max_streams_bidi;       /* 0=default */
  uint16_t  max_streams_uni;        /* 0=default */
  uint8_t   enable_datagrams;       /* 0/1 */
  bvcq_cc   cc;                     /* congestion control */
} bvcq_settings;

/* NOTE: key_pass is declared but currently ignored for PEM files. */
typedef enum {
  BVCQ_CRED_NONE = 0,          /* no certificate (client); self-signed server */
  BVCQ_CRED_PEM_FILES = 1      /* cert_file + key_file (PEM) */
} bvcq_cred_kind;

typedef struct {
  bvcq_cred_kind kind;
  const char* cert_file;   /* UTF-8 path to cert PEM (may include chain) */
  const char* key_file;    /* UTF-8 path to key PEM */
  const char* key_pass;    /* optional password; NULL if none (ignored today) */
} bvcq_credentials;

/* Verification policy */
typedef enum {
  BVCQ_VERIFY_STRICT = 0,
  BVCQ_VERIFY_INSECURE_NO_VERIFY,
  BVCQ_VERIFY_DEFER
} bvcq_verify_mode;

/* ===== Events (binary stream) ===== */
typedef enum {
  /* Listener/connection */
  BVCQ_EV_CONN_ACCEPTED       = 1,  /* [cid:u64][listener_id:u64][peer:bvcq_addr] */
  BVCQ_EV_CONN_CONNECTED      = 2,  /* [cid:u64][peer:bvcq_addr] */
  BVCQ_EV_CONN_CLOSED         = 3,  /* [cid:u64][app_error:u32][transport_error:u32] */
  BVCQ_EV_CONN_CERT_REQUIRED  = 4,  /* [cid:u64] (only if VERIFY_DEFER) */

  /* Streams */
  BVCQ_EV_STREAM_OPENED       = 10, /* [cid:u64][sid:u64][bidi:u8] */
  BVCQ_EV_STREAM_WRITABLE     = 11, /* [sid:u64] */
  BVCQ_EV_STREAM_READ         = 12, /* [sid:u64][fin:u32][len:u32][bytes:len] */

  /* Datagrams */
  BVCQ_EV_DGRAM_READ          = 20  /* [cid:u64][len:u32][bytes:len] */
} bvcq_ev_type;

typedef struct {
  uint32_t type;   /* bvcq_ev_type */
  uint32_t flags;  /* reserved */
  uint32_t size;   /* total size (including this header) */
} bvcq_ev_hdr;

/* ===== Library lifecycle & integration ===== */
BVCQ_API const char* BVCQ_CALL bvc_quic_version(int* out_major, int* out_minor);

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_init(bvcq_lib* out_lib, int* out_wakeup_fd);

/* Optional: Windows runloop handle (returns NULL elsewhere). */
BVCQ_API void* BVCQ_CALL bvc_quic_get_wakeup_handle(bvcq_lib lib);

BVCQ_API void BVCQ_CALL bvc_quic_shutdown(bvcq_lib lib);

/* ===== Registration / Config ===== */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_open_registration(bvcq_lib lib, const char* app_name, bvcq_reg* out_reg);

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_open_config(
  bvcq_lib lib,
  bvcq_reg reg,
  const char* const* alpn, int alpn_count,
  const bvcq_settings* settings,
  const bvcq_credentials* client_creds,
  const bvcq_credentials* server_creds,
  bvcq_verify_mode verify_client,
  bvcq_verify_mode verify_server,
  bvcq_cfg* out_cfg);

/* ===== Server: Listener ===== */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_listener_start(
  bvcq_lib lib, bvcq_reg reg, bvcq_cfg cfg,
  const char* bind_ip, uint16_t bind_port,
  bvcq_listener* out_listener);

BVCQ_API void BVCQ_CALL
bvc_quic_listener_stop(bvcq_listener lst);

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_listener_get_port(bvcq_listener lst, uint16_t* out_port);

/* ===== Client: Connection ===== */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_connect(
  bvcq_lib lib, bvcq_reg reg, bvcq_cfg cfg,
  const char* server_name,  /* SNI; may be NULL (fall back to ip) */
  const char* ip, uint16_t port,
  bvcq_conn* out_conn);

BVCQ_API void BVCQ_CALL
bvc_quic_conn_close(bvcq_conn c, uint32_t app_error_code);

/* Certificate decision when verify policy is DEFER. */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_conn_cert_complete(bvcq_conn c, int accept, uint16_t tls_alert_code /*0=generic*/);

/* Enables/disables TLS key logging (NSS format) for a connection.
   - Returns BVCQ_ERR_UNSUPPORTED if the library was built without keylog support.
   - Returns BVCQ_ERR_SYS if the underlying MsQuic doesn’t expose a compatible knob.
   - On success, secrets from future handshakes on this connection may be logged.

   If path is NULL or empty when enabling, the implementation will try SSLKEYLOGFILE.
*/
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_conn_enable_keylog(bvcq_conn c, int enable, const char* path /*optional*/);

/* Retrieve negotiated handshake info. Caller must set .size. */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_get_conn_handshake(bvcq_conn c, bvcq_handshake_info* out_info);

/* ===== Streams ===== */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_stream_open(bvcq_conn c, int bidi /*0=uni,1=bidi*/, bvcq_stream* out_sid);

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_stream_send(bvcq_stream sid, const void* data, size_t len, int fin, uint32_t flags /*reserved*/);

BVCQ_API void BVCQ_CALL
bvc_quic_stream_shutdown(bvcq_stream sid);

/* Backpressure: pause/resume inbound delivery. */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_stream_set_read_enabled(bvcq_stream sid, int enabled);

/* ===== Datagrams ===== */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_dgram_send(bvcq_conn c, const void* data, size_t len);

/* ===== Events & Stats ===== */
BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_drain_events(bvcq_lib lib, void* out_buf, size_t buf_bytes, size_t* out_used);

BVCQ_API bvc_quic_status BVCQ_CALL
bvc_quic_get_conn_stats(bvcq_conn c, bvcq_conn_stats* out_stats);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* BVC_QUIC_H */