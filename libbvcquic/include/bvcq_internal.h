// bvcq_internal.h (private)
#pragma once
#include <msquic.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
  #include <pthread.h>
#else
  #include <windows.h>
#endif

#include "bvc_quic.h" // public types

/* ---------- Logging / Diagnostics ---------------------------------------- */
int  bvcq_log_level(void);
void bvcq_logf_internal(int level, const char* fmt, ...);

#define LOGF_MIN(...) do { if (bvcq_log_level() >= 1) bvcq_logf_internal(1, __VA_ARGS__); } while (0)

#if BVCQ_BUILD_DIAG
  #define DIAGF(...)  do { if (bvcq_log_level() >= 2) bvcq_logf_internal(2, __VA_ARGS__); } while (0)
#else
  #define DIAGF(...)  do { (void)0; } while (0)
#endif

#define LOG_ENTER(fmt, ...) LOGF_MIN(">> " fmt, ##__VA_ARGS__)
#define LOG_LEAVE(fmt, ...) LOGF_MIN("<< " fmt, ##__VA_ARGS__)

const char* quic_status_name(QUIC_STATUS s);

/* -------- dgram send ctx (track for early-close cleanup) -------- */
typedef struct dgsend_s {
  uint8_t* data;
  uint32_t len;
  struct dgsend_s* next;
} dgsend_t;

/* -------- State -------- */
typedef struct conn_s {
  uint64_t id;
  HQUIC   h;
  int     read_enabled;
  int     cert_deferred;

  /* robust close handling */
  int     closing;         /* set once conn_close() is called */
  int     closed_emitted;  /* we’ve emitted BVCQ_EV_CONN_CLOSED */

  /* pending DATAGRAM sends to free on early close */
  dgsend_t* dgram_head;
} conn_t;

typedef struct strm_s {
  uint64_t id; HQUIC h; uint64_t conn_id; int read_enabled; int bidi;
} strm_t;

typedef struct lst_s {
  uint64_t id; HQUIC h; bvcq_addr bind; uint64_t cfg_id;
} lst_t;

typedef struct cfg_s {
  uint64_t id; HQUIC h;
  QUIC_BUFFER* alpns; uint32_t alpn_count;
  int allow_client; int allow_server;
  bvcq_verify_mode verify_client, verify_server;
} cfg_t;

/* queues, tables */
typedef struct evnode_s { struct evnode_s* next; size_t len; uint8_t data[]; } evnode_t;

typedef struct {
#ifndef _WIN32
  int pipe_r, pipe_w; pthread_mutex_t mu;
#else
  HANDLE wake; CRITICAL_SECTION mu;
#endif
  evnode_t* head; evnode_t* tail;
} evq_s;

typedef struct {
  uint64_t next_id;
  conn_t* conns; size_t conns_len;
  strm_t* strms; size_t strms_len;
  lst_t*  lsts;  size_t lsts_len;
  cfg_t*  cfgs;  size_t cfgs_len;
} tbl_s;

typedef struct {
  const QUIC_API_TABLE* api; HQUIC reg;
  tbl_s tbl; evq_s q;
} lib_s;

extern lib_s* G;

/* tables */
void     tbl_init(tbl_s* t);
uint64_t tbl_newid(tbl_s* t);
conn_t*  tbl_add_conn(tbl_s* t, HQUIC h);
strm_t*  tbl_add_strm(tbl_s* t, HQUIC h, uint64_t cid, int bidi);
lst_t*   tbl_add_lst (tbl_s* t, HQUIC h, const bvcq_addr* b, uint64_t cfg_id);
cfg_t*   tbl_add_cfg (tbl_s* t, HQUIC h);

conn_t*  tbl_find_conn(tbl_s* t, uint64_t id);
strm_t*  tbl_find_strm(tbl_s* t, uint64_t id);
lst_t*   tbl_find_lst (tbl_s* t, uint64_t id);
cfg_t*   tbl_find_cfg (tbl_s* t, uint64_t id);

/* evqueue */
void   evq_init(evq_s* q);
void   evq_free(evq_s* q);
void   evq_push(evq_s* q, const void* rec, size_t len);
size_t evq_copy_out(evq_s* q, void* out, size_t cap);
void   evq_wakeup(evq_s* q);

/* emitters */
void emit_conn_accepted(uint64_t cid,uint64_t lstid,const bvcq_addr* peer);
void emit_conn_connected(uint64_t cid,const bvcq_addr* peer);
void emit_conn_closed(uint64_t cid,uint32_t app,uint32_t tcode);
void emit_conn_cert_required(uint64_t cid);
void emit_stream_opened(uint64_t cid,uint64_t sid,int bidi);
void emit_stream_writable(uint64_t sid);
void emit_stream_read(uint64_t sid,int fin,const uint8_t* buf,uint32_t len);
void emit_dgram_read(uint64_t cid,const uint8_t* buf,uint32_t len);

/* tiny utils */
void dump_bytes(const void* p, size_t n);

/* Forward decls */
QUIC_STATUS QUIC_API on_stream(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event);
bvc_quic_status st_from_quic(QUIC_STATUS s);

/* helpers used across callbacks */
static inline uint64_t conn_id_from_h(HQUIC h){
  for (size_t i=0;i<G->tbl.conns_len;i++) if (G->tbl.conns[i].h==h) return G->tbl.conns[i].id;
  return 0;
}
static inline uint64_t strm_id_from_h(HQUIC h){
  for (size_t i=0;i<G->tbl.strms_len;i++) if (G->tbl.strms[i].h==h) return G->tbl.strms[i].id;
  return 0;
}

/* --- dgram send list helpers (header-only) -------------------------------- */

static inline void link_dgsend_ctx(conn_t* c, dgsend_t* n){
  if (!c || !n) return;
  n->next = c->dgram_head;
  c->dgram_head = n;
}

static inline void unlink_dgsend_ctx(conn_t* c, dgsend_t* target){
  if (!c || !target) return;
  dgsend_t** p = &c->dgram_head;
  while (*p) {
    if (*p == target) { *p = target->next; return; }
    p = &(*p)->next;
  }
}

static inline void free_all_dgsends(conn_t* c){
  if (!c) return;
  dgsend_t* n = c->dgram_head;
  while (n) {
    dgsend_t* nx = n->next;
    if (n->data) free(n->data);
    free(n);
    n = nx;
  }
  c->dgram_head = NULL;
}
