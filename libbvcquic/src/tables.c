// lib/tables.c — handle tables (conn/stream/listener/config)

#include "bvcq_internal.h"
#include <stdlib.h>
#include <string.h>

void tbl_init(tbl_s* t){
    memset(t, 0, sizeof(*t));
    t->next_id = 1;
}

uint64_t tbl_newid(tbl_s* t){
    return t->next_id++;
}

conn_t* tbl_add_conn(tbl_s* t, HQUIC h){
    t->conns = (conn_t*)realloc(t->conns, (t->conns_len + 1) * sizeof(conn_t));
    conn_t* c = &t->conns[t->conns_len++];
    memset(c, 0, sizeof(*c));
    c->id = tbl_newid(t);
    c->h  = h;
    c->read_enabled = 1;
    c->cert_deferred = 0;
    return c;
}

strm_t* tbl_add_strm(tbl_s* t, HQUIC h, uint64_t conn_id, int bidi){
    t->strms = (strm_t*)realloc(t->strms, (t->strms_len + 1) * sizeof(strm_t));
    strm_t* s = &t->strms[t->strms_len++];
    memset(s, 0, sizeof(*s));
    s->id = tbl_newid(t);
    s->h  = h;
    s->conn_id = conn_id;
    s->read_enabled = 1;
    s->bidi = bidi ? 1 : 0;
    return s;
}

lst_t* tbl_add_lst(tbl_s* t, HQUIC h, const bvcq_addr* b, uint64_t cfg_id){
    t->lsts = (lst_t*)realloc(t->lsts, (t->lsts_len + 1) * sizeof(lst_t));
    lst_t* l = &t->lsts[t->lsts_len++];
    memset(l, 0, sizeof(*l));
    l->id = tbl_newid(t);
    l->h  = h;
    if (b) l->bind = *b;
    l->cfg_id = cfg_id;
    return l;
}

cfg_t* tbl_add_cfg(tbl_s* t, HQUIC h){
    t->cfgs = (cfg_t*)realloc(t->cfgs, (t->cfgs_len + 1) * sizeof(cfg_t));
    cfg_t* c = &t->cfgs[t->cfgs_len++];
    memset(c, 0, sizeof(*c));
    c->id = tbl_newid(t);
    c->h  = h;
    return c;
}

conn_t* tbl_find_conn(tbl_s* t, uint64_t id){
    for (size_t i = 0; i < t->conns_len; i++) if (t->conns[i].id == id) return &t->conns[i];
    return NULL;
}

strm_t* tbl_find_strm(tbl_s* t, uint64_t id){
    for (size_t i = 0; i < t->strms_len; i++) if (t->strms[i].id == id) return &t->strms[i];
    return NULL;
}

lst_t* tbl_find_lst(tbl_s* t, uint64_t id){
    for (size_t i = 0; i < t->lsts_len; i++) if (t->lsts[i].id == id) return &t->lsts[i];
    return NULL;
}

cfg_t* tbl_find_cfg(tbl_s* t, uint64_t id){
    for (size_t i = 0; i < t->cfgs_len; i++) if (t->cfgs[i].id == id) return &t->cfgs[i];
    return NULL;
}