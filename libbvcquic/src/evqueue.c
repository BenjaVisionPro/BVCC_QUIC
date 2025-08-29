// lib/evqueue.c — portable event queue + wake mechanism

#include "bvcq_internal.h"
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <pthread.h>
#else
  #include <windows.h>
#endif

void evq_init(evq_s* q){
    memset(q, 0, sizeof(*q));
#ifndef _WIN32
    int fds[2];
    if (pipe(fds) == 0) {
        int fl = fcntl(fds[0], F_GETFL, 0);
        fcntl(fds[0], F_SETFL, fl | O_NONBLOCK);
        q->pipe_r = fds[0];
        q->pipe_w = fds[1];
        LOGF_MIN("[evq] init: POSIX pipe wake fd_r=%d fd_w=%d", q->pipe_r, q->pipe_w);
    } else {
        q->pipe_r = q->pipe_w = -1;
        LOGF_MIN("[evq] init: POSIX pipe creation FAILED (errno=%d)", errno);
    }
    pthread_mutex_init(&q->mu, NULL);
#else
    q->wake = CreateEventA(NULL, FALSE, FALSE, NULL);
    InitializeCriticalSection(&q->mu);
    LOGF_MIN("[evq] init: Win32 event wake=%p", (void*)q->wake);
#endif
}

void evq_free(evq_s* q){
#ifndef _WIN32
    if (q->pipe_r != -1) close(q->pipe_r);
    if (q->pipe_w != -1) close(q->pipe_w);
    pthread_mutex_destroy(&q->mu);
#else
    if (q->wake) CloseHandle(q->wake);
    DeleteCriticalSection(&q->mu);
#endif
    size_t freed = 0;
    evnode_t* n = q->head;
    while (n) { evnode_t* nx = n->next; free(n); n = nx; ++freed; }
    q->head = q->tail = NULL;
    LOGF_MIN("[evq] free: drained %zu node(s)", freed);
}

void evq_wakeup(evq_s* q){
#ifndef _WIN32
    if (q->pipe_w != -1) {
        (void)write(q->pipe_w, "x", 1);
        DIAGF("[evq] wakeup: wrote 1 byte to fd %d", q->pipe_w);
    }
#else
    if (q->wake) {
        SetEvent(q->wake);
        DIAGF("[evq] wakeup: SetEvent(%p)", (void*)q->wake);
    }
#endif
}

void evq_push(evq_s* q, const void* rec, size_t len){
#ifndef _WIN32
    pthread_mutex_lock(&q->mu);
#else
    EnterCriticalSection(&q->mu);
#endif
    evnode_t* n = (evnode_t*)malloc(sizeof(evnode_t) + len);
    if (!n) {
#ifndef _WIN32
        pthread_mutex_unlock(&q->mu);
#else
        LeaveCriticalSection(&q->mu);
#endif
        DIAGF("[evq] push: OOM allocating %zu bytes", sizeof(evnode_t) + len);
        return;
    }
    n->next = NULL;
    n->len  = len;
    memcpy(n->data, rec, len);
    if (q->tail) q->tail->next = n; else q->head = n;
    q->tail = n;
#ifndef _WIN32
    pthread_mutex_unlock(&q->mu);
#else
    LeaveCriticalSection(&q->mu);
#endif
    DIAGF("[evq] push: queued %zu bytes", len);
    evq_wakeup(q);
}

size_t evq_copy_out(evq_s* q, void* out, size_t cap){
    size_t used = 0;
#ifndef _WIN32
    pthread_mutex_lock(&q->mu);
#else
    EnterCriticalSection(&q->mu);
#endif
    while (q->head) {
        evnode_t* n = q->head;
        if (n->len > cap - used) break;
        memcpy((uint8_t*)out + used, n->data, n->len);
        used += n->len;
        q->head = n->next;
        if (!q->head) q->tail = NULL;
        free(n);
    }
#ifndef _WIN32
    pthread_mutex_unlock(&q->mu);
    if (used > 0 && q->pipe_r != -1) {
        char b[64];
        while (read(q->pipe_r, b, sizeof(b)) > 0) { /* drain */ }
    }
#else
    LeaveCriticalSection(&q->mu);
    if (used > 0 && q->wake) ResetEvent(q->wake);
#endif
    DIAGF("[evq] copy_out: %zu bytes (cap=%zu)", used, cap);
    return used;
}