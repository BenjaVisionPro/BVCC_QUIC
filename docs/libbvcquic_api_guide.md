
# libbvcquic API Guide

This document explains what **libbvcquic** does and how to use it in practice.  
It complements the build instructions by walking through the concepts and the API exposed in `bvc_quic.h`.

---

## Overview

`libbvcquic` is a thin wrapper around MsQuic. It provides a **stable, FFI-safe surface** for QUIC sockets:
- Uses **opaque handles** (`bvcq_conn`, `bvcq_stream`, etc.) instead of raw MsQuic pointers.  
- Delivers events via a **binary queue** (`bvc_quic_drain_events`), not direct callbacks.  
- Ensures **predictable shutdown** (close is idempotent; you always get `EV_CONN_CLOSED`).  
- Structures are versioned with `.size` so future extensions remain compatible.  

The intended use cases are embedding QUIC into event-driven runtimes such as:
- GemStone/Pharo FFI,
- Unreal Engine plugins,
- or any C/C++ application needing a minimal QUIC layer.

---

## Core Concepts

- **Library (`bvcq_lib`)**: Global context created once per process (`bvc_quic_init`).  
- **Registration (`bvcq_reg`)**: Identifies an "application" to MsQuic; used for grouping connections.  
- **Config (`bvcq_cfg`)**: Bundles ALPNs, settings, and credentials into a reusable handle.  
- **Listener (`bvcq_listener`)**: Accepts inbound connections (server-side).  
- **Connection (`bvcq_conn`)**: Represents a single QUIC connection.  
- **Stream (`bvcq_stream`)**: QUIC stream (uni- or bi-directional).  

Events are drained explicitly from the queue — nothing calls into your code asynchronously.

---

## Lifecycle Walkthrough

Typical usage looks like this:

```c
bvcq_lib L;
int wake_fd;
bvc_quic_init(&L, &wake_fd);  // initialize the library

bvcq_reg R;
bvc_quic_open_registration(L, "example-app", &R);

bvcq_cfg C;
bvc_quic_open_config(
    L, R,
    alpn_list, alpn_count,
    &settings,
    &client_creds,
    &server_creds,
    BVCQ_VERIFY_STRICT, BVCQ_VERIFY_STRICT,
    &C);

// Server
bvcq_listener lst;
bvc_quic_listener_start(L, R, C, "0.0.0.0", 4433, &lst);

// Client
bvcq_conn conn;
bvc_quic_connect(L, R, C, "example.com", "1.2.3.4", 4433, &conn);

// Poll events
uint8_t buf[4096];
size_t used;
while (running) {
    if (bvc_quic_drain_events(L, buf, sizeof buf, &used) == BVCQ_OK) {
        const bvcq_ev_hdr* ev = (const bvcq_ev_hdr*)buf;
        // inspect ev->type and handle payload accordingly
    }
}

bvc_quic_shutdown(L);
```

---

## API Reference

### Initialization

- `bvc_quic_init(&lib, &wakeup_fd)`  
  Creates the library context. On POSIX, returns a wakeup pipe fd suitable for `select/poll/epoll`.  
  On Windows, `bvc_quic_get_wakeup_handle` returns a HANDLE for `WaitForMultipleObjects`.

- `bvc_quic_shutdown(lib)`  
  Frees all resources.

### Registration and Config

- `bvc_quic_open_registration(lib, "app", &reg)`  
- `bvc_quic_open_config(lib, reg, alpns, count, settings, client_creds, server_creds, verify_client, verify_server, &cfg)`  

`bvcq_settings` includes knobs for idle timeout, keepalive, max streams, datagram enable, congestion control.  
`bvcq_credentials` describe TLS certs (or none).  
`bvcq_verify_mode` controls peer verification (`STRICT`, `INSECURE_NO_VERIFY`, `DEFER`).

### Listeners

- `bvc_quic_listener_start(lib, reg, cfg, ip, port, &listener)`  
- `bvc_quic_listener_stop(listener)`  
- `bvc_quic_listener_get_port(listener, &port)`  

### Connections

- `bvc_quic_connect(lib, reg, cfg, server_name, ip, port, &conn)`  
- `bvc_quic_conn_close(conn, app_error_code)` (idempotent, always emits CLOSED)  
- `bvc_quic_conn_cert_complete(conn, accept, tls_alert_code)` (only needed if verify mode is DEFER)  
- `bvc_quic_conn_enable_keylog(conn, enable, path)` (if built with keylog support)  
- `bvc_quic_get_conn_handshake(conn, &handshake_info)`  
- `bvc_quic_get_conn_stats(conn, &stats)`  

### Streams

- `bvc_quic_stream_open(conn, bidi, &sid)`  
- `bvc_quic_stream_send(sid, data, len, fin, flags)`  
- `bvc_quic_stream_shutdown(sid)`  
- `bvc_quic_stream_set_read_enabled(sid, enabled)`  

### Datagrams

- `bvc_quic_dgram_send(conn, data, len)`  

### Events

- `bvc_quic_drain_events(lib, buf, buf_size, &used)`  
  Fills a user buffer with one or more events. Each begins with `bvcq_ev_hdr`.  
  Event types (`bvcq_ev_type`):  
  - `EV_CONN_ACCEPTED`, `EV_CONN_CONNECTED`, `EV_CONN_CLOSED`, `EV_CONN_CERT_REQUIRED`  
  - `EV_STREAM_OPENED`, `EV_STREAM_WRITABLE`, `EV_STREAM_READ`  
  - `EV_DGRAM_READ`  

The event queue is **single-producer, single-consumer**. Drain it promptly to avoid backpressure.

---

## Error Handling

All functions return `bvc_quic_status`:
- `BVCQ_OK` on success.  
- Negative values for errors (`ERR_BADARG`, `ERR_NOTFOUND`, etc.).  
- `ERR_AGAIN` signals a non-fatal retry case.

---

## Practical Notes

- Always set `.size` when passing structs (`bvcq_settings`, `bvcq_handshake_info`, `bvcq_conn_stats`).  
- Always drain events — otherwise the library can stall.  
- `conn_close` is safe to call multiple times; after the first, it’s a no-op.  
- Datagrams and streams may arrive concurrently; handle events in order drained.  
- If verify mode is `DEFER`, you *must* call `conn_cert_complete()` or the connection will hang.  

---

## Summary

`libbvcquic` gives you:  
- QUIC sockets that integrate with your event loop via fd/handle.  
- A consistent C API surface (no direct MsQuic headers).  
- A small set of event types covering streams, datagrams, and connection lifecycle.  

It is designed to be predictable and portable — so you can focus on your application, not QUIC internals.
