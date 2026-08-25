#ifndef ESRB_CLIENT_H
#define ESRB_CLIENT_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <pthread.h>
#include <ruby.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "queue.h"

typedef struct {
    es_client_t *client;
    esrb_queue_t queue;
    int wakeup_fd[2];
    pthread_t watchdog_thread;
    _Atomic bool watchdog_running;
    _Atomic bool notified;
    _Atomic bool closed;
    _Atomic uint64_t dropped;
    _Atomic uint64_t delivered;
    _Atomic uint64_t timeouts;
    _Atomic uint64_t errors;
    _Atomic uint64_t seq_gaps;
    _Atomic uint64_t leaked_messages;
    _Atomic uint64_t last_global_seq;
    _Atomic bool seen_global_seq;
    _Atomic uint64_t last_event_seq[ES_EVENT_TYPE_LAST];
    _Atomic bool seen_event_seq[ES_EVENT_TYPE_LAST];
    es_auth_result_t default_auth;
    bool default_cache;
    bool strict_cache;
    bool strict_version;
    double deadline_margin;
    uint64_t min_margin_ticks;
    pid_t owner_pid;
} esrb_client_t;

extern const rb_data_type_t esrb_client_type;

void esrb_init_client(VALUE endpoint_security);
void esrb_notify(esrb_client_t *client);
bool esrb_respond_slot(esrb_client_t *client, esrb_slot_t *slot, es_auth_result_t result, uint32_t flags, bool cache);
void *esrb_watchdog_main(void *argument);

#endif
