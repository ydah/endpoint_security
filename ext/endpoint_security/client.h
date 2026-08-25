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
    es_auth_result_t default_auth;
    bool default_cache;
    bool strict_cache;
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
