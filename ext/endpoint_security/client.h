#ifndef ESRB_CLIENT_H
#define ESRB_CLIENT_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <pthread.h>
#include <ruby.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "queue.h"

typedef struct {
    _Atomic size_t sequence;
    esrb_slot_t *slot;
    size_t position;
    uint64_t fire_at;
} esrb_watchdog_request_t;

typedef struct {
    esrb_slot_t *slot;
    size_t position;
    uint64_t fire_at;
} esrb_watchdog_entry_t;

typedef struct {
    size_t capacity;
    size_t mask;
    esrb_watchdog_request_t *requests;
    _Atomic size_t enqueue_position;
    _Atomic size_t dequeue_position;
    esrb_watchdog_entry_t *heap;
    size_t heap_size;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
} esrb_watchdog_t;

typedef struct {
    es_client_t *client;
    esrb_queue_t queue;
    int wakeup_fd[2];
    pthread_t watchdog_thread;
    esrb_watchdog_t watchdog;
    bool watchdog_thread_started;
    _Atomic bool watchdog_running;
    _Atomic bool watchdog_stopped;
    _Atomic bool delete_ready;
    _Atomic bool client_ready;
    _Atomic es_new_client_result_t creation_result;
    _Atomic bool notified;
    _Atomic bool closed;
    _Atomic uint32_t active_callbacks;
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
    bool warn_on_truncated_path;
    double deadline_margin;
    uint64_t min_margin_ticks;
    pid_t owner_pid;
} esrb_client_t;

extern const rb_data_type_t esrb_client_type;

void esrb_init_client(VALUE endpoint_security);
void esrb_notify(esrb_client_t *client);
bool esrb_respond_slot(esrb_client_t *client, esrb_slot_t *slot, es_auth_result_t result, uint32_t flags, bool cache);
bool esrb_watchdog_init(esrb_watchdog_t *watchdog, size_t capacity);
void esrb_watchdog_destroy(esrb_watchdog_t *watchdog);
void esrb_watchdog_abandon(esrb_watchdog_t *watchdog);
bool esrb_watchdog_arm(esrb_watchdog_t *watchdog, esrb_slot_t *slot);
void *esrb_watchdog_main(void *argument);

#endif
