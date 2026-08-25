#ifndef ESRB_QUEUE_H
#define ESRB_QUEUE_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

enum {
    ESRB_ANSWER_PENDING = 0,
    ESRB_ANSWER_ANSWERED = 1,
    ESRB_ANSWER_NOT_AUTH = 2
};

typedef struct {
    _Atomic size_t sequence;
    _Atomic bool occupied;
    const es_message_t *message;
    es_client_t *client;
    size_t position;
    uint64_t fire_at;
    _Atomic uint32_t answer_state;
    _Atomic uint32_t readers;
} esrb_slot_t;

typedef struct {
    size_t capacity;
    size_t mask;
    esrb_slot_t *slots;
    _Atomic size_t enqueue_position;
    _Atomic size_t dequeue_position;
    _Atomic size_t depth_max;
} esrb_queue_t;

bool esrb_queue_init(esrb_queue_t *queue, size_t capacity);
void esrb_queue_destroy(esrb_queue_t *queue);
esrb_slot_t *esrb_queue_enqueue(esrb_queue_t *queue);
void esrb_queue_publish(esrb_queue_t *queue, esrb_slot_t *slot);
esrb_slot_t *esrb_queue_dequeue(esrb_queue_t *queue);
void esrb_queue_disarm(esrb_slot_t *slot);
void esrb_queue_release(esrb_queue_t *queue, esrb_slot_t *slot);
size_t esrb_queue_depth(const esrb_queue_t *queue);

#endif
