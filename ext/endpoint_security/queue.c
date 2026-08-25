/* queue.c
 * Calling threads: producer = ES handler (no GVL), consumer = Ruby dispatcher (GVL).
 * The watchdog scans occupied slots without taking a lock.
 */
#include "queue.h"

#include <stdlib.h>

bool
esrb_queue_init(esrb_queue_t *queue, size_t capacity)
{
    if (capacity < 2 || (capacity & (capacity - 1)) != 0) {
        return false;
    }

    queue->slots = calloc(capacity, sizeof(*queue->slots));
    if (queue->slots == NULL) {
        return false;
    }

    queue->capacity = capacity;
    queue->mask = capacity - 1;
    atomic_init(&queue->enqueue_position, 0);
    atomic_init(&queue->dequeue_position, 0);
    atomic_init(&queue->depth_max, 0);
    for (size_t index = 0; index < capacity; index++) {
        atomic_init(&queue->slots[index].sequence, index);
        atomic_init(&queue->slots[index].occupied, false);
        atomic_init(&queue->slots[index].answer_state, ESRB_ANSWER_NOT_AUTH);
    }
    return true;
}

void
esrb_queue_destroy(esrb_queue_t *queue)
{
    free(queue->slots);
    queue->slots = NULL;
}

esrb_slot_t *
esrb_queue_enqueue(esrb_queue_t *queue)
{
    size_t position = atomic_load_explicit(&queue->enqueue_position, memory_order_relaxed);

    for (;;) {
        esrb_slot_t *slot = &queue->slots[position & queue->mask];
        size_t sequence = atomic_load_explicit(&slot->sequence, memory_order_acquire);
        intptr_t difference = (intptr_t)sequence - (intptr_t)position;

        if (difference == 0) {
            if (atomic_compare_exchange_weak_explicit(
                    &queue->enqueue_position, &position, position + 1, memory_order_relaxed, memory_order_relaxed)) {
                slot->position = position;
                return slot;
            }
        } else if (difference < 0) {
            return NULL;
        } else {
            position = atomic_load_explicit(&queue->enqueue_position, memory_order_relaxed);
        }
    }
}

void
esrb_queue_publish(esrb_queue_t *queue, esrb_slot_t *slot)
{
    size_t depth = slot->position + 1 - atomic_load_explicit(&queue->dequeue_position, memory_order_relaxed);
    size_t maximum = atomic_load_explicit(&queue->depth_max, memory_order_relaxed);
    while (depth > maximum && !atomic_compare_exchange_weak_explicit(
               &queue->depth_max, &maximum, depth, memory_order_relaxed, memory_order_relaxed)) {
    }
    atomic_store_explicit(&slot->sequence, slot->position + 1, memory_order_release);
}

esrb_slot_t *
esrb_queue_dequeue(esrb_queue_t *queue)
{
    size_t position = atomic_load_explicit(&queue->dequeue_position, memory_order_relaxed);

    for (;;) {
        esrb_slot_t *slot = &queue->slots[position & queue->mask];
        size_t sequence = atomic_load_explicit(&slot->sequence, memory_order_acquire);
        intptr_t difference = (intptr_t)sequence - (intptr_t)(position + 1);

        if (difference == 0) {
            if (atomic_compare_exchange_weak_explicit(
                    &queue->dequeue_position, &position, position + 1, memory_order_relaxed, memory_order_relaxed)) {
                return slot;
            }
        } else if (difference < 0) {
            return NULL;
        } else {
            position = atomic_load_explicit(&queue->dequeue_position, memory_order_relaxed);
        }
    }
}

void
esrb_queue_release(esrb_queue_t *queue, esrb_slot_t *slot)
{
    atomic_store_explicit(&slot->occupied, false, memory_order_release);
    atomic_store_explicit(&slot->sequence, slot->position + queue->capacity, memory_order_release);
}

size_t
esrb_queue_depth(const esrb_queue_t *queue)
{
    size_t enqueued = atomic_load_explicit(&queue->enqueue_position, memory_order_relaxed);
    size_t dequeued = atomic_load_explicit(&queue->dequeue_position, memory_order_relaxed);
    return enqueued - dequeued;
}
