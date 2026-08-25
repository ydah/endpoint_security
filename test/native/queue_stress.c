/* queue_stress.c
 * Calling threads: four producers and one consumer; no Ruby VM is involved.
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "queue.h"

enum {
    PRODUCERS = 4,
    ITEMS_PER_PRODUCER = 250000,
    TOTAL_ITEMS = PRODUCERS * ITEMS_PER_PRODUCER
};

static esrb_queue_t queue;
static _Atomic size_t consumed;
static _Atomic bool scanning;

static void *
produce(void *argument)
{
    uintptr_t producer = (uintptr_t)argument;
    for (size_t index = 0; index < ITEMS_PER_PRODUCER; index++) {
        esrb_slot_t *slot;
        while ((slot = esrb_queue_enqueue(&queue)) == NULL) {
        }
        slot->message = (const es_message_t *)(producer * ITEMS_PER_PRODUCER + index + 1);
        atomic_store_explicit(&slot->occupied, true, memory_order_release);
        esrb_queue_publish(&queue, slot);
    }
    return NULL;
}

static void *
consume(void *argument)
{
    (void)argument;
    while (atomic_load_explicit(&consumed, memory_order_relaxed) < TOTAL_ITEMS) {
        esrb_slot_t *slot = esrb_queue_dequeue(&queue);
        if (slot == NULL) {
            continue;
        }
        if (slot->message == NULL) {
            abort();
        }
        atomic_fetch_add_explicit(&consumed, 1, memory_order_relaxed);
        esrb_queue_release(&queue, slot);
    }
    return NULL;
}

static void *
scan(void *argument)
{
    (void)argument;
    while (atomic_load_explicit(&scanning, memory_order_acquire)) {
        for (size_t index = 0; index < queue.capacity; index++) {
            esrb_slot_t *slot = &queue.slots[index];
            if (!atomic_load_explicit(&slot->occupied, memory_order_acquire)) {
                continue;
            }
            atomic_fetch_add_explicit(&slot->readers, 1, memory_order_acquire);
            if (atomic_load_explicit(&slot->occupied, memory_order_acquire) && slot->message == NULL) {
                abort();
            }
            atomic_fetch_sub_explicit(&slot->readers, 1, memory_order_release);
        }
    }
    return NULL;
}

int
main(void)
{
    if (!esrb_queue_init(&queue, 8192)) {
        return 1;
    }

    pthread_t producers[PRODUCERS];
    pthread_t consumer;
    pthread_t scanner;
    atomic_init(&scanning, true);
    pthread_create(&scanner, NULL, scan, NULL);
    pthread_create(&consumer, NULL, consume, NULL);
    for (uintptr_t index = 0; index < PRODUCERS; index++) {
        pthread_create(&producers[index], NULL, produce, (void *)index);
    }
    for (size_t index = 0; index < PRODUCERS; index++) {
        pthread_join(producers[index], NULL);
    }
    pthread_join(consumer, NULL);
    atomic_store_explicit(&scanning, false, memory_order_release);
    pthread_join(scanner, NULL);

    esrb_queue_destroy(&queue);
    puts("1,000,000 queue operations passed");
    return 0;
}
