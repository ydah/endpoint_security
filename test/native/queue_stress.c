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

int
main(void)
{
    if (!esrb_queue_init(&queue, 8192)) {
        return 1;
    }

    pthread_t producers[PRODUCERS];
    pthread_t consumer;
    pthread_create(&consumer, NULL, consume, NULL);
    for (uintptr_t index = 0; index < PRODUCERS; index++) {
        pthread_create(&producers[index], NULL, produce, (void *)index);
    }
    for (size_t index = 0; index < PRODUCERS; index++) {
        pthread_join(producers[index], NULL);
    }
    pthread_join(consumer, NULL);

    esrb_queue_destroy(&queue);
    puts("1,000,000 queue operations passed");
    return 0;
}
