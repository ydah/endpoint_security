/* watchdog_stress.c
 * Calling threads: one test thread and the production watchdog pthread.
 */
#include "client.h"
#include "esmock.h"

#include <mach/mach_time.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(condition)                                                                                              \
    do {                                                                                                              \
        if (!(condition)) {                                                                                           \
            abort();                                                                                                  \
        }                                                                                                             \
    } while (0)

void
esrb_notify(esrb_client_t *client)
{
    (void)client;
}

static uint64_t
ticks_for_nanoseconds(uint64_t nanoseconds)
{
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    return nanoseconds * info.denom / info.numer;
}

int
main(void)
{
    enum { CAPACITY = 64, ROUNDS = 20 };
    esrb_client_t client;
    es_message_t messages[CAPACITY];
    memset(&client, 0, sizeof(client));
    memset(messages, 0, sizeof(messages));
    CHECK(esrb_queue_init(&client.queue, CAPACITY));
    CHECK(esrb_watchdog_init(&client.watchdog, CAPACITY));
    atomic_init(&client.watchdog_running, true);
    atomic_init(&client.timeouts, 0);
    client.default_auth = ES_AUTH_RESULT_ALLOW;
    esmock_reset();
    CHECK(pthread_create(&client.watchdog_thread, NULL, esrb_watchdog_main, &client) == 0);

    for (size_t round = 0; round < ROUNDS; round++) {
        for (size_t index = 0; index < CAPACITY; index++) {
            esrb_slot_t *slot = &client.queue.slots[index];
            messages[index].event_type = ES_EVENT_TYPE_AUTH_EXEC;
            slot->message = &messages[index];
            slot->client = (es_client_t *)1;
            slot->position = round * CAPACITY + index;
            slot->fire_at = mach_absolute_time() + ticks_for_nanoseconds((index % 8 + 1) * 1000000ULL);
            atomic_store_explicit(&slot->answer_state, ESRB_ANSWER_PENDING, memory_order_relaxed);
            atomic_store_explicit(&slot->occupied, true, memory_order_release);
            CHECK(esrb_watchdog_arm(&client.watchdog, slot));
        }

        size_t target = (round + 1) * CAPACITY;
        for (size_t attempt = 0; esmock_response_count() < target && attempt < 5000; attempt++) {
            nanosleep(&(struct timespec){.tv_nsec = 1000000}, NULL);
        }
        CHECK(esmock_response_count() == target);
        for (size_t index = 0; index < CAPACITY; index++) {
            esrb_queue_disarm(&client.queue.slots[index]);
        }
    }

    atomic_store_explicit(&client.watchdog_running, false, memory_order_release);
    pthread_cond_broadcast(&client.watchdog.condition);
    CHECK(pthread_join(client.watchdog_thread, NULL) == 0);
    CHECK(atomic_load_explicit(&client.timeouts, memory_order_relaxed) == CAPACITY * ROUNDS);
    esrb_watchdog_destroy(&client.watchdog);
    esrb_queue_destroy(&client.queue);
    puts("1,280 watchdog responses passed");
    return 0;
}
