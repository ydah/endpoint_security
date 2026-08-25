/* watchdog.c
 * Calling thread: dedicated pthread without the GVL. Ruby APIs are forbidden.
 */
#include "client.h"

#include <mach/mach_time.h>
#include <time.h>

void *
esrb_watchdog_main(void *argument)
{
    esrb_client_t *client = argument;
    const struct timespec interval = {.tv_sec = 0, .tv_nsec = 1000000};

    /* ponytail: fixed-ring scan is O(queue depth); replace with a lock-free deadline heap if profiling requires it. */
    while (atomic_load_explicit(&client->watchdog_running, memory_order_acquire)) {
        uint64_t now = mach_absolute_time();
        for (size_t index = 0; index < client->queue.capacity; index++) {
            esrb_slot_t *slot = &client->queue.slots[index];
            if (!atomic_load_explicit(&slot->occupied, memory_order_acquire) || slot->fire_at > now) {
                continue;
            }

            uint32_t expected = ESRB_ANSWER_PENDING;
            if (!atomic_compare_exchange_strong_explicit(
                    &slot->answer_state, &expected, ESRB_ANSWER_ANSWERED, memory_order_acq_rel, memory_order_acquire)) {
                continue;
            }

            if (slot->message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
                es_respond_flags_result(slot->client, slot->message, client->default_auth == ES_AUTH_RESULT_ALLOW ? UINT32_MAX : 0,
                    client->default_cache);
            } else {
                es_respond_auth_result(slot->client, slot->message, client->default_auth, client->default_cache);
            }
            atomic_fetch_add_explicit(&client->timeouts, 1, memory_order_relaxed);
            esrb_notify(client);
        }
        nanosleep(&interval, NULL);
    }
    return NULL;
}
