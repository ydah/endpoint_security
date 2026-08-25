/* watchdog.c
 * Calling threads: arm = ES handler without the GVL; heap owner = dedicated pthread without the GVL.
 * The handler only publishes to a bounded lock-free queue. Ruby APIs are forbidden.
 */
#include "client.h"

#include <mach/mach_time.h>
#include <stdlib.h>
#include <time.h>

static void
heap_swap(esrb_watchdog_t *watchdog, size_t left, size_t right)
{
    esrb_watchdog_entry_t temporary = watchdog->heap[left];
    watchdog->heap[left] = watchdog->heap[right];
    watchdog->heap[right] = temporary;
    watchdog->heap[left].slot->watchdog_index = left;
    watchdog->heap[right].slot->watchdog_index = right;
}

static void
heap_up(esrb_watchdog_t *watchdog, size_t index)
{
    while (index > 0) {
        size_t parent = (index - 1) / 2;
        if (watchdog->heap[parent].fire_at <= watchdog->heap[index].fire_at) {
            break;
        }
        heap_swap(watchdog, parent, index);
        index = parent;
    }
}

static void
heap_down(esrb_watchdog_t *watchdog, size_t index)
{
    for (;;) {
        size_t left = index * 2 + 1;
        if (left >= watchdog->heap_size) {
            return;
        }
        size_t right = left + 1;
        size_t smallest = right < watchdog->heap_size && watchdog->heap[right].fire_at < watchdog->heap[left].fire_at
            ? right
            : left;
        if (watchdog->heap[index].fire_at <= watchdog->heap[smallest].fire_at) {
            return;
        }
        heap_swap(watchdog, index, smallest);
        index = smallest;
    }
}

static void
heap_remove(esrb_watchdog_t *watchdog, size_t index)
{
    esrb_slot_t *removed = watchdog->heap[index].slot;
    removed->watchdog_index = SIZE_MAX;
    watchdog->heap_size--;
    if (index == watchdog->heap_size) {
        return;
    }
    watchdog->heap[index] = watchdog->heap[watchdog->heap_size];
    watchdog->heap[index].slot->watchdog_index = index;
    esrb_slot_t *moved = watchdog->heap[index].slot;
    heap_up(watchdog, index);
    heap_down(watchdog, moved->watchdog_index);
}

static void
heap_set(esrb_watchdog_t *watchdog, const esrb_watchdog_request_t *request)
{
    size_t index = request->slot->watchdog_index;
    if (index >= watchdog->heap_size || watchdog->heap[index].slot != request->slot) {
        if (watchdog->heap_size >= watchdog->capacity) {
            return;
        }
        index = watchdog->heap_size++;
        request->slot->watchdog_index = index;
    }
    watchdog->heap[index] = (esrb_watchdog_entry_t){
        .slot = request->slot, .position = request->position, .fire_at = request->fire_at
    };
    heap_up(watchdog, index);
    heap_down(watchdog, request->slot->watchdog_index);
}

static bool
request_pop(esrb_watchdog_t *watchdog, esrb_watchdog_request_t *output)
{
    size_t position = atomic_load_explicit(&watchdog->dequeue_position, memory_order_relaxed);
    esrb_watchdog_request_t *request = &watchdog->requests[position & watchdog->mask];
    if (atomic_load_explicit(&request->sequence, memory_order_acquire) != position + 1) {
        return false;
    }
    atomic_store_explicit(&watchdog->dequeue_position, position + 1, memory_order_relaxed);
    output->slot = request->slot;
    output->position = request->position;
    output->fire_at = request->fire_at;
    atomic_store_explicit(&request->sequence, position + watchdog->capacity, memory_order_release);
    return true;
}

bool
esrb_watchdog_init(esrb_watchdog_t *watchdog, size_t capacity)
{
    watchdog->capacity = capacity;
    watchdog->mask = capacity - 1;
    watchdog->heap_size = 0;
    watchdog->requests = calloc(capacity, sizeof(*watchdog->requests));
    watchdog->heap = calloc(capacity, sizeof(*watchdog->heap));
    if (watchdog->requests == NULL || watchdog->heap == NULL) {
        free(watchdog->requests);
        free(watchdog->heap);
        watchdog->requests = NULL;
        watchdog->heap = NULL;
        return false;
    }
    atomic_init(&watchdog->enqueue_position, 0);
    atomic_init(&watchdog->dequeue_position, 0);
    for (size_t index = 0; index < capacity; index++) {
        atomic_init(&watchdog->requests[index].sequence, index);
    }
    if (pthread_mutex_init(&watchdog->mutex, NULL) != 0) {
        free(watchdog->requests);
        free(watchdog->heap);
        watchdog->requests = NULL;
        watchdog->heap = NULL;
        return false;
    }
    if (pthread_cond_init(&watchdog->condition, NULL) != 0) {
        pthread_mutex_destroy(&watchdog->mutex);
        free(watchdog->requests);
        free(watchdog->heap);
        watchdog->requests = NULL;
        watchdog->heap = NULL;
        return false;
    }
    return true;
}

void
esrb_watchdog_destroy(esrb_watchdog_t *watchdog)
{
    if (watchdog->requests == NULL) {
        return;
    }
    pthread_cond_destroy(&watchdog->condition);
    pthread_mutex_destroy(&watchdog->mutex);
    free(watchdog->requests);
    free(watchdog->heap);
    watchdog->requests = NULL;
    watchdog->heap = NULL;
}

void
esrb_watchdog_abandon(esrb_watchdog_t *watchdog)
{
    free(watchdog->requests);
    free(watchdog->heap);
    watchdog->requests = NULL;
    watchdog->heap = NULL;
}

bool
esrb_watchdog_arm(esrb_watchdog_t *watchdog, esrb_slot_t *slot)
{
    size_t position = atomic_load_explicit(&watchdog->enqueue_position, memory_order_relaxed);
    for (;;) {
        esrb_watchdog_request_t *request = &watchdog->requests[position & watchdog->mask];
        size_t sequence = atomic_load_explicit(&request->sequence, memory_order_acquire);
        intptr_t difference = (intptr_t)sequence - (intptr_t)position;
        if (difference == 0) {
            if (atomic_compare_exchange_weak_explicit(&watchdog->enqueue_position, &position, position + 1,
                    memory_order_relaxed, memory_order_relaxed)) {
                request->slot = slot;
                request->position = slot->position;
                request->fire_at = slot->fire_at;
                atomic_store_explicit(&request->sequence, position + 1, memory_order_release);
                pthread_cond_signal(&watchdog->condition);
                return true;
            }
        } else if (difference < 0) {
            return false;
        } else {
            position = atomic_load_explicit(&watchdog->enqueue_position, memory_order_relaxed);
        }
    }
}

static void
answer_due(esrb_client_t *client, esrb_watchdog_entry_t entry)
{
    esrb_slot_t *slot = entry.slot;
    if (!atomic_load_explicit(&slot->occupied, memory_order_acquire)) {
        return;
    }
    atomic_fetch_add_explicit(&slot->readers, 1, memory_order_acquire);
    if (!atomic_load_explicit(&slot->occupied, memory_order_acquire) || slot->position != entry.position) {
        atomic_fetch_sub_explicit(&slot->readers, 1, memory_order_release);
        return;
    }
    uint32_t expected = ESRB_ANSWER_PENDING;
    if (atomic_compare_exchange_strong_explicit(
            &slot->answer_state, &expected, ESRB_ANSWER_ANSWERED, memory_order_acq_rel, memory_order_acquire)) {
        if (slot->message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
            es_respond_flags_result(slot->client, slot->message,
                client->default_auth == ES_AUTH_RESULT_ALLOW ? UINT32_MAX : 0, client->default_cache);
        } else {
            es_respond_auth_result(slot->client, slot->message, client->default_auth, client->default_cache);
        }
        atomic_fetch_add_explicit(&client->timeouts, 1, memory_order_relaxed);
        esrb_notify(client);
    }
    atomic_fetch_sub_explicit(&slot->readers, 1, memory_order_release);
}

void *
esrb_watchdog_main(void *argument)
{
    esrb_client_t *client = argument;
    esrb_watchdog_t *watchdog = &client->watchdog;
    while (atomic_load_explicit(&client->watchdog_running, memory_order_acquire)) {
        esrb_watchdog_request_t request;
        while (request_pop(watchdog, &request)) {
            heap_set(watchdog, &request);
        }
        uint64_t now = mach_absolute_time();
        while (watchdog->heap_size > 0 && watchdog->heap[0].fire_at <= now) {
            esrb_watchdog_entry_t entry = watchdog->heap[0];
            heap_remove(watchdog, 0);
            answer_due(client, entry);
            now = mach_absolute_time();
        }

        struct timespec wake;
        clock_gettime(CLOCK_REALTIME, &wake);
        wake.tv_nsec += 1000000;
        if (wake.tv_nsec >= 1000000000) {
            wake.tv_sec++;
            wake.tv_nsec -= 1000000000;
        }
        pthread_mutex_lock(&watchdog->mutex);
        pthread_cond_timedwait(&watchdog->condition, &watchdog->mutex, &wake);
        pthread_mutex_unlock(&watchdog->mutex);
    }
    return NULL;
}
