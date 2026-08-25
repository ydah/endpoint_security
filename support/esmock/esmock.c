/* esmock.c
 * Calling threads: tests invoke injection; the copied ES handler may enqueue without the GVL.
 */
#include "esmock.h"

#include <Block.h>
#include <mach/mach_time.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct es_client_s {
    es_handler_block_t handler;
};

typedef struct {
    _Atomic size_t references;
    es_message_t message;
} mock_message_t;

static _Atomic size_t responses;
static _Atomic uint32_t last_response;

static mock_message_t *
mock_from_message(const es_message_t *message)
{
    return (mock_message_t *)((char *)message - offsetof(mock_message_t, message));
}

es_new_client_result_t
es_new_client(es_client_t **client, es_handler_block_t handler)
{
    *client = calloc(1, sizeof(**client));
    if (*client == NULL) {
        return ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    }
    (*client)->handler = Block_copy(handler);
    return ES_NEW_CLIENT_RESULT_SUCCESS;
}

es_return_t
es_delete_client(es_client_t *client)
{
    if (client == NULL) {
        return ES_RETURN_ERROR;
    }
    Block_release(client->handler);
    free(client);
    return ES_RETURN_SUCCESS;
}

es_return_t
es_subscribe(es_client_t *client, const es_event_type_t *events, uint32_t event_count)
{
    return client != NULL && events != NULL && event_count > 0 ? ES_RETURN_SUCCESS : ES_RETURN_ERROR;
}

es_return_t
es_unsubscribe(es_client_t *client, const es_event_type_t *events, uint32_t event_count)
{
    return client != NULL && events != NULL && event_count > 0 ? ES_RETURN_SUCCESS : ES_RETURN_ERROR;
}

es_return_t
es_unsubscribe_all(es_client_t *client)
{
    return client == NULL ? ES_RETURN_ERROR : ES_RETURN_SUCCESS;
}

es_respond_result_t
es_respond_auth_result(es_client_t *client, const es_message_t *message, es_auth_result_t result, bool cache)
{
    (void)cache;
    if (client == NULL || message == NULL) {
        return ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT;
    }
    atomic_store_explicit(&last_response, (uint32_t)result, memory_order_relaxed);
    atomic_fetch_add_explicit(&responses, 1, memory_order_relaxed);
    return ES_RESPOND_RESULT_SUCCESS;
}

es_respond_result_t
es_respond_flags_result(es_client_t *client, const es_message_t *message, uint32_t flags, bool cache)
{
    (void)cache;
    if (client == NULL || message == NULL) {
        return ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT;
    }
    atomic_store_explicit(&last_response, flags, memory_order_relaxed);
    atomic_fetch_add_explicit(&responses, 1, memory_order_relaxed);
    return ES_RESPOND_RESULT_SUCCESS;
}

void
es_retain_message(const es_message_t *message)
{
    atomic_fetch_add_explicit(&mock_from_message(message)->references, 1, memory_order_relaxed);
}

void
es_release_message(const es_message_t *message)
{
    mock_message_t *mock = mock_from_message(message);
    if (atomic_fetch_sub_explicit(&mock->references, 1, memory_order_acq_rel) == 1) {
        free(mock);
    }
}

void
esmock_inject(es_client_t *client, es_event_type_t event_type, bool auth, uint64_t deadline)
{
    mock_message_t *mock = calloc(1, sizeof(*mock));
    atomic_init(&mock->references, 1);
    mock->message.version = 4;
    clock_gettime(CLOCK_REALTIME, &mock->message.time);
    mock->message.mach_time = mach_absolute_time();
    mock->message.deadline = deadline;
    mock->message.event_type = event_type;
    mock->message.action_type = auth ? ES_ACTION_TYPE_AUTH : ES_ACTION_TYPE_NOTIFY;
    client->handler(client, &mock->message);
    es_release_message(&mock->message);
}

size_t
esmock_response_count(void)
{
    return atomic_load_explicit(&responses, memory_order_relaxed);
}

uint32_t
esmock_last_response(void)
{
    return atomic_load_explicit(&last_response, memory_order_relaxed);
}

void
esmock_reset(void)
{
    atomic_store_explicit(&responses, 0, memory_order_relaxed);
    atomic_store_explicit(&last_response, 0, memory_order_relaxed);
}
