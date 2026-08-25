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
    bool subscriptions[ES_EVENT_TYPE_LAST];
};

typedef struct {
    _Atomic size_t references;
    es_process_t process;
    es_process_t target;
    es_file_t executable;
    es_file_t target_executable;
    struct statfs statfs;
    es_event_gatekeeper_user_override_t gatekeeper;
    es_sha256_t sha256;
    es_message_t message;
} mock_message_t;

static _Atomic size_t responses;
static _Atomic uint32_t last_response;
static _Atomic bool inverted[3];

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
    if (client == NULL || events == NULL || event_count == 0) {
        return ES_RETURN_ERROR;
    }
    for (uint32_t index = 0; index < event_count; index++) {
        if (events[index] < 0 || events[index] >= ES_EVENT_TYPE_LAST) {
            return ES_RETURN_ERROR;
        }
        client->subscriptions[events[index]] = true;
    }
    return ES_RETURN_SUCCESS;
}

es_return_t
es_unsubscribe(es_client_t *client, const es_event_type_t *events, uint32_t event_count)
{
    if (client == NULL || events == NULL || event_count == 0) {
        return ES_RETURN_ERROR;
    }
    for (uint32_t index = 0; index < event_count; index++) {
        if (events[index] < 0 || events[index] >= ES_EVENT_TYPE_LAST) {
            return ES_RETURN_ERROR;
        }
        client->subscriptions[events[index]] = false;
    }
    return ES_RETURN_SUCCESS;
}

es_return_t
es_unsubscribe_all(es_client_t *client)
{
    if (client == NULL) {
        return ES_RETURN_ERROR;
    }
    memset(client->subscriptions, 0, sizeof(client->subscriptions));
    return ES_RETURN_SUCCESS;
}

es_return_t
es_subscriptions(es_client_t *client, size_t *count, es_event_type_t **subscriptions)
{
    if (client == NULL || count == NULL || subscriptions == NULL) {
        return ES_RETURN_ERROR;
    }
    *count = 0;
    for (size_t index = 0; index < ES_EVENT_TYPE_LAST; index++) {
        *count += client->subscriptions[index] ? 1 : 0;
    }
    *subscriptions = *count == 0 ? NULL : malloc(*count * sizeof(**subscriptions));
    if (*count > 0 && *subscriptions == NULL) {
        return ES_RETURN_ERROR;
    }
    size_t output = 0;
    for (size_t index = 0; index < ES_EVENT_TYPE_LAST; index++) {
        if (client->subscriptions[index]) {
            (*subscriptions)[output++] = (es_event_type_t)index;
        }
    }
    return ES_RETURN_SUCCESS;
}

es_return_t
es_mute_process(es_client_t *client, const audit_token_t *token)
{
    return client != NULL && token != NULL ? ES_RETURN_SUCCESS : ES_RETURN_ERROR;
}

es_return_t
es_unmute_process(es_client_t *client, const audit_token_t *token)
{
    return es_mute_process(client, token);
}

es_return_t
es_mute_process_events(es_client_t *client, const audit_token_t *token, const es_event_type_t *events, size_t count)
{
    return client != NULL && token != NULL && events != NULL && count > 0 ? ES_RETURN_SUCCESS : ES_RETURN_ERROR;
}

es_return_t
es_unmute_process_events(es_client_t *client, const audit_token_t *token, const es_event_type_t *events, size_t count)
{
    return es_mute_process_events(client, token, events, count);
}

es_return_t
es_mute_path(es_client_t *client, const char *path, es_mute_path_type_t type)
{
    (void)type;
    return client != NULL && path != NULL ? ES_RETURN_SUCCESS : ES_RETURN_ERROR;
}

es_return_t
es_unmute_path(es_client_t *client, const char *path, es_mute_path_type_t type)
{
    return es_mute_path(client, path, type);
}

es_return_t
es_mute_path_events(
    es_client_t *client, const char *path, es_mute_path_type_t type, const es_event_type_t *events, size_t count)
{
    (void)type;
    return client != NULL && path != NULL && events != NULL && count > 0 ? ES_RETURN_SUCCESS : ES_RETURN_ERROR;
}

es_return_t
es_unmute_path_events(
    es_client_t *client, const char *path, es_mute_path_type_t type, const es_event_type_t *events, size_t count)
{
    return es_mute_path_events(client, path, type, events, count);
}

es_return_t
es_unmute_all_paths(es_client_t *client)
{
    return client == NULL ? ES_RETURN_ERROR : ES_RETURN_SUCCESS;
}

es_return_t
es_unmute_all_target_paths(es_client_t *client)
{
    return es_unmute_all_paths(client);
}

es_return_t
es_invert_muting(es_client_t *client, es_mute_inversion_type_t type)
{
    if (client == NULL || type < 0 || type >= ES_MUTE_INVERSION_TYPE_LAST) {
        return ES_RETURN_ERROR;
    }
    atomic_fetch_xor_explicit(&inverted[type], true, memory_order_relaxed);
    return ES_RETURN_SUCCESS;
}

es_mute_inverted_return_t
es_muting_inverted(es_client_t *client, es_mute_inversion_type_t type)
{
    if (client == NULL || type < 0 || type >= ES_MUTE_INVERSION_TYPE_LAST) {
        return ES_MUTE_INVERTED_ERROR;
    }
    return atomic_load_explicit(&inverted[type], memory_order_relaxed) ? ES_MUTE_INVERTED : ES_MUTE_NOT_INVERTED;
}

es_clear_cache_result_t
es_clear_cache(es_client_t *client)
{
    return client == NULL ? ES_CLEAR_CACHE_RESULT_ERR_INTERNAL : ES_CLEAR_CACHE_RESULT_SUCCESS;
}

es_return_t
es_muted_paths_events(es_client_t *client, es_muted_paths_t **paths)
{
    if (client == NULL || paths == NULL) {
        return ES_RETURN_ERROR;
    }
    *paths = calloc(1, sizeof(**paths));
    return *paths == NULL ? ES_RETURN_ERROR : ES_RETURN_SUCCESS;
}

void
es_release_muted_paths(es_muted_paths_t *paths)
{
    free(paths);
}

es_return_t
es_muted_processes_events(es_client_t *client, es_muted_processes_t **processes)
{
    if (client == NULL || processes == NULL) {
        return ES_RETURN_ERROR;
    }
    *processes = calloc(1, sizeof(**processes));
    return *processes == NULL ? ES_RETURN_ERROR : ES_RETURN_SUCCESS;
}

void
es_release_muted_processes(es_muted_processes_t *processes)
{
    free(processes);
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
    static const char executable_path[] = "/usr/bin/mock-source";
    static const char target_path[] = "/usr/bin/mock-target";
    mock->executable.path.data = executable_path;
    mock->executable.path.length = sizeof(executable_path) - 1;
    mock->executable.path_truncated = true;
    mock->target_executable.path.data = target_path;
    mock->target_executable.path.length = sizeof(target_path) - 1;
    mock->target_executable.path_truncated = true;
    mock->process.executable = &mock->executable;
    mock->target.executable = &mock->target_executable;
    mock->process.cdhash[0] = 0xff;
    mock->target.cdhash[0] = 0xff;
    mock->message.process = &mock->process;
    mock->message.event_type = event_type;
    mock->message.action_type = auth ? ES_ACTION_TYPE_AUTH : ES_ACTION_TYPE_NOTIFY;
    if (event_type == ES_EVENT_TYPE_AUTH_EXEC || event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
        mock->message.event.exec.target = &mock->target;
    }
    if (event_type == ES_EVENT_TYPE_NOTIFY_MOUNT) {
        mock->statfs.f_bsize = 4096;
        memcpy(mock->statfs.f_fstypename, "mockfs", sizeof("mockfs"));
        mock->message.event.mount.statfs = &mock->statfs;
    }
    if (event_type == ES_EVENT_TYPE_NOTIFY_GETATTRLIST) {
        mock->message.event.getattrlist.attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
        mock->message.event.getattrlist.attrlist.commonattr = 1;
    }
    if (event_type == ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE) {
        mock->sha256[0] = 0xff;
        mock->gatekeeper.sha256 = &mock->sha256;
        mock->message.event.gatekeeper_user_override = &mock->gatekeeper;
    }
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
    for (size_t index = 0; index < 3; index++) {
        atomic_store_explicit(&inverted[index], false, memory_order_relaxed);
    }
}

uint32_t
es_exec_arg_count(const es_event_exec_t *event)
{
    (void)event;
    return 0;
}

uint32_t
es_exec_env_count(const es_event_exec_t *event)
{
    (void)event;
    return 0;
}

uint32_t
es_exec_fd_count(const es_event_exec_t *event)
{
    (void)event;
    return 0;
}

es_string_token_t
es_exec_arg(const es_event_exec_t *event, uint32_t index)
{
    (void)event;
    (void)index;
    return (es_string_token_t){0};
}

es_string_token_t
es_exec_env(const es_event_exec_t *event, uint32_t index)
{
    (void)event;
    (void)index;
    return (es_string_token_t){0};
}

const es_fd_t *
es_exec_fd(const es_event_exec_t *event, uint32_t index)
{
    static const es_fd_t empty = {0};
    (void)event;
    (void)index;
    return &empty;
}
