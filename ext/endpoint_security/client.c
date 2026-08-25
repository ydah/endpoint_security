/* client.c
 * Calling threads: lifecycle/control = Ruby threads with the GVL; handler = ES thread without the GVL.
 */
#include "client.h"

#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "message.h"
#include "mute.h"
#ifdef ESRB_MOCK
#include "esmock.h"
#endif

static VALUE c_client;

static void
client_drain_and_release(esrb_client_t *client)
{
    esrb_slot_t *slot;
    while ((slot = esrb_queue_dequeue(&client->queue)) != NULL) {
        uint32_t expected = ESRB_ANSWER_PENDING;
        if (atomic_compare_exchange_strong_explicit(
                &slot->answer_state, &expected, ESRB_ANSWER_ANSWERED, memory_order_acq_rel, memory_order_acquire)) {
            if (slot->message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
                es_respond_flags_result(slot->client, slot->message,
                    client->default_auth == ES_AUTH_RESULT_ALLOW ? UINT32_MAX : 0, client->default_cache);
            } else {
                es_respond_auth_result(slot->client, slot->message, client->default_auth, client->default_cache);
            }
        }
        es_release_message(slot->message);
        esrb_queue_release(&client->queue, slot);
    }
}

static void
client_close_native(esrb_client_t *client)
{
    if (atomic_exchange_explicit(&client->closed, true, memory_order_acq_rel)) {
        return;
    }

    if (atomic_exchange_explicit(&client->watchdog_running, false, memory_order_acq_rel)) {
        pthread_join(client->watchdog_thread, NULL);
    }
    if (client->client != NULL) {
        es_delete_client(client->client);
        client->client = NULL;
    }
    client_drain_and_release(client);
    esrb_notify(client);
}

static void
client_free(void *pointer)
{
    esrb_client_t *client = pointer;
    if (client->owner_pid == 0 || client->owner_pid == getpid()) {
        client_close_native(client);
    } else {
        client->client = NULL;
        atomic_store_explicit(&client->watchdog_running, false, memory_order_release);
        atomic_store_explicit(&client->closed, true, memory_order_release);
    }
    esrb_queue_destroy(&client->queue);
    if (client->wakeup_fd[0] >= 0) {
        close(client->wakeup_fd[0]);
    }
    if (client->wakeup_fd[1] >= 0) {
        close(client->wakeup_fd[1]);
    }
    xfree(client);
}

static size_t
client_size(const void *pointer)
{
    esrb_client_t const *client = pointer;
    return client == NULL ? 0 : sizeof(*client) + client->queue.capacity * sizeof(esrb_slot_t);
}

const rb_data_type_t esrb_client_type = {
    .wrap_struct_name = "EndpointSecurity::Client",
    .function = {.dfree = client_free, .dsize = client_size},
    .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE
client_allocate(VALUE klass)
{
    esrb_client_t *client;
    VALUE object = TypedData_Make_Struct(klass, esrb_client_t, &esrb_client_type, client);
    client->wakeup_fd[0] = -1;
    client->wakeup_fd[1] = -1;
    atomic_init(&client->closed, true);
    return object;
}

static esrb_client_t *
get_client(VALUE self)
{
    esrb_client_t *client;
    TypedData_Get_Struct(self, esrb_client_t, &esrb_client_type, client);
    if (client->owner_pid != getpid()) {
        rb_raise(rb_path2class("EndpointSecurity::ForkedClientError"), "Endpoint Security clients cannot be used after fork");
    }
    return client;
}

static esrb_client_t *
get_open_client(VALUE self)
{
    esrb_client_t *client = get_client(self);
    if (atomic_load_explicit(&client->closed, memory_order_acquire)) {
        rb_raise(rb_path2class("EndpointSecurity::ClientError"), "client is closed");
    }
    return client;
}

static void __attribute__((noreturn))
raise_new_client_error(es_new_client_result_t result)
{
    const char *klass;
    switch (result) {
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            klass = "EndpointSecurity::InvalidArgumentError";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            klass = "EndpointSecurity::NotEntitledError";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            klass = "EndpointSecurity::NotPermittedError";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            klass = "EndpointSecurity::NotPrivilegedError";
            break;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            klass = "EndpointSecurity::TooManyClientsError";
            break;
        default:
            klass = "EndpointSecurity::InternalError";
            break;
    }
    rb_raise(rb_path2class(klass), "es_new_client failed with result %d", result);
}

void
esrb_notify(esrb_client_t *client)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &client->notified, &expected, true, memory_order_acq_rel, memory_order_relaxed)) {
        return;
    }

    unsigned char byte = 1;
    ssize_t ignored = write(client->wakeup_fd[1], &byte, sizeof(byte));
    (void)ignored;
}

static uint64_t
deadline_fire_time(esrb_client_t *client, uint64_t deadline)
{
    uint64_t now = mach_absolute_time();
    if (deadline <= now) {
        return now;
    }
    uint64_t remaining = deadline - now;
    uint64_t advance = (uint64_t)((double)remaining * client->deadline_margin);
    if (advance < client->min_margin_ticks) {
        advance = client->min_margin_ticks;
    }
    return advance >= remaining ? now : deadline - advance;
}

static void
record_sequence_gaps(esrb_client_t *client, const es_message_t *message)
{
    if (message->version >= 4) {
        uint64_t previous = atomic_exchange_explicit(&client->last_global_seq, message->global_seq_num, memory_order_relaxed);
        bool seen = atomic_exchange_explicit(&client->seen_global_seq, true, memory_order_relaxed);
        if (seen && message->global_seq_num > previous + 1) {
            atomic_fetch_add_explicit(&client->seq_gaps, message->global_seq_num - previous - 1, memory_order_relaxed);
        }
    } else if (message->version >= 2 && message->event_type >= 0 && message->event_type < ES_EVENT_TYPE_LAST) {
        size_t index = (size_t)message->event_type;
        uint64_t previous = atomic_exchange_explicit(&client->last_event_seq[index], message->seq_num, memory_order_relaxed);
        bool seen = atomic_exchange_explicit(&client->seen_event_seq[index], true, memory_order_relaxed);
        if (seen && message->seq_num > previous + 1) {
            atomic_fetch_add_explicit(&client->seq_gaps, message->seq_num - previous - 1, memory_order_relaxed);
        }
    }
}

static void
handle_message(esrb_client_t *client, es_client_t *native_client, const es_message_t *message)
{
    record_sequence_gaps(client, message);
    es_retain_message(message);
    esrb_slot_t *slot = esrb_queue_enqueue(&client->queue);
    if (slot == NULL) {
        if (message->action_type == ES_ACTION_TYPE_AUTH) {
            if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
                es_respond_flags_result(native_client, message,
                    client->default_auth == ES_AUTH_RESULT_ALLOW ? UINT32_MAX : 0, client->default_cache);
            } else {
                es_respond_auth_result(native_client, message, client->default_auth, client->default_cache);
            }
        }
        atomic_fetch_add_explicit(&client->dropped, 1, memory_order_relaxed);
        es_release_message(message);
        return;
    }

    slot->message = message;
    slot->client = native_client;
    slot->fire_at = message->action_type == ES_ACTION_TYPE_AUTH ? deadline_fire_time(client, message->deadline) : UINT64_MAX;
    atomic_store_explicit(&slot->answer_state,
        message->action_type == ES_ACTION_TYPE_AUTH ? ESRB_ANSWER_PENDING : ESRB_ANSWER_NOT_AUTH, memory_order_relaxed);
    atomic_store_explicit(&slot->occupied, true, memory_order_release);
    esrb_queue_publish(&client->queue, slot);
    esrb_notify(client);
}

static VALUE
client_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE options;
    rb_scan_args(argc, argv, "0:", &options);
    esrb_client_t *client;
    TypedData_Get_Struct(self, esrb_client_t, &esrb_client_type, client);

    size_t queue_depth = 8192;
    client->default_auth = ES_AUTH_RESULT_ALLOW;
    client->default_cache = false;
    client->strict_cache = false;
    client->strict_version = false;
    client->warn_on_truncated_path = false;
    client->deadline_margin = 0.2;
    uint64_t min_margin_ns = 5000000ULL;
    if (!NIL_P(options)) {
        VALUE depth = rb_hash_aref(options, ID2SYM(rb_intern("queue_depth")));
        VALUE auth = rb_hash_aref(options, ID2SYM(rb_intern("auth_default")));
        VALUE margin = rb_hash_aref(options, ID2SYM(rb_intern("deadline_margin")));
        VALUE minimum = rb_hash_aref(options, ID2SYM(rb_intern("min_margin_ns")));
        VALUE strict_cache = rb_hash_aref(options, ID2SYM(rb_intern("strict_cache")));
        VALUE strict_version = rb_hash_aref(options, ID2SYM(rb_intern("strict_version")));
        VALUE default_cache = rb_hash_aref(options, ID2SYM(rb_intern("default_cache")));
        VALUE on_full = rb_hash_aref(options, ID2SYM(rb_intern("on_full")));
        VALUE warn_on_truncated_path = rb_hash_aref(options, ID2SYM(rb_intern("warn_on_truncated_path")));
        queue_depth = NIL_P(depth) ? queue_depth : NUM2SIZET(depth);
        client->deadline_margin = NIL_P(margin) ? client->deadline_margin : NUM2DBL(margin);
        min_margin_ns = NIL_P(minimum) ? min_margin_ns : NUM2ULL(minimum);
        client->strict_cache = RTEST(strict_cache);
        client->strict_version = RTEST(strict_version);
        client->default_cache = RTEST(default_cache);
        client->warn_on_truncated_path = RTEST(warn_on_truncated_path);
        if (!NIL_P(on_full)) {
            Check_Type(on_full, T_SYMBOL);
            if (SYM2ID(on_full) != rb_intern("drop") && SYM2ID(on_full) != rb_intern("respond_default")) {
                rb_raise(rb_eArgError, "on_full must be :drop or :respond_default");
            }
        }
        if (!NIL_P(auth)) {
            Check_Type(auth, T_SYMBOL);
            if (SYM2ID(auth) == rb_intern("deny")) {
                client->default_auth = ES_AUTH_RESULT_DENY;
            } else if (SYM2ID(auth) != rb_intern("allow")) {
                rb_raise(rb_eArgError, "auth_default must be :allow or :deny");
            }
        }
    }
    if (!isfinite(client->deadline_margin) || client->deadline_margin < 0.0 || client->deadline_margin > 1.0) {
        rb_raise(rb_eArgError, "deadline_margin must be between 0.0 and 1.0");
    }
    if (!esrb_queue_init(&client->queue, queue_depth)) {
        rb_raise(rb_eArgError, "queue_depth must be a power of two and at least 2");
    }
    if (pipe(client->wakeup_fd) != 0) {
        esrb_queue_destroy(&client->queue);
        rb_sys_fail("pipe");
    }
    if (fcntl(client->wakeup_fd[0], F_SETFL, O_NONBLOCK) == -1 ||
        fcntl(client->wakeup_fd[1], F_SETFL, O_NONBLOCK) == -1) {
        int error = errno;
        close(client->wakeup_fd[0]);
        close(client->wakeup_fd[1]);
        client->wakeup_fd[0] = -1;
        client->wakeup_fd[1] = -1;
        esrb_queue_destroy(&client->queue);
        errno = error;
        rb_sys_fail("fcntl");
    }

    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    client->min_margin_ticks = min_margin_ns * info.denom / info.numer;
    client->owner_pid = getpid();
    atomic_init(&client->notified, false);
    atomic_init(&client->dropped, 0);
    atomic_init(&client->delivered, 0);
    atomic_init(&client->timeouts, 0);
    atomic_init(&client->errors, 0);
    atomic_init(&client->seq_gaps, 0);
    atomic_init(&client->leaked_messages, 0);
    atomic_init(&client->last_global_seq, 0);
    atomic_init(&client->seen_global_seq, false);
    for (size_t index = 0; index < ES_EVENT_TYPE_LAST; index++) {
        atomic_init(&client->last_event_seq[index], 0);
        atomic_init(&client->seen_event_seq[index], false);
    }
    atomic_store_explicit(&client->closed, false, memory_order_release);

    es_new_client_result_t result = es_new_client(&client->client, ^(es_client_t *native, const es_message_t *message) {
      handle_message(client, native, message);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        close(client->wakeup_fd[0]);
        close(client->wakeup_fd[1]);
        client->wakeup_fd[0] = -1;
        client->wakeup_fd[1] = -1;
        esrb_queue_destroy(&client->queue);
        atomic_store_explicit(&client->closed, true, memory_order_release);
        raise_new_client_error(result);
    }

    atomic_init(&client->watchdog_running, true);
    if (pthread_create(&client->watchdog_thread, NULL, esrb_watchdog_main, client) != 0) {
        atomic_store_explicit(&client->watchdog_running, false, memory_order_release);
        client_close_native(client);
        rb_raise(rb_eRuntimeError, "failed to create Endpoint Security watchdog");
    }
    return self;
}

static VALUE
client_close(VALUE self)
{
    client_close_native(get_client(self));
    return Qnil;
}

static VALUE
client_closed_p(VALUE self)
{
    return atomic_load_explicit(&get_client(self)->closed, memory_order_acquire) ? Qtrue : Qfalse;
}

static VALUE
client_wakeup_fd(VALUE self)
{
    return INT2NUM(get_open_client(self)->wakeup_fd[0]);
}

static VALUE
client_wake(VALUE self)
{
    esrb_notify(get_client(self));
    return Qnil;
}

static VALUE
client_drain(int argc, VALUE *argv, VALUE self)
{
    VALUE maximum_value;
    rb_scan_args(argc, argv, "01", &maximum_value);
    long maximum = NIL_P(maximum_value) ? 256 : NUM2LONG(maximum_value);
    esrb_client_t *client = get_open_client(self);
    unsigned char buffer[256];
    while (read(client->wakeup_fd[0], buffer, sizeof(buffer)) > 0) {
    }

    VALUE messages = rb_ary_new_capa(maximum);
    for (long index = 0; index < maximum; index++) {
        esrb_slot_t *slot = esrb_queue_dequeue(&client->queue);
        if (slot == NULL) {
            break;
        }
        rb_ary_push(messages, esrb_message_wrap(self, client, slot));
        atomic_fetch_add_explicit(&client->delivered, 1, memory_order_relaxed);
    }

    atomic_store_explicit(&client->notified, false, memory_order_release);
    if (esrb_queue_depth(&client->queue) > 0) {
        esrb_notify(client);
    }
    return messages;
}

static VALUE
client_subscribe(VALUE self, VALUE values)
{
    esrb_client_t *client = get_open_client(self);
    Check_Type(values, T_ARRAY);
    long count = RARRAY_LEN(values);
    if (count <= 0 || count > UINT32_MAX) {
        rb_raise(rb_eArgError, "at least one event is required");
    }
    es_event_type_t *events = ALLOC_N(es_event_type_t, count);
    for (long index = 0; index < count; index++) {
        events[index] = (es_event_type_t)NUM2INT(rb_ary_entry(values, index));
    }
    es_return_t result = es_subscribe(client->client, events, (uint32_t)count);
    xfree(events);
    if (result != ES_RETURN_SUCCESS) {
        rb_raise(rb_path2class("EndpointSecurity::SubscriptionError"), "es_subscribe failed");
    }
    return Qtrue;
}

static VALUE
client_unsubscribe(VALUE self, VALUE values)
{
    esrb_client_t *client = get_open_client(self);
    if (NIL_P(values)) {
        if (es_unsubscribe_all(client->client) != ES_RETURN_SUCCESS) {
            rb_raise(rb_path2class("EndpointSecurity::SubscriptionError"), "es_unsubscribe_all failed");
        }
        return Qtrue;
    }

    Check_Type(values, T_ARRAY);
    long count = RARRAY_LEN(values);
    es_event_type_t *events = ALLOC_N(es_event_type_t, count);
    for (long index = 0; index < count; index++) {
        events[index] = (es_event_type_t)NUM2INT(rb_ary_entry(values, index));
    }
    es_return_t result = es_unsubscribe(client->client, events, (uint32_t)count);
    xfree(events);
    if (result != ES_RETURN_SUCCESS) {
        rb_raise(rb_path2class("EndpointSecurity::SubscriptionError"), "es_unsubscribe failed");
    }
    return Qtrue;
}

static VALUE
client_subscriptions(VALUE self)
{
    esrb_client_t *client = get_open_client(self);
    size_t count = 0;
    es_event_type_t *subscriptions = NULL;
    if (es_subscriptions(client->client, &count, &subscriptions) != ES_RETURN_SUCCESS) {
        rb_raise(rb_path2class("EndpointSecurity::SubscriptionError"), "es_subscriptions failed");
    }
    VALUE values = rb_ary_new_capa((long)count);
    VALUE event_type = rb_path2class("EndpointSecurity::EventType");
    for (size_t index = 0; index < count; index++) {
        rb_ary_push(values, rb_funcall(event_type, rb_intern("symbol"), 1, INT2NUM(subscriptions[index])));
    }
    free(subscriptions);
    return values;
}

static VALUE
client_stats(VALUE self)
{
    esrb_client_t *client = get_client(self);
    VALUE stats = rb_hash_new();
#define SET_STAT(name, value) rb_hash_aset(stats, ID2SYM(rb_intern(name)), ULL2NUM(value))
    SET_STAT("delivered", atomic_load_explicit(&client->delivered, memory_order_relaxed));
    SET_STAT("dropped", atomic_load_explicit(&client->dropped, memory_order_relaxed));
    SET_STAT("timeouts", atomic_load_explicit(&client->timeouts, memory_order_relaxed));
    SET_STAT("errors", atomic_load_explicit(&client->errors, memory_order_relaxed));
    SET_STAT("queue_depth_max", atomic_load_explicit(&client->queue.depth_max, memory_order_relaxed));
    SET_STAT("queue_depth", esrb_queue_depth(&client->queue));
    SET_STAT("seq_gaps", atomic_load_explicit(&client->seq_gaps, memory_order_relaxed));
    SET_STAT("leaked_messages", atomic_load_explicit(&client->leaked_messages, memory_order_relaxed));
#undef SET_STAT
    return stats;
}

bool
esrb_respond_slot(esrb_client_t *client, esrb_slot_t *slot, es_auth_result_t result, uint32_t flags, bool cache)
{
    if (atomic_load_explicit(&client->closed, memory_order_acquire)) {
        return false;
    }
    uint32_t expected = ESRB_ANSWER_PENDING;
    if (!atomic_compare_exchange_strong_explicit(
            &slot->answer_state, &expected, ESRB_ANSWER_ANSWERED, memory_order_acq_rel, memory_order_acquire)) {
        return false;
    }

    es_respond_result_t response;
    if (slot->message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        response = es_respond_flags_result(slot->client, slot->message, flags, cache);
    } else {
        response = es_respond_auth_result(slot->client, slot->message, result, cache);
    }
    return response == ES_RESPOND_RESULT_SUCCESS;
}

#ifdef ESRB_MOCK
static VALUE
mock_inject(int argc, VALUE *argv, VALUE module)
{
    (void)module;
    VALUE client_value;
    VALUE options;
    rb_scan_args(argc, argv, "1:", &client_value, &options);
    VALUE event = rb_hash_fetch(options, ID2SYM(rb_intern("event")));
    VALUE auth_value = rb_hash_aref(options, ID2SYM(rb_intern("auth")));
    VALUE deadline_ms = rb_hash_aref(options, ID2SYM(rb_intern("deadline_ms")));
    esrb_client_t *client = get_open_client(client_value);
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    uint64_t delay = NIL_P(deadline_ms) ? 1000 : NUM2ULL(deadline_ms);
    uint64_t deadline = mach_absolute_time() + delay * 1000000ULL * info.denom / info.numer;
    esmock_inject(client->client, (es_event_type_t)NUM2INT(event), RTEST(auth_value), deadline);
    return Qnil;
}

static VALUE
mock_response_count(VALUE module)
{
    (void)module;
    return SIZET2NUM(esmock_response_count());
}

static VALUE
mock_last_response(VALUE module)
{
    (void)module;
    return UINT2NUM(esmock_last_response());
}

static VALUE
mock_reset(VALUE module)
{
    (void)module;
    esmock_reset();
    return Qnil;
}
#endif

void
esrb_init_client(VALUE endpoint_security)
{
    c_client = rb_define_class_under(endpoint_security, "Client", rb_cObject);
    rb_define_alloc_func(c_client, client_allocate);
    rb_define_method(c_client, "initialize", client_initialize, -1);
    rb_define_method(c_client, "close", client_close, 0);
    rb_define_method(c_client, "closed?", client_closed_p, 0);
    rb_define_method(c_client, "__wakeup_fd", client_wakeup_fd, 0);
    rb_define_method(c_client, "__wake", client_wake, 0);
    rb_define_method(c_client, "__drain", client_drain, -1);
    rb_define_method(c_client, "__subscribe", client_subscribe, 1);
    rb_define_method(c_client, "__unsubscribe", client_unsubscribe, 1);
    rb_define_method(c_client, "__subscriptions", client_subscriptions, 0);
    rb_define_method(c_client, "stats", client_stats, 0);
    esrb_init_mute(c_client);

#ifdef ESRB_MOCK
    VALUE mock = rb_define_module_under(endpoint_security, "Mock");
    rb_define_singleton_method(mock, "inject", mock_inject, -1);
    rb_define_singleton_method(mock, "response_count", mock_response_count, 0);
    rb_define_singleton_method(mock, "last_response", mock_last_response, 0);
    rb_define_singleton_method(mock, "reset", mock_reset, 0);
#endif
}
