/* message.c
 * Calling thread: Ruby dispatcher with the GVL.
 */
#include "message.h"

#include <mach/mach_time.h>
#include <unistd.h>

#include "field.h"

typedef struct {
    VALUE owner;
    esrb_client_t *client;
    esrb_slot_t *slot;
    bool valid;
    bool held;
} esrb_message_t;

static VALUE c_message;

static bool
message_owned_here(const esrb_message_t *message)
{
    return message->client->owner_pid == getpid();
}

static void
message_mark(void *pointer)
{
    esrb_message_t *message = pointer;
    rb_gc_mark(message->owner);
}

static void
message_release(esrb_message_t *message)
{
    if (!message->valid) {
        return;
    }
    if (!message_owned_here(message)) {
        message->valid = false;
        return;
    }
    uint32_t flags = message->client->default_auth == ES_AUTH_RESULT_ALLOW ? UINT32_MAX : 0;
    esrb_respond_slot(
        message->client, message->slot, message->client->default_auth, flags, message->client->default_cache);
    esrb_queue_disarm(message->slot);
    es_release_message(message->slot->message);
    esrb_queue_release(&message->client->queue, message->slot);
    message->valid = false;
}

static void
message_free(void *pointer)
{
    esrb_message_t *message = pointer;
    if (message->valid && message->held && message_owned_here(message)) {
        atomic_fetch_add_explicit(&message->client->leaked_messages, 1, memory_order_relaxed);
    }
    message_release(message);
    xfree(message);
}

static size_t
message_size(const void *pointer)
{
    return pointer == NULL ? 0 : sizeof(esrb_message_t);
}

static const rb_data_type_t message_type = {
    .wrap_struct_name = "EndpointSecurity::Message",
    .function = {.dmark = message_mark, .dfree = message_free, .dsize = message_size},
    .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static esrb_message_t *
get_message(VALUE self)
{
    esrb_message_t *message;
    TypedData_Get_Struct(self, esrb_message_t, &message_type, message);
    if (!message_owned_here(message)) {
        rb_raise(rb_path2class("EndpointSecurity::ForkedClientError"), "Endpoint Security messages cannot be used after fork");
    }
    if (!message->valid) {
        rb_raise(rb_path2class("EndpointSecurity::MessageInvalidatedError"), "message has been released");
    }
    return message;
}

static VALUE
message_version(VALUE self)
{
    return UINT2NUM(get_message(self)->slot->message->version);
}

static VALUE
message_event_type(VALUE self)
{
    es_event_type_t event = get_message(self)->slot->message->event_type;
    VALUE event_type = rb_path2class("EndpointSecurity::EventType");
    return rb_funcall(event_type, rb_intern("symbol"), 1, INT2NUM(event));
}

static VALUE
message_action_type(VALUE self)
{
    es_action_type_t action = get_message(self)->slot->message->action_type;
    if (action == ES_ACTION_TYPE_AUTH) {
        return ID2SYM(rb_intern("auth"));
    }
    if (action == ES_ACTION_TYPE_NOTIFY) {
        return ID2SYM(rb_intern("notify"));
    }
    return INT2NUM(action);
}

static VALUE
message_auth_p(VALUE self)
{
    return get_message(self)->slot->message->action_type == ES_ACTION_TYPE_AUTH ? Qtrue : Qfalse;
}

static VALUE
message_deadline(VALUE self)
{
    return ULL2NUM(get_message(self)->slot->message->deadline);
}

static VALUE
message_mach_time(VALUE self)
{
    return ULL2NUM(get_message(self)->slot->message->mach_time);
}

static VALUE
message_seq_num(VALUE self)
{
    const es_message_t *message = get_message(self)->slot->message;
    return message->version >= 2 ? ULL2NUM(message->seq_num) : Qnil;
}

static VALUE
message_global_seq_num(VALUE self)
{
    const es_message_t *message = get_message(self)->slot->message;
    return message->version >= 4 ? ULL2NUM(message->global_seq_num) : Qnil;
}

static VALUE
message_time(VALUE self)
{
    const es_message_t *message = get_message(self)->slot->message;
    return rb_time_nano_new(message->time.tv_sec, message->time.tv_nsec);
}

static VALUE
message_process(VALUE self)
{
    esrb_message_t *wrapper = get_message(self);
    const es_message_t *message = wrapper->slot->message;
    return esrb_view_wrap(self, message->process, "es_process_t", message->version, wrapper->client->strict_version);
}

static VALUE
message_thread(VALUE self)
{
    esrb_message_t *wrapper = get_message(self);
    const es_message_t *message = wrapper->slot->message;
    return message->version >= 4
        ? esrb_view_wrap(self, message->thread, "es_thread_t", message->version, wrapper->client->strict_version)
        : Qnil;
}

static VALUE
message_event(VALUE self)
{
    esrb_message_t *wrapper = get_message(self);
    return esrb_event_wrap(self, wrapper->slot->message, wrapper->client->strict_version);
}

static VALUE
message_result(VALUE self)
{
    const es_message_t *message = get_message(self)->slot->message;
    if (message->action_type == ES_ACTION_TYPE_AUTH) {
        return Qnil;
    }
    if (message->action_type != ES_ACTION_TYPE_NOTIFY) {
        return Qnil;
    }
    switch (message->action.notify.result_type) {
        case ES_RESULT_TYPE_FLAGS:
            return UINT2NUM(message->action.notify.result.flags);
        case ES_RESULT_TYPE_AUTH:
            if (message->action.notify.result.auth == ES_AUTH_RESULT_ALLOW) {
                return ID2SYM(rb_intern("allow"));
            }
            if (message->action.notify.result.auth == ES_AUTH_RESULT_DENY) {
                return ID2SYM(rb_intern("deny"));
            }
            return INT2NUM(message->action.notify.result.auth);
        default:
            return INT2NUM(message->action.notify.result_type);
    }
}

static VALUE
message_raw_pointer(VALUE self)
{
    return ULL2NUM((uintptr_t)get_message(self)->slot->message);
}

static VALUE
message_raw_event_bytes(VALUE self)
{
    const es_message_t *message = get_message(self)->slot->message;
    return rb_str_new((const char *)&message->event, sizeof(message->event));
}

static VALUE
message_time_left(VALUE self)
{
    esrb_message_t *message = get_message(self);
    uint64_t now = mach_absolute_time();
    uint64_t deadline = message->slot->message->deadline;
    if (deadline <= now) {
        return DBL2NUM(0.0);
    }
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    double seconds = (double)(deadline - now) * (double)info.numer / (double)info.denom / 1000000000.0;
    return DBL2NUM(seconds);
}

static VALUE
message_answered_p(VALUE self)
{
    esrb_message_t *message = get_message(self);
    return atomic_load_explicit(&message->slot->answer_state, memory_order_acquire) == ESRB_ANSWER_ANSWERED ? Qtrue : Qfalse;
}

static VALUE
respond_auth(int argc, VALUE *argv, VALUE self, es_auth_result_t result)
{
    VALUE options;
    rb_scan_args(argc, argv, "0:", &options);
    bool cache = true;
    if (!NIL_P(options)) {
        VALUE cache_value = rb_hash_aref(options, ID2SYM(rb_intern("cache")));
        cache = NIL_P(cache_value) || RTEST(cache_value);
    }
    esrb_message_t *message = get_message(self);
    if (cache) {
        VALUE event_type = rb_path2class("EndpointSecurity::EventType");
        VALUE event = rb_funcall(event_type, rb_intern("symbol"), 1, INT2NUM(message->slot->message->event_type));
        if (!RTEST(rb_funcall(event_type, rb_intern("cacheable?"), 1, event))) {
            if (message->client->strict_cache) {
                rb_raise(rb_path2class("EndpointSecurity::NonCacheableEventError"), "event cannot be cached");
            }
            rb_warn("Endpoint Security event cannot be cached; using cache: false");
            cache = false;
        }
    }
    uint32_t flags = result == ES_AUTH_RESULT_ALLOW ? UINT32_MAX : 0;
    return esrb_respond_slot(message->client, message->slot, result, flags, cache) ? Qtrue : Qfalse;
}

static VALUE
message_allow(int argc, VALUE *argv, VALUE self)
{
    return respond_auth(argc, argv, self, ES_AUTH_RESULT_ALLOW);
}

static VALUE
message_deny(int argc, VALUE *argv, VALUE self)
{
    return respond_auth(argc, argv, self, ES_AUTH_RESULT_DENY);
}

static VALUE
message_respond(int argc, VALUE *argv, VALUE self)
{
    VALUE options;
    rb_scan_args(argc, argv, "0:", &options);
    VALUE flags = rb_hash_fetch(options, ID2SYM(rb_intern("flags")));
    VALUE cache_value = rb_hash_aref(options, ID2SYM(rb_intern("cache")));
    bool cache = NIL_P(cache_value) || RTEST(cache_value);
    esrb_message_t *message = get_message(self);
    if (message->slot->message->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
        rb_raise(rb_path2class("EndpointSecurity::MessageError"), "flags responses are only valid for AUTH_OPEN");
    }
    return esrb_respond_slot(message->client, message->slot, ES_AUTH_RESULT_ALLOW, NUM2UINT(flags), cache) ? Qtrue : Qfalse;
}

static VALUE
message_respond_default(VALUE self)
{
    esrb_message_t *message = get_message(self);
    uint32_t flags = message->client->default_auth == ES_AUTH_RESULT_ALLOW ? UINT32_MAX : 0;
    return esrb_respond_slot(
        message->client, message->slot, message->client->default_auth, flags, message->client->default_cache)
        ? Qtrue
        : Qfalse;
}

static VALUE
message_retain(VALUE self)
{
    get_message(self)->held = true;
    return self;
}

static VALUE
message_release_bang(VALUE self)
{
    esrb_message_t *message;
    TypedData_Get_Struct(self, esrb_message_t, &message_type, message);
    if (!message_owned_here(message)) {
        rb_raise(rb_path2class("EndpointSecurity::ForkedClientError"), "Endpoint Security messages cannot be used after fork");
    }
    message_release(message);
    return Qnil;
}

static VALUE
message_auto_release(VALUE self)
{
    esrb_message_t *message;
    TypedData_Get_Struct(self, esrb_message_t, &message_type, message);
    if (!message->held) {
        message_release(message);
    }
    return Qnil;
}

static VALUE
message_valid_p(VALUE self)
{
    esrb_message_t *message;
    TypedData_Get_Struct(self, esrb_message_t, &message_type, message);
    if (!message_owned_here(message)) {
        rb_raise(rb_path2class("EndpointSecurity::ForkedClientError"), "Endpoint Security messages cannot be used after fork");
    }
    return message->valid ? Qtrue : Qfalse;
}

static VALUE
message_warn_on_truncated_path(VALUE self)
{
    return get_message(self)->client->warn_on_truncated_path ? Qtrue : Qfalse;
}

VALUE
esrb_message_wrap(VALUE owner, esrb_client_t *client, esrb_slot_t *slot)
{
    esrb_message_t *message;
    VALUE object = TypedData_Make_Struct(c_message, esrb_message_t, &message_type, message);
    message->owner = owner;
    message->client = client;
    message->slot = slot;
    message->valid = true;
    message->held = false;
    return object;
}

bool
esrb_message_valid_object(VALUE object)
{
    esrb_message_t *message;
    if (!rb_typeddata_is_kind_of(object, &message_type)) {
        return false;
    }
    TypedData_Get_Struct(object, esrb_message_t, &message_type, message);
    if (!message_owned_here(message)) {
        rb_raise(rb_path2class("EndpointSecurity::ForkedClientError"), "Endpoint Security messages cannot be used after fork");
    }
    return message->valid;
}

void
esrb_init_message(VALUE endpoint_security)
{
    c_message = rb_define_class_under(endpoint_security, "Message", rb_cObject);
    rb_undef_alloc_func(c_message);
    rb_define_method(c_message, "version", message_version, 0);
    rb_define_method(c_message, "event_type", message_event_type, 0);
    rb_define_method(c_message, "action_type", message_action_type, 0);
    rb_define_method(c_message, "auth?", message_auth_p, 0);
    rb_define_method(c_message, "deadline", message_deadline, 0);
    rb_define_method(c_message, "mach_time", message_mach_time, 0);
    rb_define_method(c_message, "seq_num", message_seq_num, 0);
    rb_define_method(c_message, "global_seq_num", message_global_seq_num, 0);
    rb_define_method(c_message, "time", message_time, 0);
    rb_define_method(c_message, "process", message_process, 0);
    rb_define_method(c_message, "thread", message_thread, 0);
    rb_define_method(c_message, "event", message_event, 0);
    rb_define_method(c_message, "result", message_result, 0);
    rb_define_method(c_message, "raw_event_bytes", message_raw_event_bytes, 0);
    rb_define_method(c_message, "raw_pointer", message_raw_pointer, 0);
    rb_define_method(c_message, "time_left", message_time_left, 0);
    rb_define_method(c_message, "answered?", message_answered_p, 0);
    rb_define_method(c_message, "allow!", message_allow, -1);
    rb_define_method(c_message, "deny!", message_deny, -1);
    rb_define_method(c_message, "respond", message_respond, -1);
    rb_define_method(c_message, "retain!", message_retain, 0);
    rb_define_method(c_message, "release!", message_release_bang, 0);
    rb_define_method(c_message, "valid?", message_valid_p, 0);
    rb_define_method(c_message, "__warn_on_truncated_path?", message_warn_on_truncated_path, 0);
    rb_define_method(c_message, "__respond_default!", message_respond_default, 0);
    rb_define_method(c_message, "__auto_release!", message_auto_release, 0);
}
