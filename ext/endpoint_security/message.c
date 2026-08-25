/* message.c
 * Calling thread: Ruby dispatcher with the GVL.
 */
#include "message.h"

#include <mach/mach_time.h>

typedef struct {
    VALUE owner;
    esrb_client_t *client;
    esrb_slot_t *slot;
    bool valid;
    bool held;
} esrb_message_t;

static VALUE c_message;

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
    es_release_message(message->slot->message);
    esrb_queue_release(&message->client->queue, message->slot);
    message->valid = false;
}

static void
message_free(void *pointer)
{
    esrb_message_t *message = pointer;
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
    return ID2SYM(rb_intern(get_message(self)->slot->message->action_type == ES_ACTION_TYPE_AUTH ? "auth" : "notify"));
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
    return message->valid ? Qtrue : Qfalse;
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
    rb_define_method(c_message, "time_left", message_time_left, 0);
    rb_define_method(c_message, "answered?", message_answered_p, 0);
    rb_define_method(c_message, "allow!", message_allow, -1);
    rb_define_method(c_message, "deny!", message_deny, -1);
    rb_define_method(c_message, "respond", message_respond, -1);
    rb_define_method(c_message, "retain!", message_retain, 0);
    rb_define_method(c_message, "release!", message_release_bang, 0);
    rb_define_method(c_message, "valid?", message_valid_p, 0);
    rb_define_method(c_message, "__respond_default!", message_respond_default, 0);
    rb_define_method(c_message, "__auto_release!", message_auto_release, 0);
}
