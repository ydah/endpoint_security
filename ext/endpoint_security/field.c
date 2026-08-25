/* field.c
 * Calling thread: Ruby dispatcher with the GVL. Every view retains its owning Message.
 */
#include "field.h"

#include <bsm/libbsm.h>
#include <ruby/encoding.h>
#include <string.h>

#include "message.h"

typedef struct {
    VALUE owner;
    const unsigned char *pointer;
    const esrb_schema_t *schema;
    uint32_t message_version;
    bool strict_version;
} esrb_view_t;

static VALUE c_native_view;

static const esrb_schema_t *
find_schema(const char *name)
{
    for (size_t index = 0; index < esrb_schema_count; index++) {
        if (strcmp(esrb_schemas[index].name, name) == 0) {
            return &esrb_schemas[index];
        }
    }
    return NULL;
}

static void
view_mark(void *pointer)
{
    esrb_view_t *view = pointer;
    rb_gc_mark(view->owner);
}

static void
view_free(void *pointer)
{
    xfree(pointer);
}

static size_t
view_size(const void *pointer)
{
    return pointer == NULL ? 0 : sizeof(esrb_view_t);
}

static const rb_data_type_t view_type = {
    .wrap_struct_name = "EndpointSecurity::NativeView",
    .function = {.dmark = view_mark, .dfree = view_free, .dsize = view_size},
    .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static esrb_view_t *
get_view(VALUE self)
{
    esrb_view_t *view;
    TypedData_Get_Struct(self, esrb_view_t, &view_type, view);
    if (!esrb_message_valid_object(view->owner)) {
        rb_raise(rb_path2class("EndpointSecurity::MessageInvalidatedError"), "message has been released");
    }
    return view;
}

static VALUE
class_for_schema(const char *schema)
{
    if (strcmp(schema, "es_process_t") == 0) {
        return rb_path2class("EndpointSecurity::Process");
    }
    if (strcmp(schema, "es_file_t") == 0) {
        return rb_path2class("EndpointSecurity::File");
    }
    if (strcmp(schema, "es_thread_t") == 0) {
        return rb_path2class("EndpointSecurity::Thread");
    }
    return strncmp(schema, "es_event_", 9) == 0 ? rb_path2class("EndpointSecurity::Event") : c_native_view;
}

VALUE
esrb_view_wrap(VALUE owner, const void *pointer, const char *schema_name, uint32_t message_version, bool strict_version)
{
    if (pointer == NULL) {
        return Qnil;
    }
    const esrb_schema_t *schema = find_schema(schema_name);
    if (schema == NULL) {
        return Qnil;
    }

    esrb_view_t *view;
    VALUE object = TypedData_Make_Struct(class_for_schema(schema_name), esrb_view_t, &view_type, view);
    view->owner = owner;
    view->pointer = pointer;
    view->schema = schema;
    view->message_version = message_version;
    view->strict_version = strict_version;
    return object;
}

static VALUE
time_value(time_t seconds, long nanoseconds)
{
    return rb_time_nano_new(seconds, nanoseconds);
}

static VALUE
string_token_value(const es_string_token_t *token)
{
    VALUE string = token->data == NULL ? rb_str_new("", 0) : rb_str_new(token->data, (long)token->length);
    VALUE mode = rb_funcall(rb_path2class("EndpointSecurity"), rb_intern("string_encoding"), 0);
    rb_enc_associate(string, mode == ID2SYM(rb_intern("binary")) ? rb_ascii8bit_encoding() : rb_utf8_encoding());
    return string;
}

static VALUE
audit_token_value(const audit_token_t *token)
{
    VALUE arguments[] = {
        UINT2NUM(audit_token_to_pid(*token)),
        UINT2NUM(audit_token_to_pidversion(*token)),
        UINT2NUM(audit_token_to_ruid(*token)),
        UINT2NUM(audit_token_to_euid(*token)),
        UINT2NUM(audit_token_to_rgid(*token)),
        UINT2NUM(audit_token_to_egid(*token)),
        UINT2NUM(audit_token_to_asid(*token)),
        UINT2NUM(audit_token_to_auid(*token))
    };
    return rb_funcallv(rb_path2class("EndpointSecurity::AuditToken"), rb_intern("__native_new"), 8, arguments);
}

static VALUE
stat_value(const struct stat *stat)
{
    VALUE arguments[] = {
        ULL2NUM(stat->st_dev), ULL2NUM(stat->st_ino), UINT2NUM(stat->st_mode), UINT2NUM(stat->st_nlink),
        UINT2NUM(stat->st_uid), UINT2NUM(stat->st_gid), ULL2NUM(stat->st_rdev), LL2NUM(stat->st_size),
        LL2NUM(stat->st_blocks), LONG2NUM(stat->st_blksize), time_value(stat->st_atimespec.tv_sec, stat->st_atimespec.tv_nsec),
        time_value(stat->st_mtimespec.tv_sec, stat->st_mtimespec.tv_nsec),
        time_value(stat->st_ctimespec.tv_sec, stat->st_ctimespec.tv_nsec),
        time_value(stat->st_birthtimespec.tv_sec, stat->st_birthtimespec.tv_nsec)
    };
    return rb_funcallv(rb_path2class("EndpointSecurity::Stat"), rb_intern("__native_new"), 14, arguments);
}

static const esrb_field_t *
find_field(const esrb_view_t *view, const char *name)
{
    for (size_t index = 0; index < view->schema->field_count; index++) {
        if (strcmp(view->schema->fields[index].name, name) == 0) {
            return &view->schema->fields[index];
        }
    }
    return NULL;
}

static void
referenced_schema_name(const char *type, char *name, size_t capacity)
{
    if (strncmp(type, "union ", 6) == 0 || strncmp(type, "struct ", 7) == 0) {
        name[0] = '\0';
        return;
    }
    const char *start = strstr(type, "es_");
    const char *end = start == NULL ? NULL : strstr(start, "_t");
    if (end == NULL || (size_t)(end + 2 - start) >= capacity) {
        name[0] = '\0';
        return;
    }
    size_t length = (size_t)(end + 2 - start);
    memcpy(name, start, length);
    name[length] = '\0';
}

static VALUE
read_field(VALUE self, VALUE name_value)
{
    esrb_view_t *view = get_view(self);
    const char *name = StringValueCStr(name_value);
    const esrb_field_t *field = find_field(view, name);
    if (field == NULL) {
        return Qundef;
    }
    if (field->minimum_version > view->message_version) {
        if (view->strict_version) {
            rb_raise(rb_path2class("EndpointSecurity::FieldUnavailableError"),
                "%s requires message version %u (got %u)", field->name, field->minimum_version, view->message_version);
        }
        return Qnil;
    }

    const unsigned char *address = view->pointer + field->offset;
    const char *type = field->type;
    if (strcmp(type, "es_string_token_t") == 0) {
        return string_token_value((const es_string_token_t *)address);
    }
    if (strcmp(type, "es_string_token_t *") == 0) {
        const es_string_token_t *token = *(const es_string_token_t *const *)address;
        return token == NULL ? Qnil : string_token_value(token);
    }
    if (strcmp(type, "es_token_t") == 0) {
        const es_token_t *token = (const es_token_t *)address;
        return token->data == NULL ? rb_str_new("", 0) : rb_str_new((const char *)token->data, (long)token->size);
    }
    if (strcmp(type, "audit_token_t") == 0) {
        return audit_token_value((const audit_token_t *)address);
    }
    if (strcmp(type, "audit_token_t *") == 0) {
        const audit_token_t *token = *(const audit_token_t *const *)address;
        return token == NULL ? Qnil : audit_token_value(token);
    }
    if (strcmp(type, "struct stat") == 0) {
        return stat_value((const struct stat *)address);
    }
    if (strcmp(type, "struct timespec") == 0) {
        const struct timespec *time = (const struct timespec *)address;
        return time_value(time->tv_sec, time->tv_nsec);
    }
    if (strcmp(type, "struct timeval") == 0) {
        const struct timeval *time = (const struct timeval *)address;
        return time_value(time->tv_sec, time->tv_usec * 1000L);
    }
    if (strcmp(type, "bool") == 0 || strcmp(type, "_Bool") == 0) {
        return *(const bool *)address ? Qtrue : Qfalse;
    }
    if (strstr(type, "[20]") != NULL) {
        return rb_str_new((const char *)address, 20);
    }

    char schema_name[128];
    referenced_schema_name(type, schema_name, sizeof(schema_name));
    if (schema_name[0] != '\0' && find_schema(schema_name) != NULL) {
        const void *nested = strchr(type, '*') == NULL ? address : *(const void *const *)address;
        return esrb_view_wrap(view->owner, nested, schema_name, view->message_version, view->strict_version);
    }
    if (strchr(type, '*') != NULL) {
        return Qnil;
    }

    if (strstr(type, "uint64_t") || strstr(type, "unsigned long") || strcmp(type, "size_t") == 0) {
        return ULL2NUM(*(const uint64_t *)address);
    }
    if (strstr(type, "int64_t") || strstr(type, "long long") || strstr(type, "off_t") || strstr(type, "time_t")) {
        return LL2NUM(*(const int64_t *)address);
    }
    if (strstr(type, "uint16_t")) {
        return UINT2NUM(*(const uint16_t *)address);
    }
    if (strstr(type, "int16_t")) {
        return INT2NUM(*(const int16_t *)address);
    }
    if (strstr(type, "uint8_t") || strstr(type, "unsigned char")) {
        return UINT2NUM(*(const uint8_t *)address);
    }
    if (strstr(type, "int8_t") || strcmp(type, "char") == 0) {
        return INT2NUM(*(const int8_t *)address);
    }
    if (strstr(type, "int") || strstr(type, "pid_t") || strstr(type, "uid_t") || strstr(type, "gid_t") ||
        strstr(type, "mode_t") || strstr(type, "es_") == type) {
        return INT2NUM(*(const int32_t *)address);
    }
    return Qnil;
}

static VALUE
field_names(VALUE self)
{
    esrb_view_t *view = get_view(self);
    VALUE names = rb_ary_new_capa((long)view->schema->field_count);
    for (size_t index = 0; index < view->schema->field_count; index++) {
        const esrb_field_t *field = &view->schema->fields[index];
        rb_ary_push(names, ID2SYM(rb_intern(field->name)));
    }
    return names;
}

static VALUE
schema_name(VALUE self)
{
    return rb_str_new_cstr(get_view(self)->schema->name);
}

static VALUE
exec_values(VALUE self, VALUE kind_value)
{
    esrb_view_t *view = get_view(self);
    if (strcmp(view->schema->name, "es_event_exec_t") != 0) {
        return Qnil;
    }
    ID kind = SYM2ID(kind_value);
    const es_event_exec_t *event = (const es_event_exec_t *)view->pointer;
    uint32_t count;
    VALUE values;
    if (kind == rb_intern("args") || kind == rb_intern("env")) {
        count = kind == rb_intern("args") ? es_exec_arg_count(event) : es_exec_env_count(event);
        values = rb_ary_new_capa(count);
        for (uint32_t index = 0; index < count; index++) {
            es_string_token_t token = kind == rb_intern("args") ? es_exec_arg(event, index) : es_exec_env(event, index);
            rb_ary_push(values, string_token_value(&token));
        }
        return values;
    }
    if (kind == rb_intern("fds")) {
        count = es_exec_fd_count(event);
        values = rb_ary_new_capa(count);
        for (uint32_t index = 0; index < count; index++) {
            rb_ary_push(values,
                esrb_view_wrap(view->owner, es_exec_fd(event, index), "es_fd_t", view->message_version, view->strict_version));
        }
        return values;
    }
    return Qnil;
}

VALUE
esrb_event_wrap(VALUE owner, const es_message_t *message, bool strict_version)
{
    for (size_t index = 0; index < esrb_event_schema_count; index++) {
        const esrb_event_schema_t *event = &esrb_event_schemas[index];
        if (event->event_type != message->event_type) {
            continue;
        }
        const unsigned char *address = (const unsigned char *)&message->event + event->offset;
        const void *pointer = event->indirect ? *(const void *const *)address : address;
        return esrb_view_wrap(owner, pointer, event->schema, message->version, strict_version);
    }
    return Qnil;
}

void
esrb_init_field(VALUE endpoint_security)
{
    c_native_view = rb_define_class_under(endpoint_security, "NativeView", rb_cObject);
    rb_undef_alloc_func(c_native_view);
    rb_define_method(c_native_view, "__read_field", read_field, 1);
    rb_define_method(c_native_view, "__field_names", field_names, 0);
    rb_define_method(c_native_view, "__schema_name", schema_name, 0);
    rb_define_method(c_native_view, "__exec_values", exec_values, 1);
    rb_define_class_under(endpoint_security, "Event", c_native_view);
    rb_define_class_under(endpoint_security, "Process", c_native_view);
    rb_define_class_under(endpoint_security, "File", c_native_view);
    rb_define_class_under(endpoint_security, "Thread", c_native_view);
}
