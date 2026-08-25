/* field.c
 * Calling thread: Ruby dispatcher with the GVL. Every view retains its owning Message.
 */
#include "field.h"

#include <bsm/libbsm.h>
#include <ruby/encoding.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/proc_info.h>

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
tagged_union_value(const char *kind, VALUE value)
{
    return rb_funcall(rb_path2class("EndpointSecurity::TaggedUnion"), rb_intern("__native_new"), 2,
        ID2SYM(rb_intern(kind)), value);
}

static VALUE
hex_value(const uint8_t *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    VALUE string = rb_str_new(NULL, (long)(length * 2));
    char *output = RSTRING_PTR(string);
    for (size_t index = 0; index < length; index++) {
        output[index * 2] = digits[bytes[index] >> 4];
        output[index * 2 + 1] = digits[bytes[index] & 0x0f];
    }
    return string;
}

static VALUE
binary_value(const void *bytes, size_t length)
{
    VALUE value = rb_str_new(bytes, (long)length);
    rb_enc_associate(value, rb_ascii8bit_encoding());
    return value;
}

static VALUE
acl_value(acl_t acl)
{
    if (acl == NULL) {
        return Qnil;
    }
    ssize_t size = acl_size(acl);
    if (size <= 0) {
        return Qnil;
    }
    VALUE value = rb_str_new(NULL, size);
    ssize_t copied = acl_copy_ext(RSTRING_PTR(value), acl, size);
    if (copied < 0) {
        return Qnil;
    }
    rb_str_set_len(value, copied);
    rb_enc_associate(value, rb_ascii8bit_encoding());
    return value;
}

static VALUE
uid_union(bool available, uid_t uid)
{
    return tagged_union_value(available ? "uid" : "unavailable", available ? UINT2NUM(uid) : Qnil);
}

static VALUE
destination_union(const esrb_view_t *view, bool create)
{
    es_destination_type_t type;
    es_file_t *existing_file;
    es_file_t *directory;
    es_string_token_t filename;
    mode_t mode = 0;
    if (create) {
        const es_event_create_t *event = (const es_event_create_t *)view->pointer;
        type = event->destination_type;
        existing_file = event->destination.existing_file;
        directory = event->destination.new_path.dir;
        filename = event->destination.new_path.filename;
        mode = event->destination.new_path.mode;
    } else {
        const es_event_rename_t *event = (const es_event_rename_t *)view->pointer;
        type = event->destination_type;
        existing_file = event->destination.existing_file;
        directory = event->destination.new_path.dir;
        filename = event->destination.new_path.filename;
    }
    if (type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        VALUE file = esrb_view_wrap(
            view->owner, existing_file, "es_file_t", view->message_version, view->strict_version);
        return tagged_union_value("existing_file", file);
    }

    VALUE path = rb_hash_new();
    rb_hash_aset(path, ID2SYM(rb_intern("dir")),
        esrb_view_wrap(view->owner, directory, "es_file_t", view->message_version, view->strict_version));
    rb_hash_aset(path, ID2SYM(rb_intern("filename")), string_token_value(&filename));
    if (create) {
        rb_hash_aset(path, ID2SYM(rb_intern("mode")), UINT2NUM(mode));
    }
    return tagged_union_value("new_path", path);
}

static VALUE
authentication_union(const esrb_view_t *view)
{
    const es_event_authentication_t *event = (const es_event_authentication_t *)view->pointer;
    const void *pointer = NULL;
    const char *kind = "unknown";
    const char *schema = NULL;
    switch (event->type) {
        case ES_AUTHENTICATION_TYPE_OD:
            kind = "od";
            schema = "es_event_authentication_od_t";
            pointer = event->data.od;
            break;
        case ES_AUTHENTICATION_TYPE_TOUCHID:
            kind = "touchid";
            schema = "es_event_authentication_touchid_t";
            pointer = event->data.touchid;
            break;
        case ES_AUTHENTICATION_TYPE_TOKEN:
            kind = "token";
            schema = "es_event_authentication_token_t";
            pointer = event->data.token;
            break;
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK:
            kind = "auto_unlock";
            schema = "es_event_authentication_auto_unlock_t";
            pointer = event->data.auto_unlock;
            break;
        default:
            break;
    }
    VALUE value = schema == NULL
        ? Qnil
        : esrb_view_wrap(view->owner, pointer, schema, view->message_version, view->strict_version);
    return tagged_union_value(kind, value);
}

static VALUE
od_member_union(const esrb_view_t *view)
{
    const es_od_member_id_t *member = (const es_od_member_id_t *)view->pointer;
    if (member->member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
        return tagged_union_value("name", string_token_value(&member->member_value.name));
    }
    return tagged_union_value("uuid", hex_value(member->member_value.uuid, sizeof(uuid_t)));
}

static VALUE
od_member_array_union(const esrb_view_t *view)
{
    const es_od_member_id_array_t *members = (const es_od_member_id_array_t *)view->pointer;
    if (members->member_count > UINT32_MAX) {
        return tagged_union_value("invalid", Qnil);
    }
    VALUE values = rb_ary_new_capa((long)members->member_count);
    if (members->member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
        for (size_t index = 0; index < members->member_count; index++) {
            rb_ary_push(values, string_token_value(&members->member_array.names[index]));
        }
        return tagged_union_value("names", values);
    }
    for (size_t index = 0; index < members->member_count; index++) {
        rb_ary_push(values, hex_value(members->member_array.uuids[index], sizeof(uuid_t)));
    }
    return tagged_union_value("uuids", values);
}

static VALUE
read_union(const esrb_view_t *view, const esrb_field_t *field)
{
    const char *schema = view->schema->name;
    if (strcmp(field->name, "destination") == 0 && strcmp(schema, "es_event_rename_t") == 0) {
        return destination_union(view, false);
    }
    if (strcmp(field->name, "destination") == 0 && strcmp(schema, "es_event_create_t") == 0) {
        return destination_union(view, true);
    }
    if (strcmp(field->name, "uid") == 0 && strcmp(schema, "es_event_authentication_touchid_t") == 0) {
        const es_event_authentication_touchid_t *event = (const es_event_authentication_touchid_t *)view->pointer;
        return uid_union(event->has_uid, event->uid.uid);
    }
    if (strcmp(field->name, "uid") == 0 && strcmp(schema, "es_event_openssh_login_t") == 0) {
        const es_event_openssh_login_t *event = (const es_event_openssh_login_t *)view->pointer;
        return uid_union(event->has_uid, event->uid.uid);
    }
    if (strcmp(field->name, "uid") == 0 && strcmp(schema, "es_event_login_login_t") == 0) {
        const es_event_login_login_t *event = (const es_event_login_login_t *)view->pointer;
        return uid_union(event->has_uid, event->uid.uid);
    }
    if (strcmp(field->name, "to_uid") == 0 && strcmp(schema, "es_event_su_t") == 0) {
        const es_event_su_t *event = (const es_event_su_t *)view->pointer;
        return uid_union(event->has_to_uid, event->to_uid.uid);
    }
    if (strcmp(schema, "es_event_sudo_t") == 0 && strcmp(field->name, "from_uid") == 0) {
        const es_event_sudo_t *event = (const es_event_sudo_t *)view->pointer;
        return uid_union(event->has_from_uid, event->from_uid.uid);
    }
    if (strcmp(schema, "es_event_sudo_t") == 0 && strcmp(field->name, "to_uid") == 0) {
        const es_event_sudo_t *event = (const es_event_sudo_t *)view->pointer;
        return uid_union(event->has_to_uid, event->to_uid.uid);
    }
    if (strcmp(field->name, "data") == 0 && strcmp(schema, "es_event_authentication_t") == 0) {
        return authentication_union(view);
    }
    if (strcmp(field->name, "member_value") == 0 && strcmp(schema, "es_od_member_id_t") == 0) {
        return od_member_union(view);
    }
    if (strcmp(field->name, "member_array") == 0 && strcmp(schema, "es_od_member_id_array_t") == 0) {
        return od_member_array_union(view);
    }
    if (strcmp(field->name, "file") == 0 && strcmp(schema, "es_event_gatekeeper_user_override_t") == 0) {
        const es_event_gatekeeper_user_override_t *event = (const es_event_gatekeeper_user_override_t *)view->pointer;
        if (event->file_type == ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH) {
            return tagged_union_value("path", string_token_value(&event->file.file_path));
        }
        VALUE file = esrb_view_wrap(
            view->owner, event->file.file, "es_file_t", view->message_version, view->strict_version);
        return tagged_union_value("file", file);
    }
    if (strcmp(field->name, "acl") == 0 && strcmp(schema, "es_event_setacl_t") == 0) {
        const es_event_setacl_t *event = (const es_event_setacl_t *)view->pointer;
        return tagged_union_value(
            event->set_or_clear == ES_SET ? "set" : "clear", event->set_or_clear == ES_SET ? acl_value(event->acl.set) : Qnil);
    }
    return Qundef;
}

static VALUE
string_array(const es_string_token_t *tokens, size_t count)
{
    if (tokens == NULL || count > UINT32_MAX) {
        return rb_ary_new();
    }
    VALUE values = rb_ary_new_capa((long)count);
    for (size_t index = 0; index < count; index++) {
        rb_ary_push(values, string_token_value(&tokens[index]));
    }
    return values;
}

static VALUE
read_array(const esrb_view_t *view, const esrb_field_t *field)
{
    const char *schema = view->schema->name;
    if (strcmp(schema, "es_event_su_t") == 0) {
        const es_event_su_t *event = (const es_event_su_t *)view->pointer;
        if (strcmp(field->name, "argv") == 0) {
            return string_array(event->argv, event->argc);
        }
        if (strcmp(field->name, "env") == 0) {
            return string_array(event->env, event->env_count);
        }
    }
    if (strcmp(schema, "es_event_authorization_petition_t") == 0 && strcmp(field->name, "rights") == 0) {
        const es_event_authorization_petition_t *event = (const es_event_authorization_petition_t *)view->pointer;
        return string_array(event->rights, event->right_count);
    }
    if (strcmp(schema, "es_event_od_attribute_set_t") == 0 && strcmp(field->name, "attribute_values") == 0) {
        const es_event_od_attribute_set_t *event = (const es_event_od_attribute_set_t *)view->pointer;
        return string_array(event->attribute_values, event->attribute_value_count);
    }
    if (strcmp(schema, "es_event_authorization_judgement_t") == 0 && strcmp(field->name, "results") == 0) {
        const es_event_authorization_judgement_t *event = (const es_event_authorization_judgement_t *)view->pointer;
        if (event->results == NULL || event->result_count > UINT32_MAX) {
            return rb_ary_new();
        }
        VALUE values = rb_ary_new_capa((long)event->result_count);
        for (size_t index = 0; index < event->result_count; index++) {
            rb_ary_push(values, esrb_view_wrap(view->owner, &event->results[index], "es_authorization_result_t",
                                    view->message_version, view->strict_version));
        }
        return values;
    }
    return Qundef;
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

static VALUE
statfs_value(const struct statfs *statfs)
{
    size_t type_length = strnlen(statfs->f_fstypename, sizeof(statfs->f_fstypename));
    size_t path_length = strnlen(statfs->f_mntonname, sizeof(statfs->f_mntonname));
    size_t source_length = strnlen(statfs->f_mntfromname, sizeof(statfs->f_mntfromname));
    VALUE fsid = rb_ary_new_from_args(2, INT2NUM(statfs->f_fsid.val[0]), INT2NUM(statfs->f_fsid.val[1]));
    VALUE arguments[] = {
        UINT2NUM(statfs->f_bsize), INT2NUM(statfs->f_iosize), ULL2NUM(statfs->f_blocks), ULL2NUM(statfs->f_bfree),
        ULL2NUM(statfs->f_bavail), ULL2NUM(statfs->f_files), ULL2NUM(statfs->f_ffree), fsid,
        UINT2NUM(statfs->f_owner), UINT2NUM(statfs->f_type), UINT2NUM(statfs->f_flags), UINT2NUM(statfs->f_fssubtype),
        rb_str_new(statfs->f_fstypename, (long)type_length), rb_str_new(statfs->f_mntonname, (long)path_length),
        rb_str_new(statfs->f_mntfromname, (long)source_length), UINT2NUM(statfs->f_flags_ext)
    };
    return rb_funcallv(rb_path2class("EndpointSecurity::Statfs"), rb_intern("__native_new"), 16, arguments);
}

static VALUE
attrlist_value(const struct attrlist *attributes)
{
    VALUE arguments[] = {
        UINT2NUM(attributes->bitmapcount), UINT2NUM(attributes->reserved), UINT2NUM(attributes->commonattr),
        UINT2NUM(attributes->volattr), UINT2NUM(attributes->dirattr), UINT2NUM(attributes->fileattr),
        UINT2NUM(attributes->forkattr)
    };
    return rb_funcallv(rb_path2class("EndpointSecurity::Attrlist"), rb_intern("__native_new"), 7, arguments);
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
    if (strncmp(type, "union ", 6) == 0) {
        VALUE value = read_union(view, field);
        return value == Qundef ? Qnil : value;
    }
    if (strchr(type, '*') != NULL) {
        VALUE value = read_array(view, field);
        if (value != Qundef) {
            return value;
        }
    }
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
    if (strcmp(type, "struct statfs *") == 0) {
        const struct statfs *statfs = *(const struct statfs *const *)address;
        return statfs == NULL ? Qnil : statfs_value(statfs);
    }
    if (strcmp(type, "struct attrlist") == 0) {
        return attrlist_value((const struct attrlist *)address);
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
        return binary_value(address, 20);
    }
    if (strcmp(type, "es_sha256_t *") == 0) {
        const es_sha256_t *sha256 = *(const es_sha256_t *const *)address;
        return sha256 == NULL ? Qnil : binary_value(*sha256, sizeof(*sha256));
    }
    if (strcmp(type, "struct _acl *") == 0) {
        return acl_value(*(acl_t const *)address);
    }
    if (strcmp(view->schema->name, "es_fd_t") == 0 && strcmp(field->name, "pipe") == 0) {
        const es_fd_t *descriptor = (const es_fd_t *)view->pointer;
        if (descriptor->fdtype != PROX_FDTYPE_PIPE) {
            return Qnil;
        }
        VALUE pipe = rb_hash_new();
        rb_hash_aset(pipe, ID2SYM(rb_intern("pipe_id")), ULL2NUM(descriptor->pipe.pipe_id));
        return pipe;
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
    if (strncmp(type, "es_", 3) == 0) {
        VALUE enumeration = rb_path2class("EndpointSecurity::Enum");
        return rb_funcall(enumeration, rb_intern("symbol"), 2, rb_str_new_cstr(type), INT2NUM(*(const int32_t *)address));
    }
    if (strcmp(type, "unsigned long long") == 0 || strcmp(type, "uint64_t") == 0) {
        return ULL2NUM(*(const uint64_t *)address);
    }
    if (strcmp(type, "long long") == 0 || strcmp(type, "int64_t") == 0) {
        return LL2NUM(*(const int64_t *)address);
    }
    if (strcmp(type, "unsigned long") == 0) {
        return ULONG2NUM(*(const unsigned long *)address);
    }
    if (strcmp(type, "long") == 0) {
        return LONG2NUM(*(const long *)address);
    }
    if (strcmp(type, "unsigned int") == 0 || strcmp(type, "uint32_t") == 0) {
        return UINT2NUM(*(const uint32_t *)address);
    }
    if (strcmp(type, "int") == 0 || strcmp(type, "int32_t") == 0) {
        return INT2NUM(*(const int32_t *)address);
    }
    if (strcmp(type, "unsigned short") == 0 || strcmp(type, "uint16_t") == 0) {
        return UINT2NUM(*(const uint16_t *)address);
    }
    if (strcmp(type, "short") == 0 || strcmp(type, "int16_t") == 0) {
        return INT2NUM(*(const int16_t *)address);
    }
    if (strcmp(type, "unsigned char") == 0 || strcmp(type, "uint8_t") == 0) {
        return UINT2NUM(*(const uint8_t *)address);
    }
    if (strcmp(type, "signed char") == 0 || strcmp(type, "int8_t") == 0 || strcmp(type, "char") == 0) {
        return INT2NUM(*(const int8_t *)address);
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
warn_on_truncated_path(VALUE self)
{
    return rb_funcall(get_view(self)->owner, rb_intern("__warn_on_truncated_path?"), 0);
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
    rb_define_method(c_native_view, "__warn_on_truncated_path?", warn_on_truncated_path, 0);
    rb_define_method(c_native_view, "__exec_values", exec_values, 1);
    rb_define_class_under(endpoint_security, "Event", c_native_view);
    rb_define_class_under(endpoint_security, "Process", c_native_view);
    rb_define_class_under(endpoint_security, "File", c_native_view);
    rb_define_class_under(endpoint_security, "Thread", c_native_view);
}
