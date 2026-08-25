/* mute.c
 * Calling thread: Ruby control/dispatcher threads with the GVL.
 * Returned ES-owned mute sets are copied before their mandatory release.
 */
#include "mute.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <unistd.h>

#include "client.h"
#include "field.h"

static esrb_client_t *
mute_client(VALUE self)
{
    esrb_client_t *client;
    TypedData_Get_Struct(self, esrb_client_t, &esrb_client_type, client);
    if (client->owner_pid != getpid()) {
        rb_raise(rb_path2class("EndpointSecurity::ForkedClientError"), "Endpoint Security clients cannot be used after fork");
    }
    if (atomic_load_explicit(&client->closed, memory_order_acquire)) {
        rb_raise(rb_path2class("EndpointSecurity::ClientError"), "client is closed");
    }
    return client;
}

static audit_token_t
audit_token_from_value(VALUE value)
{
    audit_token_t token = {0};
    token.val[0] = NUM2UINT(rb_funcall(value, rb_intern("auid"), 0));
    token.val[1] = NUM2UINT(rb_funcall(value, rb_intern("euid"), 0));
    token.val[2] = NUM2UINT(rb_funcall(value, rb_intern("egid"), 0));
    token.val[3] = NUM2UINT(rb_funcall(value, rb_intern("ruid"), 0));
    token.val[4] = NUM2UINT(rb_funcall(value, rb_intern("rgid"), 0));
    token.val[5] = NUM2UINT(rb_funcall(value, rb_intern("pid"), 0));
    token.val[6] = NUM2UINT(rb_funcall(value, rb_intern("asid"), 0));
    token.val[7] = NUM2UINT(rb_funcall(value, rb_intern("pidversion"), 0));
    return token;
}

static VALUE
audit_token_value(audit_token_t token)
{
    VALUE arguments[] = {
        UINT2NUM(audit_token_to_pid(token)), UINT2NUM(audit_token_to_pidversion(token)),
        UINT2NUM(audit_token_to_ruid(token)), UINT2NUM(audit_token_to_euid(token)),
        UINT2NUM(audit_token_to_rgid(token)), UINT2NUM(audit_token_to_egid(token)),
        UINT2NUM(audit_token_to_asid(token)), UINT2NUM(audit_token_to_auid(token))
    };
    return rb_funcallv(rb_path2class("EndpointSecurity::AuditToken"), rb_intern("__native_new"), 8, arguments);
}

static es_event_type_t *
event_values(VALUE values, size_t *count)
{
    Check_Type(values, T_ARRAY);
    *count = (size_t)RARRAY_LEN(values);
    if (*count == 0) {
        return NULL;
    }
    es_event_type_t *events = ALLOC_N(es_event_type_t, *count);
    for (size_t index = 0; index < *count; index++) {
        events[index] = (es_event_type_t)NUM2INT(rb_ary_entry(values, (long)index));
    }
    return events;
}

static void
check_mute_result(es_return_t result)
{
    if (result != ES_RETURN_SUCCESS) {
        rb_raise(rb_path2class("EndpointSecurity::MuteError"), "Endpoint Security mute operation failed");
    }
}

static VALUE
mute_path(VALUE self, VALUE action, VALUE path, VALUE type_value, VALUE values)
{
    esrb_client_t *client = mute_client(self);
    size_t count;
    es_event_type_t *events = event_values(values, &count);
    es_mute_path_type_t type = (es_mute_path_type_t)NUM2INT(type_value);
    const char *path_string = StringValueCStr(path);
    es_return_t result;
    if (SYM2ID(action) == rb_intern("mute")) {
        result = count == 0 ? es_mute_path(client->client, path_string, type)
                            : es_mute_path_events(client->client, path_string, type, events, count);
    } else {
        result = count == 0 ? es_unmute_path(client->client, path_string, type)
                            : es_unmute_path_events(client->client, path_string, type, events, count);
    }
    xfree(events);
    check_mute_result(result);
    return Qtrue;
}

static VALUE
mute_process(VALUE self, VALUE action, VALUE token_value, VALUE values)
{
    esrb_client_t *client = mute_client(self);
    audit_token_t token = audit_token_from_value(token_value);
    size_t count;
    es_event_type_t *events = event_values(values, &count);
    es_return_t result;
    if (SYM2ID(action) == rb_intern("mute")) {
        result = count == 0 ? es_mute_process(client->client, &token)
                            : es_mute_process_events(client->client, &token, events, count);
    } else {
        result = count == 0 ? es_unmute_process(client->client, &token)
                            : es_unmute_process_events(client->client, &token, events, count);
    }
    xfree(events);
    check_mute_result(result);
    return Qtrue;
}

static VALUE
unmute_all(VALUE self, VALUE target)
{
    esrb_client_t *client = mute_client(self);
    check_mute_result(RTEST(target) ? es_unmute_all_target_paths(client->client) : es_unmute_all_paths(client->client));
    return Qtrue;
}

static VALUE
invert_muting(VALUE self, VALUE type)
{
    esrb_client_t *client = mute_client(self);
    check_mute_result(es_invert_muting(client->client, (es_mute_inversion_type_t)NUM2INT(type)));
    return Qtrue;
}

static VALUE
muting_inverted(VALUE self, VALUE type)
{
    esrb_client_t *client = mute_client(self);
    es_mute_inverted_return_t result = es_muting_inverted(client->client, (es_mute_inversion_type_t)NUM2INT(type));
    if (result == ES_MUTE_INVERTED_ERROR) {
        rb_raise(rb_path2class("EndpointSecurity::MuteError"), "failed to query mute inversion state");
    }
    return result == ES_MUTE_INVERTED ? Qtrue : Qfalse;
}

static VALUE
clear_cache(VALUE self)
{
    es_clear_cache_result_t result = es_clear_cache(mute_client(self)->client);
    if (result != ES_CLEAR_CACHE_RESULT_SUCCESS) {
        rb_raise(rb_path2class("EndpointSecurity::ClientError"), "failed to clear Endpoint Security cache (%d)", result);
    }
    return Qtrue;
}

static VALUE
event_symbols(const es_event_type_t *events, size_t count)
{
    VALUE result = rb_ary_new_capa((long)count);
    VALUE event_type = rb_path2class("EndpointSecurity::EventType");
    for (size_t index = 0; index < count; index++) {
        rb_ary_push(result, rb_funcall(event_type, rb_intern("symbol"), 1, INT2NUM(events[index])));
    }
    return result;
}

static VALUE
muted_paths(VALUE self)
{
    es_muted_paths_t *paths = NULL;
    check_mute_result(es_muted_paths_events(mute_client(self)->client, &paths));
    VALUE result = rb_ary_new_capa(paths == NULL ? 0 : (long)paths->count);
    if (paths != NULL) {
        for (size_t index = 0; index < paths->count; index++) {
            const es_muted_path_t *path = &paths->paths[index];
            VALUE item = rb_hash_new();
            rb_hash_aset(item, ID2SYM(rb_intern("type")), INT2NUM(path->type));
            rb_hash_aset(item, ID2SYM(rb_intern("path")), esrb_string_token_value(&path->path));
            rb_hash_aset(item, ID2SYM(rb_intern("events")), event_symbols(path->events, path->event_count));
            rb_ary_push(result, item);
        }
        es_release_muted_paths(paths);
    }
    return result;
}

static VALUE
muted_processes(VALUE self)
{
    es_muted_processes_t *processes = NULL;
    check_mute_result(es_muted_processes_events(mute_client(self)->client, &processes));
    VALUE result = rb_ary_new_capa(processes == NULL ? 0 : (long)processes->count);
    if (processes != NULL) {
        for (size_t index = 0; index < processes->count; index++) {
            const es_muted_process_t *process = &processes->processes[index];
            VALUE item = rb_hash_new();
            rb_hash_aset(item, ID2SYM(rb_intern("audit_token")), audit_token_value(process->audit_token));
            rb_hash_aset(item, ID2SYM(rb_intern("events")), event_symbols(process->events, process->event_count));
            rb_ary_push(result, item);
        }
        es_release_muted_processes(processes);
    }
    return result;
}

static VALUE
audit_token_for_pid(VALUE self, VALUE pid_value)
{
    (void)self;
    pid_t pid = NUM2PIDT(pid_value);
    mach_port_t task = mach_task_self();
    bool release_task = false;
    if (pid != getpid()) {
        kern_return_t result = task_for_pid(mach_task_self(), pid, &task);
        if (result != KERN_SUCCESS) {
            rb_raise(rb_eArgError, "could not obtain task port for pid %d", pid);
        }
        release_task = true;
    }
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t result = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    if (release_task) {
        mach_port_deallocate(mach_task_self(), task);
    }
    if (result != KERN_SUCCESS) {
        rb_raise(rb_eArgError, "could not obtain audit token for pid %d", pid);
    }
    return audit_token_value(token);
}

void
esrb_init_mute(VALUE client_class)
{
    rb_define_method(client_class, "__mute_path", mute_path, 4);
    rb_define_method(client_class, "__mute_process", mute_process, 3);
    rb_define_method(client_class, "__unmute_all_paths", unmute_all, 1);
    rb_define_method(client_class, "__invert_muting", invert_muting, 1);
    rb_define_method(client_class, "__muting_inverted", muting_inverted, 1);
    rb_define_method(client_class, "__clear_cache", clear_cache, 0);
    rb_define_method(client_class, "__muted_paths", muted_paths, 0);
    rb_define_method(client_class, "__muted_processes", muted_processes, 0);
    rb_define_method(client_class, "__audit_token_for_pid", audit_token_for_pid, 1);
}
