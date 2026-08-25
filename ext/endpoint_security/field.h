#ifndef ESRB_FIELD_H
#define ESRB_FIELD_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <ruby.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *name;
    const char *type;
    size_t offset;
    uint32_t minimum_version;
} esrb_field_t;

typedef struct {
    const char *name;
    const esrb_field_t *fields;
    size_t field_count;
} esrb_schema_t;

typedef struct {
    es_event_type_t event_type;
    size_t offset;
    const char *schema;
    bool indirect;
} esrb_event_schema_t;

extern const esrb_schema_t esrb_schemas[];
extern const size_t esrb_schema_count;
extern const esrb_event_schema_t esrb_event_schemas[];
extern const size_t esrb_event_schema_count;

void esrb_init_field(VALUE endpoint_security);
VALUE esrb_view_wrap(
    VALUE owner, const void *pointer, const char *schema_name, uint32_t message_version, bool strict_version);
VALUE esrb_event_wrap(VALUE owner, const es_message_t *message, bool strict_version);

#endif
