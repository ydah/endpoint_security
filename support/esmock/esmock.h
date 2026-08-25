#ifndef ESMOCK_H
#define ESMOCK_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void esmock_inject(
    es_client_t *client, es_event_type_t event_type, bool auth, uint64_t deadline, uint32_t version, size_t event_size);
size_t esmock_response_count(void);
uint32_t esmock_last_response(void);
void esmock_reset(void);

#endif
