#ifndef ESMOCK_H
#define ESMOCK_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void esmock_inject(
    es_client_t *client, es_event_type_t event_type, es_action_type_t action_type, uint64_t deadline, uint32_t version,
    size_t event_size, es_result_type_t result_type, uint32_t result, bool source_es_client);
size_t esmock_response_count(void);
uint32_t esmock_last_response(void);
size_t esmock_client_count(void);
bool esmock_delete_on_creator_thread(void);
void esmock_set_new_client_result(es_new_client_result_t result);
void esmock_reset(void);

#endif
