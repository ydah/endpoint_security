#ifndef ESRB_MESSAGE_H
#define ESRB_MESSAGE_H

#include <ruby.h>
#include <stdbool.h>

#include "client.h"

void esrb_init_message(VALUE endpoint_security);
VALUE esrb_message_wrap(VALUE owner, esrb_client_t *client, esrb_slot_t *slot);
bool esrb_message_valid_object(VALUE object);

#endif
