#ifndef ESRB_MESSAGE_H
#define ESRB_MESSAGE_H

#include <ruby.h>

#include "client.h"

void esrb_init_message(VALUE endpoint_security);
VALUE esrb_message_wrap(VALUE owner, esrb_client_t *client, esrb_slot_t *slot);

#endif
