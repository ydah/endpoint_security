/* endpoint_security.c
 * Calling thread: Ruby VM thread with the GVL.
 */
#include <ruby.h>

#include "client.h"
#include "message.h"

RUBY_FUNC_EXPORTED void
Init_endpoint_security(void)
{
    VALUE endpoint_security = rb_define_module("EndpointSecurity");
    esrb_init_message(endpoint_security);
    esrb_init_client(endpoint_security);
}
