/* endpoint_security.c
 * Calling thread: Ruby VM thread with the GVL.
 */
#include <ruby.h>

RUBY_FUNC_EXPORTED void
Init_endpoint_security(void)
{
    rb_define_module("EndpointSecurity");
}
