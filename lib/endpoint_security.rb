# frozen_string_literal: true

require_relative "endpoint_security/version"
require_relative "endpoint_security/errors"
require_relative "endpoint_security/diagnostics"
require_relative "endpoint_security/generated/event_types"
require_relative "endpoint_security/generated/availability"
require_relative "endpoint_security/availability"
require_relative "endpoint_security/endpoint_security"
require_relative "endpoint_security/object_model"
require_relative "endpoint_security/message"
require_relative "endpoint_security/client"
require_relative "endpoint_security/recorder"

# Ruby bindings for Apple's Endpoint Security API.
module EndpointSecurity; end

# Short alias for {EndpointSecurity}.
ES = EndpointSecurity
