# frozen_string_literal: true

require_relative "endpoint_security/version"
require_relative "endpoint_security/errors"
require_relative "endpoint_security/diagnostics"
require_relative "endpoint_security/generated/event_types"
require_relative "endpoint_security/generated/enums"
require_relative "endpoint_security/generated/availability"
require_relative "endpoint_security/availability"
require_relative "endpoint_security/endpoint_security"
require_relative "endpoint_security/object_model"
require_relative "endpoint_security/message"
require_relative "endpoint_security/client"
require_relative "endpoint_security/recorder"

# Ruby bindings for Apple's Endpoint Security API.
module EndpointSecurity
  class << self
    # Encoding used for +es_string_token_t+ values.
    # @return [Symbol] +:utf8+ or +:binary+
    attr_reader :string_encoding

    # Selects the encoding used for native string tokens.
    # @param value [Symbol] +:utf8+ or +:binary+
    # @return [Symbol]
    def string_encoding=(value)
      value = value.to_sym
      raise ArgumentError, "string_encoding must be :utf8 or :binary" unless %i[utf8 binary].include?(value)

      @string_encoding = value
    end
  end

  self.string_encoding = :utf8
end

# Short alias for {EndpointSecurity}.
ES = EndpointSecurity
