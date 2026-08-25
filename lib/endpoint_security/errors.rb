# frozen_string_literal: true

module EndpointSecurity
  # Base error for this library.
  class Error < StandardError; end
  # Endpoint Security client creation failed.
  class ClientError < Error; end
  # The host executable lacks the Endpoint Security entitlement.
  class NotEntitledError < ClientError; end
  # The host executable lacks Full Disk Access.
  class NotPermittedError < ClientError; end
  # The host process is not privileged.
  class NotPrivilegedError < ClientError; end
  # The system has reached its Endpoint Security client limit.
  class TooManyClientsError < ClientError; end
  # Endpoint Security rejected an invalid argument.
  class InvalidArgumentError < ClientError; end
  # Endpoint Security reported an internal error.
  class InternalError < ClientError; end
  # An event subscription operation failed.
  class SubscriptionError < Error; end
  # An event is unavailable on the running macOS version.
  class UnsupportedEventError < SubscriptionError; end
  # A mute operation failed.
  class MuteError < Error; end
  # Base error for message operations.
  class MessageError < Error; end
  # A lazy message view outlived its native message.
  class MessageInvalidatedError < MessageError; end
  # An authorization message has already been answered.
  class AlreadyAnsweredError < MessageError; end
  # A field is absent from this message version.
  class FieldUnavailableError < MessageError; end
  # Caching was requested for a non-cacheable event.
  class NonCacheableEventError < MessageError; end
  # The running macOS version lacks a requested native API.
  class UnsupportedAPIError < Error; end
  # A client created before fork was used by the child process.
  class ForkedClientError < Error; end
  # SDK metadata generation failed.
  class CodegenError < Error; end
end
