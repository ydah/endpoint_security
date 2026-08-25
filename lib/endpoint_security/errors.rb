# frozen_string_literal: true

module EndpointSecurity
  class Error < StandardError; end
  class ClientError < Error; end
  class NotEntitledError < ClientError; end
  class NotPermittedError < ClientError; end
  class NotPrivilegedError < ClientError; end
  class TooManyClientsError < ClientError; end
  class InvalidArgumentError < ClientError; end
  class InternalError < ClientError; end
  class SubscriptionError < Error; end
  class UnsupportedEventError < SubscriptionError; end
  class MuteError < Error; end
  class MessageError < Error; end
  class MessageInvalidatedError < MessageError; end
  class AlreadyAnsweredError < MessageError; end
  class FieldUnavailableError < MessageError; end
  class NonCacheableEventError < MessageError; end
  class UnsupportedAPIError < Error; end
  class ForkedClientError < Error; end
  class CodegenError < Error; end
end
