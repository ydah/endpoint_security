# frozen_string_literal: true

module EndpointSecurity
  # Immutable copy of an Endpoint Security audit token.
  AuditToken = Data.define(:pid, :pidversion, :ruid, :euid, :rgid, :egid, :asid, :auid)
  # Immutable copy of a native +stat+ structure.
  Stat = Data.define(
    :dev, :ino, :mode, :nlink, :uid, :gid, :rdev, :size, :blocks, :block_size, :atime, :mtime, :ctime, :birthtime
  )

  [AuditToken, Stat].each do |value_class|
    value_class.define_singleton_method(:__native_new) do |*values|
      new(**members.zip(values).to_h)
    end
  end

  # Base for lazy views backed by a native message.
  class NativeView
    # @return [Hash]
    def to_h
      __field_names.to_h { |name| [name, deep_copy(public_send(name))] }
    end

    # Resolves generated native fields lazily.
    # @api private
    def method_missing(name, ...)
      field = name.to_s.delete_suffix("?")
      predicate = name.to_s.end_with?("?")
      field = "is_#{field}" if predicate && __field_names.include?(:"is_#{field}")
      return super unless __field_names.include?(field.to_sym)

      __read_field(field)
    end

    def respond_to_missing?(name, include_private = false)
      field = name.to_s.delete_suffix("?")
      __field_names.include?(field.to_sym) || __field_names.include?(:"is_#{field}") || super
    end

    private

    def deep_copy(value)
      case value
      when NativeView, Data then value.to_h
      when Array then value.map { |item| deep_copy(item) }
      else value
      end
    end
  end

  # Lazy view of an +es_process_t+.
  class Process
    # @return [Integer]
    def pid = audit_token.pid

    # @return [String]
    def cdhash_hex = cdhash.unpack1("H*")
  end

  # Lazy view of an event-specific Endpoint Security structure.
  class Event
    # @return [Array<String>, nil]
    def args = __exec_values(:args)

    # @return [Array<String>, nil]
    def env = __exec_values(:env)

    # @return [Array<NativeView>, nil]
    def fds = __exec_values(:fds)

    # @return [Hash] deep copy of the event fields
    def to_h
      super.tap do |hash|
        next unless __schema_name == "es_event_exec_t"

        hash[:args] = args
        hash[:env] = env
        hash[:fds] = fds.map(&:to_h)
      end
    end
  end
end
