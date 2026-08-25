# frozen_string_literal: true

module EndpointSecurity
  # Immutable copy of an Endpoint Security audit token.
  AuditToken = Data.define(:pid, :pidversion, :ruid, :euid, :rgid, :egid, :asid, :auid)
  # Immutable copy of a native +stat+ structure.
  Stat = Data.define(
    :dev, :ino, :mode, :nlink, :uid, :gid, :rdev, :size, :blocks, :block_size, :atime, :mtime, :ctime, :birthtime
  )

  # Code-signing flag masks from +kern/cs_blobs.h+.
  CS_FLAG_MASKS = {
    valid: 0x00000001, adhoc: 0x00000002, get_task_allow: 0x00000004, installer: 0x00000008,
    hard: 0x00000100, kill: 0x00000200, restrict: 0x00000800, enforcement: 0x00001000,
    require_lv: 0x00002000, runtime: 0x00010000, platform_binary: 0x04000000, signed: 0x20000000
  }.freeze

  # Code-signing status flags for a process.
  CSFlags = Data.define(:value) do
    # @return [Boolean] whether +flag+ is present
    def include?(flag) = value.anybits?(CS_FLAG_MASKS.fetch(flag.to_sym))

    CS_FLAG_MASKS.each_key { |flag| define_method("#{flag}?") { include?(flag) } }
  end

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

    # @return [CSFlags] code-signing status flags
    def codesigning_flags = CSFlags.new(value: __read_field("codesigning_flags"))
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
