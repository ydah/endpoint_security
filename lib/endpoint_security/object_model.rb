# frozen_string_literal: true

module EndpointSecurity
  # Immutable copy of an Endpoint Security audit token.
  AuditToken = Data.define(:pid, :pidversion, :ruid, :euid, :rgid, :egid, :asid, :auid)
  # Immutable copy of a native +stat+ structure.
  Stat = Data.define(
    :dev, :ino, :mode, :nlink, :uid, :gid, :rdev, :size, :blocks, :block_size, :atime, :mtime, :ctime, :birthtime
  )
  # Immutable copy of a native +statfs+ structure.
  Statfs = Data.define(
    :block_size, :io_size, :blocks, :blocks_free, :blocks_available, :files, :files_free, :fsid, :owner,
    :type, :flags, :subtype, :fs_type_name, :mount_path, :mount_source, :extended_flags
  )
  # Immutable copy of a native +attrlist+ structure.
  Attrlist = Data.define(:bitmap_count, :reserved, :common, :volume, :directory, :file, :fork)

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

  # Selected member of a tagged native union.
  TaggedUnion = Data.define(:kind, :value) do
    # @api private
    # @return [TaggedUnion]
    def self.__native_new(kind, value) = new(kind: kind, value: value)
  end

  # Lazily loaded native array field.
  class FieldArray
    include Enumerable

    # @api private
    # @yieldreturn [Array] copied field values
    def initialize(&loader)
      @loader = loader
    end

    # Iterates over field values.
    # @return [Enumerator, FieldArray]
    def each(&)
      return enum_for(__method__) unless block_given?

      values.each(&)
      self
    end

    # @return [Object, nil] value at +index+
    def [](index) = values[index]

    # @return [Integer] number of values
    def length = values.length
    alias size length

    # @return [Array] copied values
    def to_a = values.dup

    private

    def values = (@values ||= Array(@loader.call).freeze)
  end

  # Lazy enumerable for exec arguments and environment entries.
  class ExecArgs < FieldArray; end

  [AuditToken, Stat, Statfs, Attrlist].each do |value_class|
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

      value = __read_field(field)
      value.is_a?(Array) ? FieldArray.new { value } : value
    end

    def respond_to_missing?(name, include_private = false)
      field = name.to_s.delete_suffix("?")
      __field_names.include?(field.to_sym) || __field_names.include?(:"is_#{field}") || super
    end

    private

    def deep_copy(value)
      case value
      when NativeView then value.to_h
      when FieldArray, Array then value.map { |item| deep_copy(item) }
      when Data then deep_copy(value.to_h)
      when Hash then value.to_h { |key, item| [key, deep_copy(item)] }
      when String
        return value.dup if value.encoding != Encoding::BINARY && value.valid_encoding?

        { encoding: :base64, data: [value].pack("m0") }
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

  # Lazy view of an +es_file_t+.
  class File
    # Returns the possibly truncated path supplied by Endpoint Security.
    # @return [String]
    def path
      if path_truncated? && __warn_on_truncated_path?
        warn "Endpoint Security path is truncated; do not use it for authorization"
      end
      __read_field("path")
    end
  end

  # Lazy view of an event-specific Endpoint Security structure.
  class Event
    # @return [ExecArgs] exec arguments
    def args = (@args ||= ExecArgs.new { __exec_values(:args) })

    # @return [ExecArgs] exec environment
    def env = (@env ||= ExecArgs.new { __exec_values(:env) })

    # @return [FieldArray] exec file descriptors
    def fds = (@fds ||= FieldArray.new { __exec_values(:fds) })

    # @return [Hash] deep copy of the event fields
    def to_h
      super.tap do |hash|
        next unless __schema_name == "es_event_exec_t"

        hash[:args] = args.to_a
        hash[:env] = env.to_a
        hash[:fds] = fds.map(&:to_h)
      end
    end
  end
end
