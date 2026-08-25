# frozen_string_literal: true

require "io/wait"

module EndpointSecurity
  class Client
    class << self
      # @yield [client]
      # @return [Object]
      def open(**)
        client = new(**)
        return client unless block_given?

        yield client
      ensure
        client&.close if block_given?
      end
    end

    alias __native_initialize initialize
    alias __native_close close
    alias __native_stats stats

    # @return [Client]
    def initialize(mute_self: true, **)
      __native_initialize(mute_self: mute_self, **)
      @handlers = {}
      @subscriptions = []
      @errors = 0
      @reported_timeouts = 0
      @running = false
      mute_process(pid: ::Process.pid) if mute_self
    end

    # @return [Array<Symbol>]
    def subscribe(*events, skip_unsupported: true, **_options)
      events = events.flatten.map(&:to_sym)
      unsupported = events.reject { |event| Availability.supported_event?(event) }
      if !skip_unsupported && !unsupported.empty?
        raise UnsupportedEventError, "unsupported events: #{unsupported.join(", ")}"
      end

      events -= unsupported
      return @subscriptions if events.empty?

      __subscribe(events.map { |event| EventType.value(event) })
      @subscriptions |= events
    end

    def unsubscribe(*events)
      events = events.flatten.map(&:to_sym)
      __unsubscribe(events.map { |event| EventType.value(event) })
      @subscriptions -= events
    end

    def unsubscribe_all
      __unsubscribe(nil)
      @subscriptions.clear
    end

    # @return [Array<Symbol>]
    attr_reader :subscriptions

    # @return [Client]
    def on(event, &handler)
      raise ArgumentError, "handler block is required" unless handler

      @handlers[event.to_sym] = handler
      self
    end

    # @return [Client]
    def on_error(&handler)
      @error_handler = handler
      self
    end

    # @return [Client]
    def on_timeout(&handler)
      @timeout_handler = handler
      self
    end

    # @return [Client]
    def run
      @running = true
      wakeup = IO.for_fd(__wakeup_fd, autoclose: false)
      while @running && !closed?
        wakeup.wait_readable(0.1)
        __drain.each { |message| dispatch(message) }
        report_timeouts
      end
      self
    ensure
      @running = false
    end

    # @return [Thread]
    def start
      return @thread if @thread&.alive?

      @thread = ::Thread.new { run }
    end

    # @return [Client]
    def stop
      @running = false
      __wake unless closed?
      @thread&.join unless @thread == ::Thread.current
      self
    end

    # @return [nil]
    def close
      stop
      __native_close
    end

    # @return [Hash]
    def stats
      __native_stats.merge(errors: @errors)
    end

    PATH_TYPES = { prefix: 0, literal: 1, target_prefix: 2, target_literal: 3 }.freeze
    INVERSION_TYPES = { process: 0, path: 1, target_path: 2 }.freeze

    def mute_path(path, type: :prefix) = change_path_mute(:mute, path, type, [])
    def unmute_path(path, type: :prefix) = change_path_mute(:unmute, path, type, [])
    def mute_path_events(path, *events, type: :prefix) = change_path_mute(:mute, path, type, events)
    def unmute_path_events(path, *events, type: :prefix) = change_path_mute(:unmute, path, type, events)

    def mute_process(token = nil, pid: nil)
      change_process_mute(:mute, token || __audit_token_for_pid(pid), [])
    end

    def unmute_process(token = nil, pid: nil)
      change_process_mute(:unmute, token || __audit_token_for_pid(pid), [])
    end

    def mute_process_events(token, *events) = change_process_mute(:mute, token, events)
    def unmute_process_events(token, *events) = change_process_mute(:unmute, token, events)
    def unmute_all_paths = __unmute_all_paths(false)
    def unmute_all_target_paths = __unmute_all_paths(true)
    def clear_cache = __clear_cache

    def invert_muting(type)
      __invert_muting(INVERSION_TYPES.fetch(type.to_sym))
    end

    def muting_inverted?(type)
      __muting_inverted(INVERSION_TYPES.fetch(type.to_sym))
    end

    def muted_paths
      __muted_paths.map { |item| item.merge(type: PATH_TYPES.key(item[:type])) }
    end

    def muted_processes = __muted_processes

    private

    def change_path_mute(action, path, type, events)
      __mute_path(action, String(path), PATH_TYPES.fetch(type.to_sym), events.map { |event| EventType.value(event) })
    end

    def change_process_mute(action, token, events)
      raise ArgumentError, "audit token or pid is required" unless token

      __mute_process(action, token, events.map { |event| EventType.value(event) })
    end

    def dispatch(message)
      handler = @handlers[message.event_type]
      handler&.call(message)
    rescue StandardError => e
      @errors += 1
      message.__respond_default! if message.auth? && !message.answered?
      @error_handler&.call(e)
    ensure
      message.__auto_release!
    end

    def report_timeouts
      count = __native_stats[:timeouts]
      (count - @reported_timeouts).times { @timeout_handler&.call }
      @reported_timeouts = count
    end
  end
end
