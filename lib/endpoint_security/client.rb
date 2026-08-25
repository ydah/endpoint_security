# frozen_string_literal: true

require "io/wait"

module EndpointSecurity
  # Owns an Endpoint Security client and dispatches subscribed messages.
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

    # Calls the native constructor.
    # @api private
    alias __native_initialize initialize
    # Calls the native close implementation.
    # @api private
    alias __native_close close
    # Calls the native statistics implementation.
    # @api private
    alias __native_stats stats

    # @return [Client]
    def initialize(mute_self: true, subscribe: nil, probe: :lazy, **)
      raise ArgumentError, "probe must be :lazy, :eager, or :off" unless %i[lazy eager off].include?(probe.to_sym)

      __native_initialize(mute_self: mute_self, **)
      @probe = probe.to_sym
      @handlers = {}
      @subscriptions = []
      @errors = 0
      @reported_timeouts = 0
      @running = false
      mute_process(pid: ::Process.pid) if mute_self
      if @probe == :eager
        EventType.all.each do |event|
          Availability.probe_cache[event] = probe_event(event) if Availability.supported_event?(event)
        end
      end
      self.subscribe(subscribe) if subscribe
    end

    # @return [Array<Symbol>]
    def subscribe(*events, skip_unsupported: true, **_options)
      events = events.flatten.map(&:to_sym) - @subscriptions
      unsupported = events.reject { |event| supported_event?(event) }
      if !skip_unsupported && !unsupported.empty?
        raise UnsupportedEventError, "unsupported events: #{unsupported.join(", ")}"
      end

      events -= unsupported
      return @subscriptions if events.empty?

      begin
        __subscribe(events.map { |event| EventType.value(event) })
      rescue SubscriptionError => e
        raise SubscriptionError, "failed to subscribe: #{events.join(", ")} (#{e.message})"
      end
      @subscriptions |= events
    end

    # @return [Array<Symbol>] remaining subscriptions
    def unsubscribe(*events)
      events = events.flatten.map(&:to_sym)
      __unsubscribe(events.map { |event| EventType.value(event) })
      @subscriptions -= events
    end

    # @return [Array] empty subscription list
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

    # Native values for path mute kinds.
    # @api private
    PATH_TYPES = { prefix: 0, literal: 1, target_prefix: 2, target_literal: 3 }.freeze
    # Native values for mute inversion kinds.
    # @api private
    INVERSION_TYPES = { process: 0, path: 1, target_path: 2 }.freeze

    # Mutes events for +path+.
    def mute_path(path, type: :prefix) = change_path_mute(:mute, path, type, [])
    # Removes a path mute.
    def unmute_path(path, type: :prefix) = change_path_mute(:unmute, path, type, [])
    # Mutes selected +events+ for +path+.
    def mute_path_events(path, *events, type: :prefix) = change_path_mute(:mute, path, type, events)
    # Removes selected event mutes for +path+.
    def unmute_path_events(path, *events, type: :prefix) = change_path_mute(:unmute, path, type, events)

    # Mutes a process by audit token or PID.
    def mute_process(token = nil, pid: nil)
      change_process_mute(:mute, token || __audit_token_for_pid(pid), [])
    end

    # Removes a process mute by audit token or PID.
    def unmute_process(token = nil, pid: nil)
      change_process_mute(:unmute, token || __audit_token_for_pid(pid), [])
    end

    # Mutes selected +events+ for a process.
    def mute_process_events(token, *events) = change_process_mute(:mute, token, events)
    # Removes selected event mutes for a process.
    def unmute_process_events(token, *events) = change_process_mute(:unmute, token, events)
    # Removes every source-path mute.
    def unmute_all_paths = __unmute_all_paths(false)
    # Removes every target-path mute.
    def unmute_all_target_paths = __unmute_all_paths(true)
    # Clears the Endpoint Security authorization cache.
    def clear_cache = __clear_cache

    # Inverts muting for +type+.
    def invert_muting(type)
      __invert_muting(INVERSION_TYPES.fetch(type.to_sym))
    end

    # @return [Boolean] whether muting for +type+ is inverted
    def muting_inverted?(type)
      __muting_inverted(INVERSION_TYPES.fetch(type.to_sym))
    end

    # @return [Array<Hash>] copied path mute entries
    def muted_paths
      __muted_paths.map { |item| item.merge(type: PATH_TYPES.key(item[:type])) }
    end

    # @return [Array<Hash>] copied process mute entries
    def muted_processes = __muted_processes

    private

    def supported_event?(event)
      return false unless Availability.supported_event?(event)
      return true if @probe == :off

      Availability.probe_cache.fetch(event) { Availability.probe_cache[event] = probe_event(event) }
    end

    def probe_event(event)
      value = EventType.value(event)
      __subscribe([value])
      __unsubscribe([value])
      true
    rescue SubscriptionError
      false
    end

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
