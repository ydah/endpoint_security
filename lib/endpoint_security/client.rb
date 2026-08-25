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
    def initialize(**)
      __native_initialize(**)
      @handlers = {}
      @subscriptions = []
      @errors = 0
      @reported_timeouts = 0
      @running = false
    end

    # @return [Array<Symbol>]
    def subscribe(*events, **_options)
      events = events.flatten.map(&:to_sym)
      __subscribe(events.map { |event| EventType.value(event) })
      @subscriptions |= events
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

      @thread = Thread.new { run }
    end

    # @return [Client]
    def stop
      @running = false
      __wake unless closed?
      @thread&.join unless @thread == Thread.current
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

    private

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
