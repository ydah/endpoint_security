# frozen_string_literal: true

require "json"

module EndpointSecurity
  # Writes subscribed events as newline-delimited JSON.
  class Recorder
    # @param events [Array<Symbol>] events to record
    # @param out [IO] destination for JSON lines
    def initialize(events:, out: $stdout, **client_options)
      @events = events
      @out = out
      @client_options = client_options
    end

    # Starts recording and blocks until the client stops.
    # @return [Client]
    def run
      Client.open(**@client_options) do |client|
        client.subscribe(@events)
        @events.each { |event| client.on(event) { |message| @out.puts(JSON.generate(message.to_h)) } }
        client.run
      end
    end
  end
end
