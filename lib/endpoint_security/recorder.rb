# frozen_string_literal: true

require "json"

module EndpointSecurity
  class Recorder
    def initialize(events:, out: $stdout, **client_options)
      @events = events
      @out = out
      @client_options = client_options
    end

    def run
      Client.open(**@client_options) do |client|
        client.subscribe(@events)
        @events.each { |event| client.on(event) { |message| @out.puts(JSON.generate(message.to_h)) } }
        client.run
      end
    end
  end
end
