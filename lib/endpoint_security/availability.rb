# frozen_string_literal: true

require "open3"

module EndpointSecurity
  # Checks whether events exist on the running macOS version.
  module Availability
    module_function

    # @return [Gem::Version] running macOS version
    def runtime_version
      @runtime_version ||= Gem::Version.new(Open3.capture2("sw_vers", "-productVersion").first.strip)
    end

    # @return [Boolean] whether +event+ is available on this macOS version
    def supported_event?(event)
      runtime_version >= Gem::Version.new(EVENT_MIN_OS.fetch(event.to_sym))
    end
  end
end
