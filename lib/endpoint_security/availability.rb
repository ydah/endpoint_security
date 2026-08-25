# frozen_string_literal: true

require "open3"

module EndpointSecurity
  module Availability
    module_function

    def runtime_version
      @runtime_version ||= Gem::Version.new(Open3.capture2("sw_vers", "-productVersion").first.strip)
    end

    def supported_event?(event)
      runtime_version >= Gem::Version.new(EVENT_MIN_OS.fetch(event.to_sym))
    end
  end
end
