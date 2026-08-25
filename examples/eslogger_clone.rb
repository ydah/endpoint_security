# frozen_string_literal: true

require "endpoint_security"

ES::Recorder.new(events: ES::EventType.all_notify, out: $stdout).run
