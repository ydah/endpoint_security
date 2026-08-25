# frozen_string_literal: true

require "endpoint_security"

deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + (Integer(ENV.fetch("HOURS", "24")) * 3600)
ES::Client.open do |client|
  client.subscribe(ES::EventType.all_notify)
  ES::EventType.all_notify.each { |event| client.on(event) { |_message| nil } }
  client.start
  sleep(60) while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
  warn client.stats.inspect
end
