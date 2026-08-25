# frozen_string_literal: true

require "benchmark"
require "yaml"
require_relative "../lib/endpoint_security"

count = Integer(ENV.fetch("MESSAGES", "100000"))
client = ES::Client.new(queue_depth: 8192, mute_self: false)
event = ES::EventType.value(:notify_exec)
elapsed = Benchmark.realtime do
  count.times do
    ES::Mock.inject(client, event: event, auth: false)
    client.send(:__drain, 1).first.__auto_release!
  end
end
rate = count / elapsed
baseline = YAML.load_file(File.join(__dir__, "baseline.yml")).fetch("messages_per_second")
puts format("%<rate>.0f messages/s", rate: rate)
abort "throughput regressed by more than 15%" if rate < baseline * 0.85
client.close
