# frozen_string_literal: true

require "spec_helper"
require "timeout"

RSpec.describe ES::Client do
  def wait_until(timeout: 1)
    Timeout.timeout(timeout) do
      sleep(0.001) until yield
    end
  end

  before { ES::Mock.reset }

  it "delivers subscribed mock messages through the dispatcher" do
    client = described_class.new(queue_depth: 8)
    received = Queue.new
    client.subscribe(:notify_exec)
    client.on(:notify_exec) do |message|
      received << [
        message.event_type, message.process.executable.path, message.event.target.executable.path, message.to_h
      ]
    end
    client.start

    ES::Mock.inject(client, event: ES::EventType.value(:notify_exec), auth: false)
    event_type, source, target, hash = received.pop
    expect([event_type, source, target]).to eq([:notify_exec, "/usr/bin/mock-source", "/usr/bin/mock-target"])
    expect(hash[:event][:target][:executable][:path]).to eq("/usr/bin/mock-target")
    expect(client.stats[:delivered]).to eq(1)
  ensure
    client&.close
  end

  it "responds to AUTH exactly once under competing calls" do
    client = described_class.new(queue_depth: 8)
    results = Queue.new
    client.on(:auth_exec) do |message|
      results << [message.allow!, message.deny!, message.answered?]
    end
    client.start

    ES::Mock.inject(client, event: ES::EventType.value(:auth_exec), auth: true)
    expect(results.pop).to eq([true, false, true])
    expect(ES::Mock.response_count).to eq(1)
  ensure
    client&.close
  end

  it "uses the watchdog before a slow handler reaches its deadline" do
    client = described_class.new(queue_depth: 8, auth_default: :deny)
    client.on(:auth_exec) { sleep(0.05) }
    client.start

    ES::Mock.inject(client, event: ES::EventType.value(:auth_exec), auth: true, deadline_ms: 10)
    wait_until { ES::Mock.response_count == 1 }
    expect(ES::Mock.last_response).to eq(1)
    expect(client.stats[:timeouts]).to eq(1)
  ensure
    client&.close
  end

  it "falls back immediately when a handler raises" do
    client = described_class.new(queue_depth: 8)
    errors = Queue.new
    client.on(:auth_exec) { raise "boom" }
    client.on_error { |error| errors << error.message }
    client.start

    ES::Mock.inject(client, event: ES::EventType.value(:auth_exec), auth: true)
    expect(errors.pop).to eq("boom")
    expect(ES::Mock.response_count).to eq(1)
    expect(client.stats[:errors]).to eq(1)
  ensure
    client&.close
  end

  it "round-trips mute, inversion, and cache control APIs" do
    client = described_class.new(queue_depth: 8)
    expect(client.mute_path("/tmp", type: :prefix)).to be(true)
    expect(client.mute_path_events("/tmp", :notify_exec, type: :literal)).to be(true)
    expect(client.unmute_path("/tmp")).to be(true)
    expect(client.invert_muting(:path)).to be(true)
    expect(client.muting_inverted?(:path)).to be(true)
    expect(client.muted_paths).to eq([])
    expect(client.muted_processes).to eq([])
    expect(client.clear_cache).to be(true)
  ensure
    client&.close
  end

  it "rejects caching for a non-cacheable event in strict mode" do
    client = described_class.new(queue_depth: 8, strict_cache: true)
    errors = Queue.new
    client.on(:auth_signal) { |message| message.allow!(cache: true) }
    client.on_error { |error| errors << error }
    client.start

    ES::Mock.inject(client, event: ES::EventType.value(:auth_signal), auth: true)
    expect(errors.pop).to be_a(ES::NonCacheableEventError)
    expect(ES::Mock.response_count).to eq(1)
  ensure
    client&.close
  end

  it "deep-copies every generated event type without unsupported-field exceptions" do
    client = described_class.new(queue_depth: 256, mute_self: false)
    ES::EventType.all.each do |event|
      ES::Mock.inject(client, event: ES::EventType.value(event), auth: false)
      message = client.send(:__drain, 1).first
      expect { message.to_h }.not_to raise_error
      expect(message.raw_event_bytes).not_to be_empty if ES::EventType.reserved?(event)
      message.__auto_release!
    end
  ensure
    client&.close
  end
end
