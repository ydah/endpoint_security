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
    client.on(:notify_exec) { |message| received << message.event_type }
    client.start

    ES::Mock.inject(client, event: ES::EventType.value(:notify_exec), auth: false)
    expect(received.pop).to eq(:notify_exec)
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
end
