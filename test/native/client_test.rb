# frozen_string_literal: true

require "spec_helper"
require "json"
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
    expect { JSON.generate(hash) }.not_to raise_error
    expect(hash.dig(:process, :cdhash, :encoding)).to eq(:base64)
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

  it "falls back immediately when an AUTH handler returns unanswered" do
    client = described_class.new(queue_depth: 8, auth_default: :deny)
    client.on(:auth_exec) { |_message| nil }
    client.start

    ES::Mock.inject(client, event: ES::EventType.value(:auth_exec), auth: true, deadline_ms: 1000)
    wait_until { ES::Mock.response_count == 1 }
    expect(ES::Mock.last_response).to eq(1)
    expect(client.stats[:timeouts]).to eq(0)
  ensure
    client&.close
  end

  it "releases retained AUTH messages safely while the watchdog races" do
    client = described_class.new(queue_depth: 8)
    retained = Queue.new
    client.on(:auth_exec) { |message| retained << message.retain! }
    client.start

    200.times do
      ES::Mock.inject(client, event: ES::EventType.value(:auth_exec), auth: true, deadline_ms: 1)
      retained.pop.release!
    end
    wait_until { ES::Mock.response_count == 200 }
    expect(ES::Mock.response_count).to eq(200)
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

  it "exposes enum and tagged-union event fields without raw discriminators" do
    client = described_class.new(queue_depth: 8, mute_self: false)
    ES::Mock.inject(client, event: ES::EventType.value(:notify_create), auth: false)
    message = client.send(:__drain, 1).first

    expect(message.event.destination_type).to eq(:existing_file)
    expect(message.event.destination).to eq(ES::TaggedUnion.new(kind: :existing_file, value: nil))
    expect(message.to_h.dig(:event, :destination, :kind)).to eq(:existing_file)
  ensure
    message&.__auto_release!
    client&.close
  end

  it "copies opaque SDK value types instead of silently returning nil" do
    client = described_class.new(queue_depth: 8, mute_self: false)

    ES::Mock.inject(client, event: ES::EventType.value(:notify_mount), auth: false)
    mount = client.send(:__drain, 1).first
    expect(mount.event.statfs).to be_a(ES::Statfs)
    expect(mount.event.statfs.fs_type_name).to eq("mockfs")
    mount.__auto_release!

    ES::Mock.inject(client, event: ES::EventType.value(:notify_getattrlist), auth: false)
    getattrlist = client.send(:__drain, 1).first
    attributes = ES::Attrlist.new(
      bitmap_count: 5, reserved: 0, common: 1, volume: 0, directory: 0, file: 0, fork: 0
    )
    expect(getattrlist.event.attrlist).to eq(attributes)
    getattrlist.__auto_release!

    ES::Mock.inject(client, event: ES::EventType.value(:notify_gatekeeper_user_override), auth: false)
    gatekeeper = client.send(:__drain, 1).first
    expect(gatekeeper.event.sha256).to eq("\xff".b + ("\0".b * 31))
  ensure
    mount&.__auto_release!
    getattrlist&.__auto_release!
    gatekeeper&.__auto_release!
    client&.close
  end

  it "enforces message versions and exposes typed process metadata" do
    client = described_class.new(queue_depth: 8, strict_version: true, subscribe: :notify_exec, mute_self: false)
    ES::Mock.inject(client, event: ES::EventType.value(:notify_exec), auth: false)
    message = client.send(:__drain, 1).first

    expect(client.subscriptions).to eq([:notify_exec])
    expect(message.result).to eq(:allow)
    expect(message.raw_pointer).to be_a(Integer)
    expect(message.process.codesigning_flags).to be_a(ES::CSFlags)
    expect(message.event.args).to be_a(ES::ExecArgs)
    expect(message.event.fds).to be_a(ES::FieldArray)
    expect { message.process.cs_validation_category }.to raise_error(ES::FieldUnavailableError)
  ensure
    message&.__auto_release!
    client&.close
  end

  it "warns when configured before returning a truncated path" do
    client = described_class.new(queue_depth: 8, mute_self: false, warn_on_truncated_path: true)
    ES::Mock.inject(client, event: ES::EventType.value(:notify_exec), auth: false)
    message = client.send(:__drain, 1).first

    expect { message.process.executable.path }.to output(/path is truncated/).to_stderr
  ensure
    message&.__auto_release!
    client&.close
  end

  it "validates safety-sensitive client options" do
    expect { described_class.new(auth_default: :maybe) }.to raise_error(ArgumentError)
    expect { described_class.new(on_full: :block) }.to raise_error(ArgumentError)
    expect { described_class.new(probe: :sometimes) }.to raise_error(ArgumentError)
  end

  it "rejects inherited client operations after fork" do
    client = described_class.new(queue_depth: 8)
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      result = begin
        client.muted_paths
        "no error"
      rescue StandardError => e
        e.class.name
      end
      writer.write(result)
      writer.close
      exit! 0
    end
    writer.close
    expect(reader.read).to eq("EndpointSecurity::ForkedClientError")
    Process.wait(pid)
  ensure
    reader&.close
    writer&.close
    client&.close
  end
end
