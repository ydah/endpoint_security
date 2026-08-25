# frozen_string_literal: true

require "spec_helper"
require "fileutils"
require "tmpdir"
require "timeout"

RSpec.describe "Endpoint Security integration" do
  before do
    skip "set RUN_ES_INTEGRATION=1 and use a signed root Ruby" unless ENV["RUN_ES_INTEGRATION"] == "1"
  end

  it "observes an exec from a bounded test command" do
    observed = Queue.new
    client = ES::Client.new
    client.subscribe(:notify_exec)
    client.on(:notify_exec) do |message|
      path = message.event.target.executable.path
      observed << path if path == "/usr/bin/true"
    end
    client.start
    system("/usr/bin/true")
    expect(Timeout.timeout(5) { observed.pop }).to eq("/usr/bin/true")
  ensure
    client&.close
  end

  it "observes open, rename, and unlink in an isolated directory" do
    observed = Queue.new
    client = ES::Client.new
    client.subscribe(:notify_open, :notify_rename, :notify_unlink)
    client.on(:notify_open) { |message| observed << :open if message.event.file.path.include?("es-integration") }
    client.on(:notify_rename) { |message| observed << :rename if message.event.source.path.include?("es-integration") }
    client.on(:notify_unlink) { |message| observed << :unlink if message.event.target.path.include?("es-integration") }
    client.start

    Dir.mktmpdir("es-integration") do |directory|
      source = File.join(directory, "source")
      target = File.join(directory, "target")
      system("/usr/bin/touch", source, exception: true)
      system("/bin/mv", source, target, exception: true)
      system("/bin/rm", target, exception: true)
      events = []
      Timeout.timeout(5) { events << observed.pop until (%i[open rename unlink] - events).empty? }
      expect(events.uniq).to contain_exactly(:open, :rename, :unlink)
    end
  ensure
    client&.close
  end

  it "denies only a dedicated test executable" do
    denied = Queue.new
    Dir.mktmpdir("es-auth-integration") do |directory|
      executable = File.join(directory, "deny-me")
      FileUtils.cp("/usr/bin/true", executable)
      FileUtils.chmod(0o755, executable)
      client = ES::Client.new(auth_default: :allow)
      client.subscribe(:auth_exec)
      client.on(:auth_exec) do |message|
        if message.event.target.executable.path == executable
          denied << message.deny!(cache: false)
        else
          message.allow!(cache: false)
        end
      end
      client.start

      expect(system(executable)).to be(false)
      expect(Timeout.timeout(5) { denied.pop }).to be(true)
    end
  ensure
    client&.close
  end
end
