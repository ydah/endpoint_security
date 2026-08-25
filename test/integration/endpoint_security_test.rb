# frozen_string_literal: true

require "spec_helper"
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
end
