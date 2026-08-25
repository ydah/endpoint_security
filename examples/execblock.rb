# frozen_string_literal: true

require "endpoint_security"

blocked_prefix = ARGV.fetch(0, "/tmp/")
ES::Client.open(auth_default: :allow) do |client|
  client.subscribe(:auth_exec)
  client.on(:auth_exec) do |message|
    target = message.event.target
    target.executable.path.start_with?(blocked_prefix) ? message.deny!(cache: false) : message.allow!(cache: false)
  end
  client.run
end
