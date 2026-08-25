# frozen_string_literal: true

require "endpoint_security"

ES::Client.open do |client|
  client.subscribe(:notify_exec, :notify_fork, :notify_exit)
  client.on(:notify_exec) do |message|
    puts "exec pid=#{message.event.target.pid} path=#{message.event.target.executable.path}"
  end
  client.on(:notify_fork) { |message| puts "fork child=#{message.event.child.pid}" }
  client.on(:notify_exit) { |message| puts "exit pid=#{message.process.pid}" }
  client.run
end
