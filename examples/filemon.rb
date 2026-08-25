# frozen_string_literal: true

require "endpoint_security"

events = %i[notify_open notify_write notify_create notify_unlink notify_rename]
ES::Client.open do |client|
  client.subscribe(events)
  events.each { |event| client.on(event) { |message| puts JSON.generate(message.to_h) } }
  client.run
end
