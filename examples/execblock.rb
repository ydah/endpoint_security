# frozen_string_literal: true

require "endpoint_security"

blocked_team_id, blocked_signing_id = ARGV
abort "usage: ruby execblock.rb TEAM_ID SIGNING_ID" unless blocked_team_id && blocked_signing_id

ES::Client.open(auth_default: :allow) do |client|
  client.subscribe(:auth_exec)
  client.on(:auth_exec) do |message|
    target = message.event.target
    blocked = target.team_id == blocked_team_id && target.signing_id == blocked_signing_id
    blocked ? message.deny!(cache: false) : message.allow!(cache: false)
  end
  client.run
end
