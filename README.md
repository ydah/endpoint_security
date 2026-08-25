# endpoint_security

Native Ruby bindings for Apple's Endpoint Security API on macOS 13 or newer.

The gem keeps Apple's callback thread away from the Ruby VM: callbacks retain and enqueue messages into a bounded lock-free ring, a Ruby dispatcher invokes handlers, and a native watchdog guarantees one AUTH response before the deadline.

## Requirements

- macOS 13+
- CRuby 3.2+
- Xcode Command Line Tools
- A host Ruby executable signed with `com.apple.developer.endpoint-security.client`
- root privileges and Full Disk Access for that executable

The entitlement belongs to the host executable, not to this gem. Apple must grant it for production use.

For production, request `com.apple.developer.endpoint-security.client` for your Apple Developer team, sign a dedicated host executable with the approved entitlement, then grant that executable Full Disk Access. The helper under [Signing](#development) only performs the signing step; it cannot grant or bypass Apple's approval.

## Installation

```ruby
gem "endpoint_security"
```

```sh
bundle install
rake compile
```

## Observe events

```ruby
require "endpoint_security"

ES::Client.open do |client|
  client.subscribe(:notify_exec)
  client.on(:notify_exec) do |message|
    target = message.event.target
    puts "#{target.executable.path} pid=#{target.pid}"
  end
  client.run
end
```

## Authorize events

```ruby
ES::Client.open(auth_default: :allow) do |client|
  client.subscribe(:auth_exec)
  client.on(:auth_exec) do |message|
    path = message.event.target.executable.path
    path.start_with?("/tmp/") ? message.deny!(cache: false) : message.allow!(cache: false)
  end
  client.run
end
```

The native watchdog sends `auth_default` if Ruby misses the deadline. `allow!`, `deny!`, and the watchdog share one atomic state, so a message is never answered twice. Keep network, file, and subprocess I/O out of an AUTH handler; use `retain!` and another thread when slow work is unavoidable.

## Muting and recording

```ruby
client.mute_path("/tmp/", type: :prefix)
client.mute_process(pid: Process.pid)
client.invert_muting(:path)

ES::Recorder.new(events: ES::EventType.all_notify, out: $stdout).run
```

`Message#to_h` makes a JSON-compatible deep copy. Lazy `Event`, `Process`, and `File` views are invalid after the handler returns unless the message was retained.

## Development

Most work needs no entitlement:

```sh
rake compile:mock
rake test
rake test:sanitize
rake test:drift
rake bench
rake rubocop
rake dev:doctor
```

Generate metadata for a new SDK with `rake codegen`. Generated files under `ext/endpoint_security/generated` and `lib/endpoint_security/generated` must not be edited by hand.

For a dedicated development machine, create a signed Ruby copy:

```sh
rake 'sign:ruby[/path/to/ruby,Developer ID Application: Example (TEAMID)]'
```

Then grant `build/es-ruby` Full Disk Access and run the bounded integration test:

```sh
RUN_ES_INTEGRATION=1 sudo -E ./build/es-ruby -S rake test:integration
```

Do not disable SIP on a general-purpose machine. This project never changes SIP, NVRAM, TCC, or signing settings automatically.

## Limitations

- Fork after client creation is unsupported and raises `ES::ForkedClientError`.
- Undocumented `RESERVED_*` events expose their enum and `raw_event_bytes`, but no guessed structure.
- Real integration tests require Apple-granted entitlement, root, signing, and TCC; CI uses `libesmock`.

Public releases follow Semantic Versioning. Before 1.0, minor releases may contain breaking API changes; from 1.0 onward, breaking changes require a major release.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
