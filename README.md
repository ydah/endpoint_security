<h1 align="center">endpoint_security</h1>

<p align="center">
  <strong>Native Ruby bindings for Apple's Endpoint Security API</strong>
</p>

<p align="center">
  <a href="https://rubygems.org/gems/endpoint_security"><img src="https://img.shields.io/gem/v/endpoint_security.svg?colorB=319e8c" alt="Gem Version"></a>
  <a href="https://github.com/ydah/endpoint_security/actions/workflows/main.yml"><img src="https://github.com/ydah/endpoint_security/actions/workflows/main.yml/badge.svg?branch=main" alt="CI"></a>
  <img src="https://img.shields.io/badge/ruby-%3E%3D%203.2-ruby.svg" alt="Ruby Version">
  <img src="https://img.shields.io/badge/macOS-%3E%3D%2013-black.svg" alt="macOS Version">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
</p>

<p align="center">
  <a href="https://ydah.github.io/endpoint_security/">Website</a> ·
  <a href="#features">Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#authorization">Authorization</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#how-it-works">How It Works</a>
</p>

---

`endpoint_security` is a native CRuby interface to Apple's Endpoint Security framework. It exposes generated event types, lazy message views, authorization responses, muting, and JSON recording without running Ruby on Apple's callback thread.

Callbacks retain and enqueue messages into a bounded lock-free queue. Ruby handlers run through the dispatcher, while a native watchdog guarantees a single fallback response for AUTH events before their deadline.

## Features

- Generated bindings for every event type in the active macOS SDK
- Lazy `Message`, `Process`, `File`, and `Event` views
- JSON-compatible deep copies with `Message#to_h`
- Bounded lock-free delivery with queue and sequence-gap statistics
- Native AUTH watchdog with exactly-once responses
- Runtime availability probing across macOS versions
- Process and path muting, cache control, and event recording
- Raw bytes for undocumented `RESERVED_*` events without guessed layouts

## Installation

Add the gem to your Gemfile:

```ruby
gem "endpoint_security"
```

Then install:

```bash
bundle install
```

### Requirements

- macOS 13 or newer
- CRuby 3.2 or newer
- Xcode Command Line Tools
- An Apple-approved Endpoint Security client entitlement
- A signed host Ruby executable with Full Disk Access
- Root privileges when opening an Endpoint Security client

> [!IMPORTANT]
> The entitlement belongs to the host executable, not the gem. Apple must approve `com.apple.developer.endpoint-security.client` for your Developer team. This project cannot grant or bypass that approval, Full Disk Access, SIP, AMFI, or code-signing requirements.

## Quick Start

Observe process executions:

```ruby
require "endpoint_security"

ES::Client.open(subscribe: :notify_exec) do |client|
  client.on(:notify_exec) do |message|
    target = message.event.target
    puts "#{target.executable.path} pid=#{target.pid}"
  end

  client.run
end
```

See [`examples/procmon.rb`](examples/procmon.rb) and [`examples/filemon.rb`](examples/filemon.rb) for complete monitoring examples.

## Authorization

Authorize or deny executions by signing identity:

```ruby
require "endpoint_security"

blocked_team_id = "TEAMID1234"
blocked_signing_id = "com.example.blocked"

ES::Client.open(subscribe: :auth_exec, auth_default: :allow) do |client|
  client.on(:auth_exec) do |message|
    target = message.event.target
    blocked = target.team_id == blocked_team_id && target.signing_id == blocked_signing_id

    blocked ? message.deny!(cache: false) : message.allow!(cache: false)
  end

  client.run
end
```

The native watchdog sends `auth_default` if Ruby misses the deadline. `allow!`, `deny!`, and the watchdog share one atomic state, so a message is never answered twice.

> [!WARNING]
> Do not authorize from a path alone. Paths may be truncated or replaced between observation and use. Prefer `cdhash`, `signing_id`, `team_id`, and platform-signing metadata. Keep network, file, and subprocess I/O out of AUTH handlers.

For slow work, call `retain!`, hand the message to another thread, and release it explicitly when finished.

## Configuration

Pass options to `ES::Client.new` or `ES::Client.open`:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `subscribe` | Symbol / Array | `nil` | Events to subscribe to during initialization |
| `mute_self` | Boolean | `true` | Mute events originating from the host process |
| `probe` | Symbol | `:lazy` | Event support probing: `:lazy`, `:eager`, or `:off` |
| `queue_depth` | Integer | `8192` | Queue capacity; must be a power of two and at least 2 |
| `auth_default` | Symbol | `:allow` | Watchdog fallback: `:allow` or `:deny` |
| `default_cache` | Boolean | `false` | Cache watchdog fallback responses |
| `deadline_margin` | Float | `0.2` | Fraction of remaining deadline reserved for fallback |
| `min_margin_ns` | Integer | `5_000_000` | Minimum watchdog margin in nanoseconds |
| `strict_cache` | Boolean | `false` | Reject caching for non-cacheable events |
| `strict_version` | Boolean | `false` | Raise when reading fields unavailable in the message version |
| `warn_on_truncated_path` | Boolean | `false` | Warn when returning a truncated path |

Register handlers and inspect runtime health:

```ruby
client.on(:notify_exec) { |message| puts message.event.target.executable.path }
client.on_error { |error| warn error.full_message }
client.on_timeout { warn "AUTH deadline fallback fired" }

warn client.stats
```

## Muting and Recording

```ruby
client.mute_path("/tmp/", type: :prefix)
client.mute_process(pid: Process.pid)
client.invert_muting(:path)
```

Record events as newline-delimited JSON:

```ruby
ES::Recorder.new(events: ES::EventType.all_notify, out: $stdout).run
```

Lazy native views are invalid after their handler returns unless the message was retained. Use `Message#to_h` when data must outlive dispatch.

## How It Works

1. The native Endpoint Security callback retains each message
2. A bounded MPMC ring queues it without entering the Ruby VM
3. A coalesced file-descriptor wakeup notifies the Ruby dispatcher
4. Ruby invokes the registered handler and releases the message
5. A native deadline heap answers overdue AUTH messages independently

Queue overflow never blocks Apple's callback thread. NOTIFY events are dropped and counted; AUTH events receive the configured fallback response.

## Development

Most development and CI tasks use the included Endpoint Security mock and require no entitlement:

```bash
bundle install
bundle exec rake
bundle exec rake test:sanitize
bundle exec rake bench
```

Generate metadata for a new SDK with `bundle exec rake codegen`. Generated files under `ext/endpoint_security/generated` and `lib/endpoint_security/generated` must not be edited by hand.

### Real Integration Tests

On a dedicated development Mac, sign a Ruby copy with an approved identity:

```bash
bundle exec rake 'sign:ruby[/path/to/ruby,Developer ID Application: Example (TEAMID)]'
```

Grant `build/es-ruby` Full Disk Access, then run:

```bash
RUN_ES_INTEGRATION=1 sudo -E ./build/es-ruby -S rake test:integration
```

Do not disable SIP on a general-purpose machine. This project never changes SIP, NVRAM, TCC, or signing settings automatically.

## Limitations

- Forking after client creation is unsupported and raises `ES::ForkedClientError`
- Undocumented `RESERVED_*` events expose only their enum and `raw_event_bytes`
- Real integration tests require Apple-granted entitlement, root, signing, and Full Disk Access
- CI uses `libesmock` and cannot validate Apple entitlement or TCC configuration

## Contributing

Bug reports and pull requests are welcome at https://github.com/ydah/endpoint_security.

## License

Released under the [MIT License](LICENSE.txt).
