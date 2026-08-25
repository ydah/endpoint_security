# frozen_string_literal: true

require "spec_helper"
require "json"
require_relative "../../codegen/ir"

RSpec.describe EndpointSecurity::Codegen::IR do
  it "lexically carries availability comments to following events" do
    source = <<~HEADER
      typedef enum {
        // available beginning in macOS 13.1
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_RESERVED_0,
      } es_event_type_t;
    HEADER

    expect(described_class.scan_availability(source)).to eq(
      "ES_EVENT_TYPE_AUTH_EXEC" => "13.1",
      "ES_EVENT_TYPE_RESERVED_0" => "13.1"
    )
  end

  it "scopes both message and msg version comments to their records" do
    source = <<~HEADER
      typedef struct {
        int value; /* field available only if message version >= 2 */
      } es_first_t;
      typedef struct {
        int value; // Available in msg versions >= 8.
      } es_second_t;
    HEADER

    expect(described_class.scan_field_versions([source])).to eq(
      %w[es_first_t value] => 2,
      %w[es_second_t value] => 8
    )
  end

  it "exposes every SDK event and marks reserved placeholders" do
    expect(ES::EventType.all.size).to eq(ES::EventType::LAST)
    expect(ES::EventType.auth?(:auth_exec)).to be(true)
    expect(ES::EventType.reserved?(:reserved_0)).to be(true)
    expect(ES::EventType.symbol(ES::EventType.value(:notify_exec))).to eq(:notify_exec)
  end

  it "symbolizes known SDK enum values and preserves unknown values" do
    expect(ES::Enum.symbol("es_auth_result_t", 0)).to eq(:allow)
    expect(ES::Enum.symbol("es_auth_result_t", 99)).to eq(99)
  end

  it "marks only answerable AUTH events as cacheable" do
    expect(ES::EventType.cacheable?(:auth_exec)).to be(true)
    expect(ES::EventType.cacheable?(:notify_exec)).to be(false)
  end

  it "rejects field types that the native reader cannot decode" do
    records = [EndpointSecurity::Codegen::Record.new(
      "es_example_t", [EndpointSecurity::Codegen::Field.new("value", "mystery_t", 1)]
    )]

    expect { described_class.validate_field_types!(records: records, enumerations: []) }
      .to raise_error(ES::CodegenError, /unsupported field type mystery_t/)
  end

  it "removes machine-specific paths from anonymous record types" do
    type = "union es_example_t::(unnamed at /custom/Xcode/MacOSX.sdk/ESMessage.h:10:2)"

    expect(described_class.normalize_type(type)).to eq("union es_example_t::(anonymous)")
  end

  it "snapshots every parsed record and its version gates" do
    snapshot = JSON.parse(File.read(Dir[File.expand_path("../../codegen/snapshots/*.json", __dir__)].max))
    expect(snapshot.fetch("records").fetch("es_process_t")).to include(
      a_hash_including("name" => "tty", "minimum_version" => 2),
      a_hash_including("name" => "cs_validation_category", "minimum_version" => 10)
    )
  end
end
