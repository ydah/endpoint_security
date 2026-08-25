# frozen_string_literal: true

require "spec_helper"
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

  it "exposes every SDK event and marks reserved placeholders" do
    expect(ES::EventType.all.size).to eq(ES::EventType::LAST)
    expect(ES::EventType.auth?(:auth_exec)).to be(true)
    expect(ES::EventType.reserved?(:reserved_0)).to be(true)
    expect(ES::EventType.symbol(ES::EventType.value(:notify_exec))).to eq(:notify_exec)
  end
end
