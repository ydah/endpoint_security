# frozen_string_literal: true

require "spec_helper"

RSpec.describe EndpointSecurity do
  it "exposes its version through ES" do
    expect(ES).to equal(described_class)
    expect(ES::VERSION).to eq("0.1.0")
  end

  it "defines the documented error hierarchy" do
    expect(ES::NotEntitledError).to be < ES::ClientError
    expect(ES::MessageInvalidatedError).to be < ES::MessageError
    expect(ES::UnsupportedEventError).to be < ES::SubscriptionError
  end

  it "explains client creation failures with an action" do
    expect(ES::Diagnostics.explain(:err_not_privileged)).to include("root")
    expect(ES::Diagnostics.explain(:err_not_permitted)).to include("Full Disk Access")
    expect(ES::Diagnostics.explain(99)).to include("Unknown", "99")
  end

  it "validates native string token encoding" do
    expect { ES.string_encoding = :invalid }.to raise_error(ArgumentError)
    expect(ES.string_encoding = :binary).to eq(:binary)
  ensure
    ES.string_encoding = :utf8
  end

  it "builds a portable source gem for both supported architectures" do
    specification = Gem::Specification.load(File.expand_path("../../endpoint_security.gemspec", __dir__))
    platform = specification.platform

    expect(platform.to_s).to eq("universal-darwin")
    expect(platform =~ Gem::Platform.new("arm64-darwin-24")).to be(true)
    expect(platform =~ Gem::Platform.new("x86_64-darwin-23")).to be(true)
    expect(platform =~ Gem::Platform.new("x86_64-linux")).to be(false)
    expect(specification.extensions).to eq(["ext/endpoint_security/extconf.rb"])
  end
end
