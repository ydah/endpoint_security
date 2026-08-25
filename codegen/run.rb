# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "yaml"
require_relative "../lib/endpoint_security/errors"
require_relative "ast"
require_relative "ir"
require_relative "emit_ruby"

module EndpointSecurity
  module Codegen
    module Run
      module_function

      def call
        sdk = capture("xcrun", "--show-sdk-path")
        version = capture("xcrun", "--show-sdk-version")
        header = File.join(sdk, "usr/include/EndpointSecurity/ESTypes.h")
        source = File.read(header)
        ir = IR.event_types(ast: AST.load(header: header, sdk: sdk), source: source)
        emitter = EmitRuby.new(ir)

        write("lib/endpoint_security/generated/event_types.rb", emitter.event_types)
        write("lib/endpoint_security/generated/availability.rb", emitter.availability)
        availability = ir.events.to_h { |event| [event.symbol.to_s, event.minimum_os] }
        write("codegen/overlay/availability.yml", YAML.dump(availability))
        write("codegen/snapshots/#{version}.json", JSON.pretty_generate(snapshot(version, ir)) << "\n")
      end

      def capture(*command)
        output, status = Open3.capture2(*command)
        raise CodegenError, "#{command.join(" ")} failed" unless status.success?

        output.strip
      end

      def write(path, content)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, content) unless File.exist?(path) && File.binread(path) == content
      end

      def snapshot(version, event_types_ir)
        {
          sdk_version: version,
          last: event_types_ir.last,
          events: event_types_ir.events.map(&:to_h)
        }
      end
    end
  end
end

EndpointSecurity::Codegen::Run.call if $PROGRAM_NAME == __FILE__
