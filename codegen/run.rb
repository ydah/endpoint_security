# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "yaml"
require_relative "../lib/endpoint_security/errors"
require_relative "ast"
require_relative "ir"
require_relative "emit_ruby"
require_relative "emit_c"

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
        umbrella = File.join(sdk, "usr/include/EndpointSecurity/EndpointSecurity.h")
        schema_ast = AST.load(header: umbrella, sdk: sdk)
        message_sources = %w[ESMessage.h ESMessageCore.h].map do |name|
          File.read(File.join(sdk, "usr/include/EndpointSecurity", name))
        end
        records = IR.records(ast: schema_ast, version_sources: message_sources)
        enumerations = IR.enumerations(ast: schema_ast)
        emitter = EmitRuby.new(
          ir, cacheable: IR.cacheable_events(message_sources.first, ir), enumerations: enumerations
        )

        write("lib/endpoint_security/generated/event_types.rb", emitter.event_types)
        write("lib/endpoint_security/generated/enums.rb", emitter.enums)
        write("lib/endpoint_security/generated/availability.rb", emitter.availability)
        write("ext/endpoint_security/generated/es_schema.c", EmitC.new(records, ir).schema)
        availability = ir.events.to_h { |event| [event.symbol.to_s, event.minimum_os] }
        write("codegen/overlay/availability.yml", YAML.dump(availability))
        write("codegen/overlay/version_map.yml", YAML.dump(version_map(records)))
        snapshot_json = JSON.pretty_generate(snapshot(version, ir, records, enumerations)) << "\n"
        write("codegen/snapshots/#{version}.json", snapshot_json)
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

      def version_map(records)
        versions = records.to_h do |record|
          fields = record.fields.select { |field| field.minimum_version > 1 }
          [record.name, fields.to_h { |field| [field.name, field.minimum_version] }]
        end
        versions.reject { |_record, fields| fields.empty? }
      end

      def snapshot(version, event_types_ir, records, enumerations)
        {
          sdk_version: version,
          last: event_types_ir.last,
          events: event_types_ir.events.map(&:to_h),
          records: records.to_h { |record| [record.name, record.fields.map(&:to_h)] },
          enumerations: enumerations.to_h { |enumeration| [enumeration.name, enumeration.values.map(&:to_h)] }
        }
      end
    end
  end
end

EndpointSecurity::Codegen::Run.call if $PROGRAM_NAME == __FILE__
