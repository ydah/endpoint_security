# frozen_string_literal: true

module EndpointSecurity
  module Codegen
    Event = Data.define(:name, :symbol, :value, :minimum_os, :reserved)
    EventTypes = Data.define(:events, :last)
    Field = Data.define(:name, :type, :minimum_version)
    Record = Data.define(:name, :fields)

    class IR
      AVAILABILITY = /available beginning in macOS ([0-9]+(?:\.[0-9]+){1,2})/i
      EVENT = /\b(ES_EVENT_TYPE_[A-Z0-9_]+)\b/

      def self.event_types(ast:, source:)
        availability = scan_availability(source)
        value = -1
        last = nil
        entries = ast.enum_containing("ES_EVENT_TYPE_AUTH_EXEC").fetch("inner", []).filter_map do |node|
          next unless node["kind"] == "EnumConstantDecl"

          value = explicit_value(node) || (value + 1)
          if node["name"] == "ES_EVENT_TYPE_LAST"
            last = value
            next
          end

          symbol = node["name"].delete_prefix("ES_EVENT_TYPE_").downcase.to_sym
          Event.new(node["name"], symbol, value, availability.fetch(node["name"]), symbol.start_with?("reserved_"))
        end

        unless last == entries.length
          raise CodegenError, "ES_EVENT_TYPE_LAST=#{last}, but #{entries.length} events were parsed"
        end

        EventTypes.new(entries.freeze, last)
      end

      def self.scan_availability(source)
        first_event = source.index("ES_EVENT_TYPE_AUTH_EXEC")
        raise CodegenError, "es_event_type_t was not found" unless first_event

        source = source[source.rindex("typedef enum {", first_event)..]
        current = nil

        source.each_line.with_object({}) do |line, versions|
          availability_match = line.match(AVAILABILITY)
          current = availability_match[1] if availability_match
          name = line[EVENT, 1]
          versions[name] = current if name && name != "ES_EVENT_TYPE_LAST"
          break versions if line.include?("} es_event_type_t;")
        end
      end

      def self.explicit_value(node)
        pending = node.fetch("inner", []).dup
        until pending.empty?
          child = pending.shift
          return Integer(child["value"]) if child.key?("value")

          pending.concat(child.fetch("inner", []))
        end
        nil
      end

      private_class_method :explicit_value

      def self.records(ast:, version_sources:)
        versions = scan_field_versions(version_sources)
        ast.typedef_records.filter_map do |name, node|
          direct = node.fetch("inner", []).select { |child| child["kind"] == "FieldDecl" && child["name"] }
          indirect_fields = node.fetch("inner", []).select { |child| child["kind"] == "IndirectFieldDecl" }
          indirect = indirect_fields.filter_map do |child|
            recursive_field(node, child["name"])
          end
          fields = (direct + indirect).uniq { |field| field["name"] }.filter_map do |field|
            next if field["name"].start_with?("reserved")

            type = field.dig("type", "desugaredQualType") || field.dig("type", "qualType")
            minimum_version = versions.fetch([name, field["name"]], versions.fetch(field["name"], 1))
            Field.new(field["name"], type, minimum_version)
          end
          next if fields.empty?

          Record.new(name, fields.freeze)
        end.freeze
      end

      def self.scan_field_versions(sources)
        sources.each_with_object({}) do |source, versions|
          source.each_line do |line|
            match = line.match(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:;|\[[^\]]+\];)[^\n]*message version >= (\d+)/)
            versions[match[1]] = Integer(match[2]) if match
          end
        end
      end

      def self.recursive_field(node, name)
        pending = node.fetch("inner", []).dup
        until pending.empty?
          child = pending.shift
          return child if child["kind"] == "FieldDecl" && child["name"] == name

          pending.concat(child.fetch("inner", []))
        end
        nil
      end

      private_class_method :recursive_field

      def self.cacheable_events(source, events)
        cacheable_structs = source.to_enum(:scan, /}\s*(es_event_[a-zA-Z0-9_]+_t);/).filter_map do
          match = Regexp.last_match
          comment_start = source.rindex("/**", match.begin(0))
          match[1] if comment_start && source[comment_start...match.begin(0)].include?("Cache key for this event type")
        end
        suffixes = cacheable_structs.map { |name| name.delete_prefix("es_event_").delete_suffix("_t") }
        events.events.select do |event|
          suffixes.include?(event.symbol.to_s.sub(/\A(?:auth|notify)_/, ""))
        end.map(&:symbol)
      end
    end
  end
end
