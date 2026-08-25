# frozen_string_literal: true

module EndpointSecurity
  module Codegen
    Event = Data.define(:name, :symbol, :value, :minimum_os, :reserved)
    EventTypes = Data.define(:events, :last)

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
    end
  end
end
