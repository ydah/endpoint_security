# frozen_string_literal: true

require "json"
require "open3"

module EndpointSecurity
  module Codegen
    class AST
      def self.load(header:, sdk:)
        output, error, status = Open3.capture3(
          "xcrun", "clang", "-x", "c", "-isysroot", sdk,
          "-Xclang", "-ast-dump=json", "-fsyntax-only", "-fparse-all-comments", header
        )
        raise CodegenError, "clang AST extraction failed: #{error}" unless status.success?

        new(JSON.parse(output))
      end

      def initialize(root)
        @root = root
      end

      def enum_containing(constant)
        walk.find do |node|
          node["kind"] == "EnumDecl" && node.fetch("inner", []).any? { |child| child["name"] == constant }
        end || raise(CodegenError, "enum containing #{constant} was not found")
      end

      def typedef_records
        nodes = walk.to_a
        by_id = nodes.to_h { |node| [node["id"], node] }
        nodes.filter_map do |node|
          next unless node["kind"] == "TypedefDecl" && node["name"]&.start_with?("es_")

          record_id = node.dig("inner", 0, "ownedTagDecl", "id")
          record = by_id[record_id]
          [node["name"], record] if record&.fetch("completeDefinition", false)
        end.to_h
      end

      def typedef_enums
        nodes = walk.to_a
        by_id = nodes.to_h { |node| [node["id"], node] }
        nodes.filter_map do |node|
          next unless node["kind"] == "TypedefDecl" && node["name"]&.start_with?("es_")

          enum_id = node.dig("inner", 0, "ownedTagDecl", "id")
          enum = by_id[enum_id]
          [node["name"], enum] if enum&.fetch("kind", nil) == "EnumDecl"
        end.to_h
      end

      private

      def walk
        Enumerator.new do |items|
          pending = [@root]
          until pending.empty?
            node = pending.pop
            items << node
            pending.concat(node.fetch("inner", []).reverse)
          end
        end
      end
    end
  end
end
