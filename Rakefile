# frozen_string_literal: true

require "bundler/gem_tasks"
require "fileutils"
require "open3"
require "rake/extensiontask"
require "rspec/core/rake_task"

Rake::ExtensionTask.new("endpoint_security") do |ext|
  ext.ext_dir = "ext/endpoint_security"
  ext.lib_dir = "lib/endpoint_security"
end

RSpec::Core::RakeTask.new("test:unit") do |task|
  task.pattern = "test/unit/**/*_test.rb"
  task.rspec_opts = "-Itest"
end

RSpec::Core::RakeTask.new("test:native:spec") do |task|
  task.pattern = "test/native/**/*_test.rb"
  task.rspec_opts = "-Itest"
end

RSpec::Core::RakeTask.new("test:integration:spec") do |task|
  task.pattern = "test/integration/**/*_test.rb"
  task.rspec_opts = "-Itest"
end

task "compile:mock" do
  Rake::Task[:clobber].invoke
  sdk = `xcrun --show-sdk-path`.strip
  FileUtils.mkdir_p("build")
  sh "xcrun", "clang", "-dynamiclib", "-fblocks", "-std=c11", "-Wall", "-Wextra",
     "-Werror", "-mmacosx-version-min=13.0", "-isysroot", sdk, "-I#{sdk}/usr/include",
     "-install_name", "@rpath/libesmock.dylib",
     "support/esmock/esmock.c", "-o", "build/libesmock.dylib"
  sh({ "ES_MOCK" => "1" }, RbConfig.ruby, "-S", "rake", "clobber", "compile")
end

task "compile:real" do
  sh({ "ES_MOCK" => nil }, RbConfig.ruby, "-S", "rake", "clobber", "compile")
end

task "test:eslogger" do
  require_relative "lib/endpoint_security/generated/event_types"

  output, status = Open3.capture2e("/usr/bin/eslogger", "--list-events")
  raise "eslogger --list-events failed: #{output}" unless status.success?

  actual = output.lines.map { |line| line.strip.to_sym }.reject { |event| event.to_s.empty? }.sort
  expected = EndpointSecurity::EventType.all_notify.map { |event| event.to_s.delete_prefix("notify_").to_sym }.sort
  missing = expected - actual
  extra = actual - expected
  unless missing.empty? && extra.empty?
    raise "eslogger drifted (missing: #{missing.join(", ")}; extra: #{extra.join(", ")})"
  end
end

task "test:api_surface" do
  sdk = `xcrun --show-sdk-path`.strip
  header = File.read(File.join(sdk, "usr/include/EndpointSecurity/ESClient.h")).gsub(%r{/\*.*?\*/}m, "")
  declarations = header.split(";").filter_map do |statement|
    name = statement.scan(/\b(es_[a-z0-9_]+)\s*\(/).last&.first
    [name, statement.include?("API_DEPRECATED")] if name
  end
  native = Dir["ext/endpoint_security/*.c"].map { |path| File.read(path) }.join
  missing = declarations.reject(&:last).map(&:first).reject { |name| native.match?(/\b#{Regexp.escape(name)}\s*\(/) }
  deprecated = declarations.select(&:last).map(&:first).select { |name| native.match?(/\b#{Regexp.escape(name)}\s*\(/) }
  raise "unbound Endpoint Security functions: #{missing.join(", ")}" unless missing.empty?
  raise "deprecated Endpoint Security functions used: #{deprecated.join(", ")}" unless deprecated.empty?
end

namespace :test do
  task native: ["compile:mock", "test:native:spec"]
  task :drift do
    require_relative "lib/endpoint_security/generated/event_types"

    generated_roots = "{codegen/overlay,codegen/snapshots," \
                      "ext/endpoint_security/generated,lib/endpoint_security/generated}"
    files = Dir["#{generated_roots}/**/*"].select { |path| File.file?(path) }
    before = files.to_h { |path| [path, File.binread(path)] }
    Rake::Task[:codegen].invoke
    after_files = Dir["#{generated_roots}/**/*"].select { |path| File.file?(path) }
    changed = (files | after_files).reject { |path| before[path] == (File.binread(path) if File.exist?(path)) }
    raise "generated files drifted: #{changed.join(", ")}" unless changed.empty?

    Rake::Task["test:eslogger"].invoke
    Rake::Task["test:api_surface"].invoke
  end
  task :sanitize do
    sdk = `xcrun --show-sdk-path`.strip
    %w[address,undefined thread].each do |sanitizer|
      output = "tmp/queue_#{sanitizer.tr(",", "_")}"
      sh "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", "-isysroot", sdk,
         "-I#{sdk}/usr/include", "-Iext/endpoint_security", "-fsanitize=#{sanitizer}",
         "test/native/queue_stress.c", "ext/endpoint_security/queue.c", "-o", output
      sh output
    end
  end
  task integration: ["compile:real", "test:integration:spec"]
end

desc "Generate Ruby and native schema files from the active macOS SDK"
task :codegen do
  ruby "codegen/run.rb"
end

task test: ["test:unit", "test:native", "test:drift"]

task :rubocop do
  sh "rubocop"
end

desc "Build API documentation"
task :yard do
  stats, status = Open3.capture2e("yard", "stats", "--list-undoc", "lib")
  puts stats
  raise "YARD coverage is below 100%" unless status.success? && stats.include?("100.00% documented")

  sh "yard", "doc", "lib"
end

namespace :dev do
  desc "Diagnose the host requirements for Endpoint Security"
  task :doctor do
    require_relative "lib/endpoint_security/doctor"
    EndpointSecurity::Doctor.run
  end
end

namespace :sign do
  desc "Copy and sign a Ruby executable with the Endpoint Security entitlement"
  task :ruby, %i[ruby developer_id] do |_task, arguments|
    ruby = arguments[:ruby] || RbConfig.ruby
    identity = arguments[:developer_id] || "-"
    sh "support/sign_ruby.sh", ruby, identity
  end
end

desc "Run the mock delivery throughput benchmark"
task :bench do
  Rake::Task["compile:mock"].invoke
  ruby "bench/throughput.rb"
end

task default: %i[compile test rubocop yard]
