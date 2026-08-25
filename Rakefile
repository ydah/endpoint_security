# frozen_string_literal: true

require "bundler/gem_tasks"
require "fileutils"
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
  ENV["ES_MOCK"] = "1"
  Rake::Task[:compile].reenable
  Rake::Task[:compile].invoke
end

task "compile:real" do
  ENV.delete("ES_MOCK")
  Rake::Task[:clobber].invoke
  Rake::Task[:compile].reenable
  Rake::Task[:compile].invoke
end

namespace :test do
  task native: ["compile:mock", "test:native:spec"]
  task :drift do
    generated_roots = "{codegen/overlay,codegen/snapshots," \
                      "ext/endpoint_security/generated,lib/endpoint_security/generated}"
    files = Dir["#{generated_roots}/**/*"].select { |path| File.file?(path) }
    before = files.to_h { |path| [path, File.binread(path)] }
    Rake::Task[:codegen].invoke
    after_files = Dir["#{generated_roots}/**/*"].select { |path| File.file?(path) }
    changed = (files | after_files).reject { |path| before[path] == (File.binread(path) if File.exist?(path)) }
    raise "generated files drifted: #{changed.join(", ")}" unless changed.empty?
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

task default: %i[compile test rubocop]
