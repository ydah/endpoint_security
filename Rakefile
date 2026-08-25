# frozen_string_literal: true

require "bundler/gem_tasks"
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

namespace :test do
  task native: :compile
  task drift: :compile
  task sanitize: :compile
  task integration: :compile
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

task default: %i[compile test rubocop]
