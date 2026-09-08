# frozen_string_literal: true

require_relative "lib/endpoint_security/version"

Gem::Specification.new do |spec|
  spec.name = "endpoint_security"
  spec.version = EndpointSecurity::VERSION
  spec.authors = ["Yudai Takada"]
  spec.email = ["t.yudai92@gmail.com"]

  spec.summary = "Ruby bindings for Apple's EndpointSecurity framework"
  spec.description = "A native Ruby interface to macOS EndpointSecurity."
  spec.homepage = "https://github.com/YudaiTakada/endpoint_security"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"
  spec.platform = Gem::Platform.new("universal-darwin")
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ bench/ test/ Gemfile .gitignore .rspec spec/ .github/ site/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/endpoint_security/extconf.rb"]
end
