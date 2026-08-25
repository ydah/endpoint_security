# frozen_string_literal: true

require "mkmf"
require "open3"
require "shellwords"

abort "endpoint_security requires macOS 13 or newer" unless RUBY_PLATFORM.include?("darwin")

sdk, status = Open3.capture2("xcrun", "--show-sdk-path")
abort "xcrun could not locate the macOS SDK; install Xcode Command Line Tools" unless status.success?

sdk = sdk.strip
dir_config("endpoint_security", File.join(sdk, "usr/include"), File.join(sdk, "usr/lib"))
$CFLAGS << " -std=c11 -fblocks -Wall -Wextra -Wno-unused-parameter -Werror=implicit-function-declaration"
$CFLAGS << " -fvisibility=hidden -mmacosx-version-min=13.0"
$LDFLAGS << " -isysroot #{sdk.shellescape} -mmacosx-version-min=13.0"
$INCFLAGS << " -I#{File.expand_path("../../support/esmock", __dir__).shellescape}"

abort "EndpointSecurity headers are missing from #{sdk}" unless have_header("EndpointSecurity/EndpointSecurity.h")
if ENV["ES_MOCK"] == "1"
  $defs << "-DESRB_MOCK"
  $LDFLAGS << " -L#{File.expand_path("../../build", __dir__).shellescape} -Wl,-rpath,@loader_path/../../build"
  endpoint_security_found = have_library("esmock")
else
  endpoint_security_found = have_framework("EndpointSecurity") || have_library("EndpointSecurity")
end
abort "EndpointSecurity library is unavailable" unless endpoint_security_found
abort "libbsm is unavailable" unless have_library("bsm")

create_makefile("endpoint_security/endpoint_security")
