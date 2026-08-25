# frozen_string_literal: true

require "open3"

module EndpointSecurity
  # Reports whether a development host meets Endpoint Security requirements.
  module Doctor
    module_function

    # Prints development host checks to +out+.
    # @return [void]
    def run(out: $stdout)
      out.puts "Endpoint Security development host diagnosis"
      check(out, "macOS 13+", Gem::Version.new(`sw_vers -productVersion`.strip) >= Gem::Version.new("13"))
      check(out, "root", Process.euid.zero?)
      check(out, "SIP disabled", command("csrutil", "status").include?("disabled"))
      check(out, "AMFI development boot arg", command("nvram", "boot-args").include?("amfi_get_out_of_my_way=0x1"))
      out.puts "WARNING: Disable SIP only on a dedicated development machine."
    end

    # @api private
    # @return [String] captured command output
    def command(*argv)
      Open3.capture2e(*argv).first
    rescue Errno::ENOENT
      ""
    end

    # @api private
    # @return [void]
    def check(out, label, available)
      out.puts format("%<label>-28s %<status>s", label: label, status: available ? "OK" : "MISSING")
    end
  end
end
