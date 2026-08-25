# frozen_string_literal: true

module EndpointSecurity
  module Diagnostics
    EXPLANATIONS = {
      success: "Endpoint Security client created successfully.",
      err_invalid_argument: "Endpoint Security rejected an invalid argument; this is likely a binding bug.",
      err_internal: "Endpoint Security reported an internal error; retry after checking system logs.",
      err_not_entitled: "The host Ruby executable lacks the Endpoint Security client entitlement.",
      err_not_permitted: "Grant Full Disk Access to the host Ruby executable.",
      err_not_privileged: "Run the signed host Ruby executable as root.",
      err_too_many_clients: "Close another Endpoint Security client and retry."
    }.freeze

    module_function

    def explain(result)
      EXPLANATIONS.fetch(result.to_sym) { "Unknown es_new_client result: #{result.inspect}." }
    end
  end
end
