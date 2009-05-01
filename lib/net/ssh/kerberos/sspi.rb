require 'net/ssh/kerberos/sspi/api'

module Net; module SSH; module Kerberos
  module SSPI

    class State
      attr_accessor :name, :realm, :valid
      alias :valid? :valid
    end

    # Acquires credentials for SSPI (GSSAPI) authentication, and determines
    # the credential's username and realm.
    def sspi_acquire_credentials(state)
      #SecPkgCredentials_Names names
      #char *delimiter, *cp

      state.valid? and return true

      #sspi->from_server_token.BufferType = SECBUFFER_TOKEN | SECBUFFER_READONLY;

      # Acquire credentials
      sspi_acquire_credentials_handle
      names = sspi_query_credentials_names
      state.name, state.realm = *names.user_name.split('@')

      #debug(("  FreeContextBuffer(%x)\n", names.sUserName));
      #result = SSPIResult.new(API::FreeContextBuffer(names.user.to_p))
      sspi_free_context_buffer names
      sspi_free_credentials_handle

      # Sometimes, Microsoft SSPI returns a UPN of the form "user@REALM@",
      # (Seen under WinXP pro after ksetup to a MIT realm). Deal with that.
      realm.chop if realm[-1] == '@'

      # Initialise the request flags.
      #sspi->request_flags = ISC_REQ_MUTUAL_AUTH | 
      #                       ISC_REQ_INTEGRITY |
      #                       ISC_REQ_CONFIDENTIALITY | 
      #                       ISC_REQ_ALLOCATE_MEMORY;
      #if (ssh->cfg.sspi_fwd_ticket)
      #  sspi->request_flags |= ISC_REQ_DELEGATE;

      if ! sspi_construct_service_name state
        state.valid = true
      #if (!sspi_construct_service_name(ssh, sspi)) {
        #debug(("  FreeCredentialsHandle(%s)\n", HDL(&sspi->credentials)));
      else
        sspi_free_credentials_handle
      end
    end 
  end
end; end; end


