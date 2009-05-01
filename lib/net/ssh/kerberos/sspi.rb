require 'win32/sspi'

module Win32; module SSPI

  SECPKG_CRED_ATTR_NAMES = 1

  SECPKG_ATTR_AUTHORITY = 6
  SECPKG_ATTR_CONNECTION_INFO = 90
  SECPKG_ATTR_ISSUER_LIST = 80
  SECPKG_ATTR_ISSUER_LIST_EX = 89
  SECPKG_ATTR_KEY_INFO = 5
  SECPKG_ATTR_LIFESPAN = 2
  SECPKG_ATTR_LOCAL_CERT_CONTEXT = 84
  SECPKG_ATTR_LOCAL_CRED = 82
  SECPKG_ATTR_NAMES = 1
  SECPKG_ATTR_PROTO_INFO = 7
  SECPKG_ATTR_REMOTE_CERT_CONTEXT = 83
  SECPKG_ATTR_REMOTE_CRED = 81
  SECPKG_ATTR_SIZES = 0
  SECPKG_ATTR_STREAM_SIZES = 4

  module API
    QueryCredentialsAttributes = Win32API.new("secur32", "QueryCredentialsAttributes", 'Plp', 'L')
    FreeContextBuffer = Win32API.new("secur32", "FreeContextBuffer", 'P', 'L')
  end

end; end

module Net; module SSH; module Kerberos
  module SSPI

    class GeneralError < StandardError; end

    include Win32::SSPI

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

      #debug(("  QueryCredentialsAttributes(%s,NAMES)\n", 
      #HDL(&sspi->credentials)));
      #status = SecurityCredentialsNames.new(API::QueryCredentialsAttributes.call(names, SECPKG_CRED_ATTR_NAMES, &names))
      unless result.ok? then sspi_free_credentials_handle; return; end

      #logeventf(ssh, "SSPI: acquired credentials for: %s", names.sUserName);
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

      #if (!sspi_construct_service_name(ssh, sspi)) {
        #debug(("  FreeCredentialsHandle(%s)\n", HDL(&sspi->credentials)));
      sspi_free_credentials_handle
      result.ok? or return

      sspi->valid = true
      return true
    end 

  private

    def sspi_free_context_buffer(b)
      result = SSPIResult.new(API::FreeContextBuffer(b.to_p))
      unless result.ok?
        #raise GeneralError, "Error freeing context_buffer: #{result}"
      end 
    end 

    def sspi_free_credentials_handle
      result = SSPIResult.new(API::FreeCredentialsHandle(@credentials.to_p))
      unless result.ok?
        @credentials = nil
        #raise GeneralError, "Error releasing credentials: #{result}"
      end 
    end 

    def sspi_acquire_credentials_handle(ts=Timestamp.new)
      sspi_free_credentials_handle if @credentials
      @credentials = SecurityHandle.new

      result = SSPIResult.new(API::AcquireCredentialsHandle.call(
                                nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil
                                nil, nil, @credentials.to_p, ts.to_p
                              ))
      unless result.ok?
        @credentials = nil
        raise GeneralError, "Error acquiring credentials: #{result}"
      end
    end
  end
end; end; end


