require 'win32/sspi'

module Net; module SSH; module Kerberos
  module SSPI

    include Win32::SSPI

    class State
      def valid?
        false
      end
    end

    # Acquires credentials for SSPI (GSSAPI) authentication, and determines
    # the credential's username and realm.
    def sspi_acquire_credentials(state)
      #SecPkgCredentials_Names names
      #char *delimiter, *cp

      state.valid? and return true

      #sspi->from_server_token.BufferType = SECBUFFER_TOKEN | SECBUFFER_READONLY;

      # Acquire credentials
      @credentials, ts = SecurityHandle.new, TimeStamp.new
      result = SSPIResult.new(API::AcquireCredentialsHandle.call(
                  nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil
                  nil, nil, @credentials.to_p, ts.to_p
                ))
      unless result.ok?
        #logeventf(ssh, "AcquireCredentialsHandle: %s", sspi_error_string(status));
        @credentials = nil
        return
      end

      #debug(("  QueryCredentialsAttributes(%s,NAMES)\n", 
      #HDL(&sspi->credentials)));
      #status = SecurityCredentialsNames.new(API::QueryCredentialsAttributes.call(names, SECPKG_CRED_ATTR_NAMES, &names))
      unless result.ok?
        #logeventf(ssh, "QueryCredentialsAttributes(NAMES): %s", sspi_error_string(status))
        result = SSPIResult.new(API::FreeCredentialsHandle.call(@credentials.to_p))
        unless results.ok?
          #logeventf(ssh, "FreeCredentialsHandle: %s", sspi_error_string(status))
        end
        @credentials = nil
        return
      end
      #debug(("    QueryCredentialsAttributes -> %x \"%.200s\"\n", names.sUserName, names.sUserName));
      #logeventf(ssh, "SSPI: acquired credentials for: %s", names.sUserName);
      domain, realm = *names.user_name.split('@')

      #debug(("  FreeContextBuffer(%x)\n", names.sUserName));
      #result = SSPIResult.new(API::FreeContextBuffer(names.user.to_p))
      unless result.ok?
        #logeventf(ssh, "FreeContextBuffer: %s", sspi_error_string(status));
      end

      #debug(("  FreeCredentialsHandle(%s)\n", HDL(&sspi->credentials)));
      result = SSPIResult.new(FreeCredentialsHandle(@credentials.to_p))
      unless result.ok?
        logeventf(ssh, "FreeCredentialsHandle: %s", sspi_error_string(status));
      end

      #*delimiter = '\0';
      #strncpy(sspi->cred_name, names.sUserName, sizeof sspi->cred_name - 1);
      #strncpy(sspi->cred_realm, delimiter + 1, sizeof sspi->cred_realm - 1);

      #debug(("  FreeContextBuffer(%x)\n", names.sUserName));
      #result = SSPIResult.new(API::FreeContextBuffer(names.user.to_p))
      unless result.ok?
        logeventf(ssh, "FreeContextBuffer: %s", sspi_error_string(status));
      end

      # Sometimes, Microsoft SSPI returns a UPN of the form "user@REALM@",
      # (Seen under WinXP pro after ksetup to a MIT realm). Deal with that.
      realm.chop if realm[-1] == '@'

      # Initialise the request flags.
      sspi->request_flags = ISC_REQ_MUTUAL_AUTH | 
                             ISC_REQ_INTEGRITY |
                             ISC_REQ_CONFIDENTIALITY | 
                             ISC_REQ_ALLOCATE_MEMORY;
      #if (ssh->cfg.sspi_fwd_ticket)
      #  sspi->request_flags |= ISC_REQ_DELEGATE;

      #if (!sspi_construct_service_name(ssh, sspi)) {
        #debug(("  FreeCredentialsHandle(%s)\n", HDL(&sspi->credentials)));
      result = SSPIResult.new(FreeCredentialsHandle(@credentials.to_p))
      return if if result != SEC_E_OK

      sspi->valid = true
      return true
    end 

  end
end; end; end


