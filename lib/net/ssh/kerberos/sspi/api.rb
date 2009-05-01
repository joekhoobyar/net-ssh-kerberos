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

  SecPkgCredentialsNames = Struct.new(:user_name)

end; end

module Net; module SSH; module Kerberos; module SSPI

  class GeneralError < StandardError; end

  include Win32::SSPI


private

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

  def sspi_query_credentials_names
    names = [0].pack('S')
    result = SSPIResult.new(API::QueryCredentialsAttributes.call(
                              @credentials, SECPKG_CRED_ATTR_NAMES, names.to_p
                            ))
    unless result.ok?
      sspi_free_credentials_handle
      raise GeneralError, "Error querying credentials names: #{result}"
    end
    cred_names = SecPkgCredentialsNames.new(names)
  end

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

end; end; end; end
