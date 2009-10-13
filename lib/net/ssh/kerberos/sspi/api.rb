require 'win32/sspi'
require 'dl'

module Win32; module SSPI

  SECPKG_CRED_ATTR_NAMES = 1

  ISC_REQ_DELEGATE                = 0x00000001
  ISC_REQ_MUTUAL_AUTH             = 0x00000002

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

	SECURITY_NATIVE_DREP       = 16;
  SECURITY_NETWORK_DREP      = 0;

  module API
    QuerySecurityPackageInfo = Win32API.new("secur32", "QuerySecurityPackageInfoA", 'pp', 'L')
    QueryCredentialsAttributes = Win32API.new("secur32", "QueryCredentialsAttributesA", 'pLp', 'L')
    CompleteAuthToken = Win32API.new("secur32", "CompleteAuthToken", 'pp', 'L')
    FreeContextBuffer = Win32API.new("secur32", "FreeContextBuffer", 'P', 'L')
  end

  SecPkgCredentialsNames = Struct.new(:user_name)
  
  class SecPkgInfo
    attr_reader :struct
    
    def capabilities; unpacked[0] end
    def max_token; unpacked[2] end
    def name; unpacked[3] end
    def comment; unpacked[4] end 
    
    def unpacked;
      @unpacked ||= @struct.to_ptr.ptr.to_a("LLL", 3) + (@struct.to_ptr.ptr + 12).to_a("SS", 2)
    end
    
    def to_p; @struct ||= "\0" * 4 end
	end

end; end

module Net; module SSH; module Kerberos; class SSPI

  class GeneralError < StandardError; end

  include Win32::SSPI

  def create(user, host)
    dispose if @credentials or @handle
    @credentials = CredHandle.new
    ts=Timestamp.new

    result = SSPIResult.new(API::AcquireCredentialsHandle.call(
                              nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil,
                              nil, nil, @credentials.to_p, ts.to_p
                            ))
    unless result.ok?
      @credentials = nil
      raise GeneralError, "Error acquiring credentials: #{result}"
    end
    
		buff = "\0\0\0\0"
		result = SSPIResult.new(API::QueryCredentialsAttributes.call(@credentials.to_p, SECPKG_CRED_ATTR_NAMES, buff))
    if result.ok?
      names = buff.to_ptr.ptr
      begin
        @cred_name = names.sub /^.*\\/, ''
        @cred_krb_name = @cred_name.gsub '@', '/';
        @server_name = Socket.gethostbyname(host)[0]
        @server_krb_name = "host/" + @server_name
      ensure
        API::FreeContextBuffer.call(names)
      end
    end
    cred_names = SecPkgCredentialsNames.new(names)
  end
  
  def init(token=nil)
    ctx = CtxtHandle.new
    ts = Timestamp.new
    prev = @state[:handle].to_p if @state and @state[:handle]
    req = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY
		input = SecurityBuffer.new(token).to_p if token
		output = SecurityBuffer.new
		ctxAttr = "\0" * 4
		result = SSPIResult.new(API::InitializeSecurityContext.call(creds.to_p, prev, @server_krb_name,
					                      req, 0, SECURITY_NATIVE_DREP, input, 0, ctx.to_p, output.to_p, ctxAttr, ts.to_p))
    if SEC_I_COMPLETE_NEEDED == result || SEC_I_COMPLETE_AND_CONTINUE == result
			result = SSPIResult.new(API::CompleteAuthToken.call(ctx.to_p, output.to_p))
    end
    unless result.ok?
      raise GeneralError, "Error initializing security context: #{result}"
    end
    @state = { :handle => ctx, :result => result, :buffers => output.buffer, :stamp => ts }
      
    if result == 0
    end
  end
  
  def dispose()
    if @credentials
      API::FreeCredentialsHandle(@credentials.to_p)
      @credentials = nil
    end
    if @handle
      API::DeleteSecurityContext(@handle.to_p)
      @handle = nil
    end
  end 

end; end; end; end
