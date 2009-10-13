require 'net/ssh/kerberos/sspi/api'

module Net; module SSH; module Kerberos; module SSPI; class GSSContext

  class GeneralError < StandardError; end

  include Win32::SSPI

  def create(user, host)
    dispose if @credentials or @handle
    @credentials = CredHandle.new
    ts=TimeStamp.new

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
        @cred_name = names.to_s.sub /^.*\\/, ''
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
    ts = TimeStamp.new
    prev = @state[:handle].to_p if @state and @state[:handle]
    req = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY
		output = SecurityBuffer.new
		input = SecurityBuffer.new(token) if token
		ctxAttr = "\0" * 4
		result = SSPIResult.new(API::InitializeSecurityContext.call(@credentials.to_p, prev, @server_krb_name,
					                      req, 0, SECURITY_NATIVE_DREP, input ? input.to_p : nil,
					                      0, ctx.to_p, output.to_p, ctxAttr, ts.to_p))
    if SEC_I_COMPLETE_NEEDED == result || SEC_I_COMPLETE_AND_CONTINUE == result
			result = SSPIResult.new(API::CompleteAuthToken.call(ctx.to_p, output.to_p))
    end
    unless result.ok?
      input.token
      raise GeneralError, "Error initializing security context: #{result} #{input.inspect}"
    end
    @state = { :handle => ctx, :result => result, :token => output.token, :stamp => ts }
    if result.value == 0
      @sizes = SecPkgSizes.new
			result = SSPIResult.new(API::QueryContextAttributes.call(ctx.to_p, SECPKG_ATTR_SIZES, @sizes.to_p))
			@handle = @state[:handle]
    end
    @state[:token]
  end
  
  def established?
    @handle && (@handle.upper.nonzero? || @handle.lower.nonzero?) && (@state.nil? || @state[:result].value.zero?)
  end
  
  def get_mic(token=nil)
    buffers = SecurityBuffer.new 2
    buffers.set_buffer 0, SECBUFFER_DATA, token
    buffers.set_buffer 1, SECBUFFER_TOKEN, nil, @sizes.max_signature
    @state[:result] = SSPIResult.new(API::MakeSignature.call(@handle.to_p, 0, buffers.to_p, 0))
    unless @state[:result].ok?
      raise GeneralError, "Error creating the signature: #{result}"
    end
    return buffers.token(1).dup
  end
  
  def dispose()
    if @credentials
      API::FreeCredentialsHandle.call(@credentials.to_p)
      @credentials = nil
    end
    if @handle
      API::DeleteSecurityContext.call(@handle.to_p)
      @handle = nil
    end
  end 

end; end; end; end; end
