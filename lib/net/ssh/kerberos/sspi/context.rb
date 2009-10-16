require 'net/ssh/kerberos/common/context'
require 'net/ssh/kerberos/sspi/api'

module Net; module SSH; module Kerberos; module SSPI; class Context < Common::Context

  include Win32::SSPI
  
  def init(token=nil)
    ctx = CtxtHandle.new
    ts = TimeStamp.new
    prev = @state[:handle] if @state
    req = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY
		output = SecurityBuffer.new
		input = SecurityBuffer.new(token) if token
		ctxAttr = "\0" * 4
		result = API::InitializeSecurityContext @credentials, prev, @server_krb_name, req, 0,
                                            SECURITY_NATIVE_DREP, input, 0, ctx, output, ctxAttr, ts
    result = API::CompleteAuthToken ctx, output if result.incomplete?
    if result.failure?
      input.token and raise GeneralError, "Error initializing security context: #{result} #{input.inspect}"
    end
    @state = State.new(ctx, result, output.token, ts)
    if result.complete?
			result = API::QueryContextAttributes ctx, SECPKG_ATTR_SIZES, @sizes=SecPkgSizes.new
			@handle = @state.handle
    end
    @state.token
  end
  
  def get_mic(token=nil)
    buffers = SecurityBuffer.new 2
    buffers.set_buffer 0, SECBUFFER_DATA, token
    buffers.set_buffer 1, SECBUFFER_TOKEN, nil, @sizes.max_signature
    @state.result = API::MakeSignature @handle, 0, buffers, 0
    unless @state.result.complete? and (token = buffers.token(1))
      raise GeneralError, "Error creating the signature: #{result}"
    end

    begin return token.dup
    ensure API::FreeContextBuffer token
    end
  end
  
private
  
  def acquire_current_credentials
    result = API::AcquireCredentialsHandle nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil, nil, nil,
                                           creds=CredHandle.new, ts=TimeStamp.new
    result.ok? or raise GeneralError, "Error acquiring credentials: #{result}"
    
		buff = "\0\0\0\0"
		result = API::QueryCredentialsAttributes creds, SECPKG_CRED_ATTR_NAMES, buff
    if result.ok?
      name = buff.to_ptr.ptr
      begin return [creds, name.to_s.dup]
      ensure API::FreeContextBuffer name
      end
    end
  end

  def release_credentials(creds)
    creds.nil? or API::FreeCredentialsHandle creds
  end

  def delete_context(handle)
    handle.nil? or API::DeleteSecurityContext handle
  end

end; end; end; end; end
