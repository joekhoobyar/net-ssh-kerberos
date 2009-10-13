require 'net/ssh/kerberos/sspi/api'

module Net; module SSH; module Kerberos; module SSPI; class Context

  class GeneralError < StandardError; end

  include Win32::SSPI

  attr_reader :cred_name, :cred_krb_name, :server_name, :server_krb_name

  def create(user, host)
    dispose if @credentials or @handle
    creds = CredHandle.new
    ts = TimeStamp.new

    result = API::AcquireCredentialsHandle nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil, nil, nil, creds, ts
    result.ok? or raise GeneralError, "Error acquiring credentials: #{result}"
    
		buff = "\0\0\0\0"
		result = API::QueryCredentialsAttributes creds, SECPKG_CRED_ATTR_NAMES, buff
    if result.ok?
      names = buff.to_ptr.ptr
      begin
        @cred_name = names.to_s.sub(/^[^\\\/]*[\\\/]/, '')
        @cred_krb_name = @cred_name.gsub('@', '/');
        @server_name = Socket.gethostbyname(host)[0]
        @server_krb_name = "host/" + @server_name

        z = (user.include?('@') ? user.gsub('@','/') : user+'/')
        unless z.downcase == @cred_krb_name[0,z.length].downcase
          raise GeneralError, "Credentials mismatch: current is #{@cred_name}, requested is #{user}"
        end
        @credentials = creds
      ensure
        @credentials or API::FreeCredentialsHandle creds
        API::FreeContextBuffer names
      end
    end
  end

  def credentials?; ! @credentials.nil? end
  
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
    @state = { :handle => ctx, :result => result, :token => output.token, :stamp => ts }
    if result.complete?
			result = API::QueryContextAttributes ctx, SECPKG_ATTR_SIZES, @sizes=SecPkgSizes.new
			@handle = @state[:handle]
    end
    @state[:token]
  end
  
  def established?
    ! @handle.nil? && (@state.nil? || @state[:result].value.zero?)
  end
  
  def get_mic(token=nil)
    buffers = SecurityBuffer.new 2
    buffers.set_buffer 0, SECBUFFER_DATA, token
    buffers.set_buffer 1, SECBUFFER_TOKEN, nil, @sizes.max_signature
    @state[:result] = API::MakeSignature @handle, 0, buffers, 0
    unless @state[:result].ok?
      raise GeneralError, "Error creating the signature: #{result}"
    end
    return buffers.token(1).dup
  end
  
  def dispose()
    @credentials and API::FreeCredentialsHandle @credentials
    @handle and API::DeleteSecurityContext @handle
  ensure
    @credentials = @handle = nil
  end 

end; end; end; end; end
