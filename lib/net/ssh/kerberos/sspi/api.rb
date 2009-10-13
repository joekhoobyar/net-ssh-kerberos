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

  module API
    QuerySecurityPackageInfo = Win32API.new("secur32", "QuerySecurityPackageInfoA", 'pp', 'L')
    QueryCredentialsAttributes = Win32API.new("secur32", "QueryCredentialsAttributesA", 'pLp', 'L')
    QueryContextAttributes = Win32API.new("secur32", "QueryContextAttributesA", 'pLp', 'L')
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

	class SecPkgSizes
	  attr_reader :struct
	  
	  def max_token; unpacked[0] end
	  def max_signature; unpacked[1] end
	  def block_size; unpacked[2] end 
	  def security_trailer; unpacked[3] end
	  
	  def unpacked;
	    @unpacked ||= @struct.to_ptr.ptr.to_a("LLLL", 4)
	  end
	  
	  def to_p; @struct ||= "\0" * 4 end
	end
	
	# Creates binary representaiton of a SecBufferDesc structure,
	# including the SecBuffer contained inside.
	class SecurityBuffer
	
	  def initialize(buffers=nil)
	    case buffers
	    when String
		    @bufferTokens = [ buffers ]
		    @bufferSizes = [ buffers.length ]
		    @bufferTypes = [ SECBUFFER_TOKEN ]
		  when Fixnum
		    @bufferTokens = [ "\0" * TOKENBUFSIZE ] * buffers
		    @bufferSizes = [ TOKENBUFSIZE ] * buffers
		    @bufferTypes = [ SECBUFFER_TOKEN ] * buffers
		  when NilClass
		    @bufferTokens = [ "\0" * TOKENBUFSIZE ]
		    @bufferSizes = [ TOKENBUFSIZE ]
		    @bufferTypes = [ SECBUFFER_TOKEN ]
	    else
	      raise ArgumentError
		  end
	  end
	  
	  def bufferSize(n=0)
	    unpack
	    @bufferSizes[n]
	  end
	  
	  def bufferType(n=0)
	    unpack
	    @bufferTypes[n]
	  end
	  
	  def token(n=0)
	    unpack
	    @bufferTokens[n]
	  end
	  
	  def to_p
	    # Assumption is that when to_p is called we are going to get a packed structure. Therefore,
	    # set @unpacked back to nil so we know to unpack when accessors are next accessed.
	    @unpacked = nil
	    # Assignment of inner structure to variable is very important here. Without it,
	    # will not be able to unpack changes to the structure. Alternative, nested unpacks,
	    # does not work (i.e. @struct.unpack("LLP12")[2].unpack("LLP12") results in "no associated pointer")
	    @sec_buffers ||= @bufferTokens.inject([]) do |v,t|
	      v.push @bufferSizes[v.size / 3], @bufferTypes[v.size / 3], t
	    end.pack("LLP" * @bufferTokens.size)
	    @struct ||= [SECBUFFER_VERSION, @bufferTokens.size, @sec_buffers].pack("LLP")    
	  end
	
	private
	
	  # Unpacks the SecurityBufferDesc structure into member variables. We
	  # only want to do this once per struct, so the struct is deleted
	  # after unpacking. 
	  def unpack
	    if ! @unpacked && @sec_buffers && @struct
	      d = @sec_buffers.unpack("LLL" * @bufferTokens.size)
	      k = ''; 0.upto(@bufferTokens.size - 1) do |n| k << "LLP#{d[n * 3]}" end
	      d = @sec_buffers.unpack(k)
	      0.upto(@bufferTokens.size - 1) do |n| @bufferSizes[n] = d[n * 3] end
	      0.upto(@bufferTokens.size - 1) do |n| @bufferTypes[n] = d[n * 3 + 1] end
	      0.upto(@bufferTokens.size - 1) do |n| @bufferTokens[n] = d[n * 3 + 2][0,@bufferSizes[n]] end
	      @struct = nil
	      @sec_buffers = nil
	      @unpacked = true
	    end
	  end
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
      @sizes = SecPkgSizes.new
			result = SSPIResult.new(API::QuerySecurityPackageSizes.call(ctx.to_p, @sizes.to_p))
			@handle = @state[:handle]
    end
  end
  
  def get_mic(token=nil)
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
