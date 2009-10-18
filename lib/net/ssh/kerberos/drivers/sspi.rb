require 'dl/import'
require 'dl/struct'

require 'net/ssh/errors'
require 'net/ssh/kerberos/common/context'

module Net; module SSH; module Kerberos; module Drivers

  module SSPI

    SEC_E_OK = 0x00000000

    SEC_I_CONTINUE_NEEDED = 0x00090312
    SEC_I_COMPLETE_NEEDED = 0x00090313
    SEC_I_COMPLETE_AND_CONTINUE = 0x00090314
    SEC_I_INCOMPLETE_CREDENTIALS = 0x00090320
    SEC_I_RENEGOTIATE = 0x00090321
  
    SEC_E_INSUFFICIENT_MEMORY = 0x80090300
    SEC_E_INVALID_HANDLE = 0x80090301
    SEC_E_UNSUPPORTED_FUNCTION = 0x80090302
    SEC_E_TARGET_UNKNOWN = 0x80090303
    SEC_E_INTERNAL_ERROR = 0x80090304
    SEC_E_SECPKG_NOT_FOUND = 0x80090305
    SEC_E_NOT_OWNER = 0x80090306
    SEC_E_INVALID_TOKEN = 0x80090308
    SEC_E_LOGON_DENIED = 0x8009030C
    SEC_E_UNKNOWN_CREDENTIALS = 0x8009030D
    SEC_E_NO_CREDENTIALS = 0x8009030E
    SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311
    SEC_E_WRONG_PRINCIPAL = 0x80090322

    SECPKG_CRED_INBOUND = 0x00000001
    SECPKG_CRED_OUTBOUND = 0x00000002
    SECPKG_CRED_BOTH = 0x00000003

    SECBUFFER_EMPTY = 0
    SECBUFFER_DATA = 1
    SECBUFFER_TOKEN = 2

	  SECURITY_NATIVE_DREP = 0x00000010
	  SECURITY_NETWORK_DREP = 0x00000000

    SECPKG_ATTR_SIZES = 0
    SECPKG_ATTR_NAMES = 1

    ISC_REQ_DELEGATE                = 0x00000001
    ISC_REQ_MUTUAL_AUTH             = 0x00000002
    ISC_REQ_INTEGRITY               = 0x00010000
    
    module API
      extend DL::Importable
      include DLExtensions
      
      dlload 'secur32'
    
      typealias "void **", "p", PTR_REF_ENC, proc{|v| v.ptr}
      typealias "SECURITY_STATUS", "L", proc{|v| v.to_i }, proc{|v| SSPIResult.new(v) }
      typealias "USHORT", "unsigned short"
      typealias "ULONG_REF", "unsigned long ref"
      typealias "SEC_CHAR *", "char *"
      typealias "PCtxtBuffer", "void **"
      typealias "PCharBuffer", "P", nil, nil, "P", PTR_ENC
      SecPkgInfo = struct [ "ULONG capabilities", "USHORT version", "USHORT rpcid",
                            "ULONG max_token", "SEC_CHAR *name", "SEC_CHAR *comment" ]
      typealias "PSecPkgInfo", "p", PTR_REF_ENC, PTR_REF_DEC(SecPkgInfo)
      SecHandle = struct2([ "ULONG lower", "ULONG upper" ]) do def nil?; lower.zero? && upper.zero? end end
      typealias "PSecHandle", "P"
      typealias "PCredHandle", "PSecHandle"
      typealias "PCtxtHandle", "PSecHandle"
      SecBuffer = struct [ "ULONG length", "ULONG type", "PCharBuffer data" ]
      typealias "PSecBuffer", "P", nil, nil, "P", PTR_ENC, PTR_DEC(SecBuffer)
      SecBufferDesc = struct2 [ "ULONG version", "ULONG count", "PSecBuffer buffers" ] do
        def buffer(n) SecBuffer.new(@ptr[:buffers] + SecBuffer.size * n) end
      end
      typealias "PSecBufferDesc", "P"
      TimeStamp = SecHandle
      typealias "PTimeStamp", "P"
      SecPkgSizes = struct [ "ULONG max_token", "ULONG max_signature",
                             "ULONG block_size", "ULONG security_trailer" ]
    
      class SSPIResult
        @@map = {}
        SSPI.constants.each { |v| @@map[SSPI.const_get(v.to_s)] = v if v.to_s =~ /^SEC_[EI]_/ }
    
        attr_reader :value
        alias :to_i :value
    
        def initialize(value)
          value = [value].pack("L").unpack("L").first
          raise "#{value.to_s(16)} is not a recognized result" unless @@map.has_key? value
          @value = value
        end
    
        def ok?; value & 0x80000000 == 0 end
        def complete?; value == 0 end
        def incomplete?; SEC_I_COMPLETE_NEEDED==value || SEC_I_COMPLETE_AND_CONTINUE==value end
        def failure?; value & 0x80000000 != 0 end
        def temporary_failure?
          value==SEC_E_LOGON_DENIED || value==SEC_E_NO_AUTHENTICATING_AUTHORITY || value==SEC_E_NO_CREDENTIALS
        end
        def to_s; @@map[@value].to_s end
        def ==(result)
          case result
          when SSPIResult;  @value == result.value
          when Fixnum;      @value == @@map[other]
          else false
          end
        end
      end

      extern 'SECURITY_STATUS FreeContextBuffer(void *)'
      extern 'SECURITY_STATUS QuerySecurityPackageInfo(SEC_CHAR *, PSecPkgInfo)'
			extern 'SECURITY_STATUS AcquireCredentialsHandle(void *, SEC_CHAR *, ULONG, void *, '+
				                        'void *, void *, void *, PCredHandle, PTimeStamp)'
      extern 'SECURITY_STATUS QueryCredentialsAttributes(PCredHandle, ULONG, PCtxtBuffer)'
      extern 'SECURITY_STATUS FreeCredentialsHandle(PCredHandle)'
      extern 'SECURITY_STATUS QueryContextAttributes(PCtxtHandle, ULONG, PCtxtBuffer)'
      extern 'SECURITY_STATUS CompleteAuthToken(PCtxtHandle, PSecBufferDesc)'
      extern 'SECURITY_STATUS MakeSignature(PCtxtHandle, ULONG, PSecBufferDesc, ULONG)'
			extern 'SECURITY_STATUS InitializeSecurityContext(PCredHandle, PCtxtHandle, char *, '+
				                        'ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, '+
				                        'PSecBufferDesc, ULONG_REF, PTimeStamp)'
      extern 'SECURITY_STATUS DeleteSecurityContext(PCtxtHandle)'
      
      def self.createBuffers(types,data)
        buffs, types, data = [], Array(types), Array(data)
        ptr = DL::malloc(API::SecBuffer.size * types.length)
        0.upto(types.length - 1) do |n|
          buff = API::SecBuffer.new(ptr + API::SecBufer.size * n)
          buff.type = types[n]
          n = data[n]
          buff.data = Fixnum===n ? "\0" * n : n
          buff.length = Fixnum===n ? n : n.length
          buffs << buff
        end
        buffs
      end
      
      def self.createTokenBufferDesc(token)
        desc = API::SecBufferDesc.malloc
        desc.version = 0
        desc.count = 1
        desc.buffers = createBuffers(SECBUFFER_TOKEN, token).first.ptr
        desc
      end
    end

    class Context < Net::SSH::Kerberos::Common::Context
			def init(token=nil)
			  output = API.createTokenBufferDesc 12288
        if token.nil?
          ctx = API::SecHandle.malloc
          input = nil
			  else
				  ctx = prev = @state.handle
	        input = API.createTokenBufferDesc token
			  end
			  result = API.initializeSecurityContext @credentials, prev, @target,
				                 ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY, 0,
				                 SECURITY_NATIVE_DREP, input, 0, ctx, output, 0, ts=TimeStamp.malloc
			  result = API.completeAuthToken ctx, output if result.incomplete?
			  if result.failure?
			    input.token and raise GeneralError, "Error initializing security context: #{result} #{input.inspect}"
			  end
			  @state = State.new(ctx, result, output.buffers.data, ts)
			  if result.complete?
			    result = API.queryContextAttributes ctx, SECPKG_ATTR_SIZES, @sizes=SecPkgSizes.new
			    @handle = @state.handle
			  end
			  @state.token
			end
			
			def get_mic(token=nil)
        desc = API::SecBufferDesc.malloc
        desc.version = 0
        desc.count = 2
        desc.buffers = createBuffers([SECBUFFER_DATA, SECBUFFER_TOKEN],
                                      [token, @sizes.max_signature]).first.ptr
			  @state.result = API.makeSignature @handle, 0, desc, 0
			  @state.result.complete? or raise GeneralError, "Error creating the signature: #{result}"
		    token = desc.buffer(1)
		    return token.data.to_s(token.data.length)
			end
			
		private
			
			def acquire_current_credentials
			  result = API.acquireCredentialsHandle nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil, nil, nil,
			                                         creds=API::SecHandle.malloc, ts=API::TimeStamp.malloc
			  result.ok? or raise GeneralError, "Error acquiring credentials: #{result}"
			  result = API.queryCredentialsAttributes creds, SECPKG_ATTR_NAMES, nil
			  if result.ok?
			    name = API._args_[2]
			    begin return [creds, name.to_s]
			    ensure API.freeContextBuffer name
			    end
			  end
			end
			
			def release_credentials(creds) API.freeCredentialsHandle creds unless creds.nil? end
			  
			def import_server_name(host) ['host/'+host, 'host/'+host] end
			  
			def release_server_name(target) end
			  
			def delete_context(handle)
			  API.deleteSecurityContext handle unless handle.nil?
			  API.freeContextBuffer @sizes unless @sizes.nil?
			end
		end
  end

end; end; end; end
