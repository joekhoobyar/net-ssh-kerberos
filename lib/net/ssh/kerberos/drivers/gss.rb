module Net; module SSH; module Kerberos; module Drivers;

  module GSS

    include Net::SSH::Kerberos::Constants
	
	  GSS_C_INITIATE = 1
	
	  GSS_C_DELEG_FLAG      = 1
	  GSS_C_MUTUAL_FLAG     = 2
	  GSS_C_REPLAY_FLAG     = 4
	  GSS_C_SEQUENCE_FLAG   = 8
	  GSS_C_CONF_FLAG       = 16
	  GSS_C_INTEG_FLAG      = 32
	  GSS_C_ANON_FLAG       = 64
	  GSS_C_PROT_READY_FLAG = 128
	  GSS_C_TRANS_FLAG      = 256
	
	  GSS_C_NO_NAME         = nil
	  GSS_C_NO_BUFFER       = nil
	  GSS_C_NO_OID          = nil
	  GSS_C_NO_OID_SET      = nil
	  GSS_C_NO_CONTEXT      = nil
	  GSS_C_NO_CREDENTIAL   = nil
	  GSS_C_NO_CHANNEL_BINDINGS = nil
	  GSS_C_QOP_DEFAULT     = 0
	
	  GSS_S_COMPLETE        = 0
	  GSS_S_CONTINUE_NEEDED = 1
	  GSS_S_DUPLICATE_TOKEN = 2
	  GSS_S_OLD_TOKEN       = 4
	  GSS_S_UNSEQ_TOKEN     = 8
	  GSS_S_GAP_TOKEN       = 16
	
    GSS_C_GSS_CODE = 1
    GSS_C_MECH_CODE = 2

	  module API
	    extend DL::Importable
	    include DLExtensions
	    
	    def self.gss_func(sym, sig)
	      extern "OM_uint32 #{sym} (OM_uint32_ref, #{sig})"
	      module_eval <<-"EOCODE"
  alias :_#{sym} :#{sym}
  module_function :_#{sym}
	def #{sym}(*args)
	  _#{sym}(*(args.unshift(0)))
	  @retval = GssResult.new(@retval, @args.shift)
	end 
  module_function :#{sym}
EOCODE
	    end
	
	    if RUBY_PLATFORM =~ /cygwin/
	      dlload('cyggss-1.dll')
	    else
	      dlload('libgssapi_krb5.so')
	    end 
	
      typealias "void **", "p", PTR_REF_ENC, proc{|v| v.ptr}
      typealias "GssResult", "L", proc{|v| v.to_i }, proc{|v| GssResult.new(v) }
	    typealias 'OM_uint32', 'unsigned int'
      typealias "OM_uint32_ref", 'unsigned int ref' 
	    typealias 'size_t', 'unsigned int'
      typealias "gss_bytes_t", "P" #, nil, nil, "P", PTR_ENC
	    GssBuffer = struct2 [ "size_t length", "gss_bytes_t value" ] do
        def to_s; value.to_s(length) if length > 0 end
      end
	    typealias 'gss_buffer_desc', 'GssBuffer'
	    typealias 'gss_buffer_t', 'gss_buffer_desc *'
	    GssOID = struct2 [ "OM_uint32 length", "gss_bytes_t elements" ] do
	      def eql?(oid) !oid.nil? && length==oid.length && to_s==oid.to_s end
	      def ==(oid) !oid.nil? && length==oid.length && to_s==oid.to_s end
        def to_s; elements.to_s(length) if length > 0 end
	      def inspect; 'OID: ' + (to_s.unpack("H2" * length).join(' ') rescue 'nil') end
	    end
      def GssOID.create(bytes) new [bytes.length, bytes].pack("LP#{bytes.length}").to_ptr end
	    typealias 'gss_OID', 'P', PTR_ENC, PTR_DEC(GssOID)
	    typealias 'gss_OID_ref', 'p', PTR_REF_ENC, PTR_REF_DEC(GssOID)
	    GssOIDSet = struct2 [ "size_t count", "gss_OID elements" ] do
        def oids
          if @oids.nil? or elements != (@oids.first.to_ptr rescue nil)
            @oids = []
            0.upto(count-1) { |n| @oids[n] = GssOID.new(elements + n*GssOID.size) } unless elements.nil?
          end
          @oids
        end
	      def inspect; 'OIDSet: [' + oids.map {|o| o.inspect }.join(', ') + ']' end
      end
	    typealias 'gss_OID_set', 'P', PTR_ENC, PTR_DEC(GssOIDSet)
	    typealias 'gss_OID_set_ref', 'p', PTR_REF_ENC, PTR_REF_DEC(GssOIDSet)
	
	    typealias 'gss_ctx_id_t', 'void *'
	    typealias 'gss_ctx_id_ref', 'void **'
	    typealias 'gss_cred_id_t', 'void *'
	    typealias 'gss_cred_id_ref', 'void **'
	    typealias 'gss_name_t', 'void *'
	    typealias 'gss_name_ref', 'void **'
	    typealias 'gss_qop_t', 'OM_uint32'
	    typealias 'gss_qop_ref', 'OM_uint32_ref'
	    typealias 'gss_cred_usage_t', 'int'
	    typealias 'gss_cred_usage_ref', 'int ref'
	
	    class GssResult
	      def initialize(code, minor=nil) @value, @minor = code, minor end
	      def ok?; major.zero? end
	      def complete?; status.zero? end
	      def incomplete?; false end
	      def failure?; major.nonzero? end
	      def temporary_failure?
	        routine_error==GSS_S_CREDENTIALS_EXPIRED ||
	          routine_error==GSS_S_CONTEXT_EXPIRED ||
	          routine_error==GSS_S_UNAVAILABLE
	      end
	      def major; (@value >> 16) & 0x0000ffff end
	      def status; @value & 0x0000ffff end
	      def calling_error; (@value >> 24) & 0x000000ff end
	      def routine_error; (@value >> 16) & 0x000000ff end
        def to_i; @value end
	      def to_s
          orig_retval, orig_args = API._retval_, API._args_
          begin
            msgctx, msgbuff, msglist = 0, API::GssBuffer.malloc, []
            begin
              result = API.gss_display_status @value, GSS_C_GSS_CODE, GSS_C_NO_OID, msgctx, msgbuff
              result.ok? or return 'unknown'
              msgctx = API._args_[3]
              msglist << msgbuff.to_s
              API.gss_release_buffer msgbuff
            end until msgctx.zero?
            msglist.empty? ? 'ok' : msglist.join(', ')
          ensure
            API.instance_eval { @retval = orig_retval; @args = orig_args }
          end
        end
	    end
	
	    gss_func "gss_acquire_cred", "gss_name_t, OM_uint32, gss_OID_set, gss_cred_usage_t, gss_cred_id_ref, void *, OM_uint32_ref"
	    gss_func "gss_inquire_cred", "gss_cred_id_t, gss_name_ref, OM_uint32_ref, gss_cred_usage_ref, gss_OID_set_ref"
      gss_func "gss_import_name", "gss_buffer_t, gss_OID, gss_name_ref"
      gss_func "gss_display_name", "gss_name_t, gss_buffer_t, gss_OID_ref"
	    gss_func "gss_release_cred", "gss_cred_id_ref"
	    gss_func "gss_release_oid_set", "gss_OID_set_ref"
	    gss_func "gss_release_name", "gss_name_ref"
      gss_func "gss_release_buffer", "gss_buffer_t"
	    gss_func "gss_init_sec_context", "gss_cred_id_t, gss_ctx_id_ref, gss_name_t, gss_OID, OM_uint32, OM_uint32, void *, "+
                                        "gss_buffer_t, gss_OID_ref, gss_buffer_t, OM_uint32_ref, OM_uint32_ref"
      gss_func "gss_delete_sec_context", "gss_ctx_id_ref, gss_buffer_t"
	    gss_func "gss_get_mic", "gss_ctx_id_t, gss_qop_t, gss_buffer_t, gss_buffer_t"
	    gss_func "gss_display_status", "OM_uint32, int, gss_OID, OM_uint32_ref, gss_buffer_t"
	    gss_func "gss_indicate_mechs", "gss_OID_set_ref"
	  end

	  # GSSAPI / Kerberos 5 OID(s)
	  GSS_C_NT_PRINCIPAL = API::GssOID.create("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01")
	  GSS_C_NT_MACHINE_UID_NAME = API::GssOID.create("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02")
	  GSS_C_NT_STRING_UID_NAME = API::GssOID.create("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03")
	  GSS_C_NT_HOSTBASED_SERVICE = API::GssOID.create("\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04")
	  GSS_C_NT_ANONYMOUS = API::GssOID.create("\x2b\x06\x01\x05\x06\x03")
	  GSS_C_NT_EXPORT_NAME = API::GssOID.create("\x2b\x06\x01\x05\x06\x04")
	  GSS_C_KRB5 = API::GssOID.create(GSS_KRB5_MECH)
	
	  # GSSAPI / Kerberos 5  Deprecated / Proprietary OID(s)
	  GSS_C_NT_HOSTBASED_SERVICE_X = API::GssOID.create("\x2b\x06\x01\x05\x06\x02")

    # GSSAPI - Kerberos 5 mechanism support.
    result = API.gss_indicate_mechs nil
    result.ok? or raise "gss_indicate_mechs failed: #{result}"
    if API._args_[0].oids.include? GSS_C_KRB5
      API.gss_release_oid_set API._args_[0]
    else
      raise "This GSSAPI library reports no support for Kerberos authentication"
    end

	  class Context < Net::SSH::Kerberos::Context
	
		  GssResult = API::GssResult
		
		  def init(token=nil)
		    unless token.nil?
		      input = API::GssBuffer.malloc
		      input.value = token.to_ptr
		      input.length = token.length
		    end
        buffer = API::GssBuffer.malloc
		    context = @state.handle if @state
		    result = API.gss_init_sec_context @credentials, context, @target, GSS_C_KRB5,
	                                        GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, 60,
	                                        GSS_C_NO_CHANNEL_BINDINGS, input, nil, buffer, 0, 0
		    result.failure? and raise GeneralError, "Error initializing security context: #{result}"
		    begin
		      @state = State.new(API._args_[1], result, buffer.to_s, nil)
		      @handle = @state.handle if result.complete?
		      return @state.token
		    ensure
		      API.gss_release_buffer buffer if buffer.value
		    end
		  end
		  
		  def get_mic(token)
		    input = API::GssBuffer.malloc
		    input.value = token.to_ptr
		    input.length = token.length
		    @state.result = API.gss_get_mic @handle, GSS_C_QOP_DEFAULT, input, output=API::GssBuffer.malloc
		    unless @state.result.complete? and output
		      raise GeneralError, "Error creating the signature: #{@state.result}"
		    end
		    begin return output.to_s
		    ensure API.gss_release_buffer output
		    end
		  end
		
		protected
		
		  def state; @state end
		  
		private
		  
		  def acquire_current_credentials
		    result = API.gss_acquire_cred nil, 60, nil, GSS_C_INITIATE, nil, nil, 0
		    result.ok? or raise GeneralError, "Error acquiring credentials: #{result}"
	      result = API.gss_inquire_cred creds=API._args_[4], nil, 0, 0, nil
	      result.ok? or raise GeneralError, "Error inquiring credentials: #{result}"
	      begin
	        name, oids = API._args_[1], API._args_[4]
	        result = API.gss_display_name name, buffer=API::GssBuffer.malloc, nil
	        result.ok? or raise GeneralError, "Error getting display name: #{result}"
	        begin return [creds, buffer.to_s]
	        ensure API.gss_release_buffer buffer
	        end
	      ensure
	        API.gss_release_name name
          API.gss_release_oid_set oids
	      end
		  end
		
		  def release_credentials(creds)
		    creds.nil? or API.gss_release_cred creds
		  end
		
		  def import_server_name(host)
		    host = 'host@' + host
		    buffer = API::GssBuffer.malloc
		    buffer.value = host.to_ptr
		    buffer.length = host.length
		    result = API.gss_import_name buffer, GSS_C_NT_HOSTBASED_SERVICE, nil
		    result.failure? and raise GeneralError, "Error importing name: #{result}"
		    [API._args_[2], host]
		  end
		
		  def release_server_name(target)
		    target.nil? or API.gss_release_name target
		  end
		
		  def delete_context(handle)
		    handle.nil? or API.gss_delete_sec_context handle, nil
		  end
		
		end
		
	end
end; end; end; end
