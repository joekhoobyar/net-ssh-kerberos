require 'dl/import'
require 'dl/struct'

require 'net/ssh/errors'
require 'net/ssh/kerberos/common/context'

module Net; module SSH; module Kerberos; module Drivers;
  
  module GSS
	
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
	
	  # GSSAPI / Kerberos 5 OID(s)
	  GSS_C_NT_PRINCIPAL = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"
	  GSS_C_NT_MACHINE_UID_NAME = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"
	  GSS_C_NT_STRING_UID_NAME = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"
	  GSS_C_NT_HOSTBASED_SERVICE = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"
	  GSS_C_NT_ANONYMOUS = "\x2b\x06\01\x05\x06\x03"
	  GSS_C_NT_EXPORT_NAME = "\x2b\x06\01\x05\x06\x04"
	
	  # GSSAPI / Kerberos 5  Deprecated / Proprietary OID(s)
	  GSS_C_NT_HOSTBASED_SERVICE_X = "\x2b\x06\x01\x05\x06\x02"

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
      typealias "gss_bytes_t", "P", nil, nil, "P", PTR_ENC
	    GssBuffer = struct2 [ "size_t length", "gss_bytes_t value" ] do
        def to_s; value.to_s(length) end
      end
	    typealias 'gss_buffer_desc', 'GssBuffer'
	    typealias 'gss_buffer_t', 'gss_buffer_desc *'
	    GssOID = struct2 [ "OM_uint32 length", "gss_bytes_t elements" ] do
        def to_s; elements.to_s(length) end
	      def inspect; 'OID: ' + to_s.unpack("H2" * length).join(' ') end
	    end
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
	
	    class GssResult < Struct.new(:major, :minor, :status, :calling_error, :routine_error)
	      def initialize(result, minor=nil)
	        self.major = (result >> 16) & 0x0000ffff
	        self.minor = minor.value if minor.respond_to? :value
	        self.status = result & 0x0000ffff
	        self.calling_error = (major >> 8) & 0x00ff
	        self.routine_error = major & 0x00ff
	      end
	      def ok?; major.zero? end
	      def complete?; status.zero? end
	      def incomplete?; false end
	      def failure?; major.nonzero? end
	      def temporary_failure?
	        routine_error==GSS_S_CREDENTIALS_EXPIRED ||
	          routine_error==GSS_S_CONTEXT_EXPIRED ||
	          routine_error==GSS_S_UNAVAILABLE
	      end
	      def to_s; "%#4.4x%4.4x [%#8.8x]" % [major, status, minor] end
	    end
	
	    gss_func "gss_acquire_cred", "gss_name_t, OM_uint32, gss_OID_set, gss_cred_usage_t, gss_cred_id_ref, gss_OID_set_ref, OM_uint32_ref"
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
	
#	    if @LIBS.empty? and ! defined? Net::SSH::Kerberos::SSPI::Context
#	      $stderr.puts "error: Failed to a find a supported GSS implementation on this platform (#{RUBY_PLATFORM})"
#	    end
	  end
	end
end; end; end; end
