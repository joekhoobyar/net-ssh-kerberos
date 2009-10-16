require 'dl/import'
require 'dl/struct'

module Net; module SSH; module Kerberos; module GSS;

  module API

    extend DL::Importable

    if RUBY_PLATFORM =~ /cygwin/
      dlload('cyggss-1.dll')
    else
      dlload('libgssapi_krb5.so')
    end 

    typealias 'OM_uint32', 'unsigned int'
    typealias 'size_t', 'unsigned int'

    GssBuffer = struct [ "size_t length", "char *value" ]
    typealias 'gss_buffer_desc', 'GssBuffer'
    typealias 'gss_buffer_t', 'gss_buffer_desc *'
    GssOID = struct [ "OM_uint32 length", "char *elements" ]
    typealias 'gss_OID_desc', 'GssOID'
    typealias 'gss_OID', 'gss_OID_desc *'
    GssOIDSet = struct [ "size_t count", "gss_OID elements" ]
    typealias 'gss_OID_set_desc', 'GssOIDSet'
    typealias 'gss_OID_set', 'gss_OID_set_desc *'

    #typealias 'gss_ctx_id_t', 'void *'
    #typealias 'gss_cred_id_t', 'void *'
    #typealias 'gss_name_t', 'void *'
    #GssCtxId = struct [ "char *handle" ]
    #GssCredId = struct [ "char *handle" ]
    typealias 'gss_ctx_id_t', 'void *'
    typealias 'gss_cred_id_t', 'void *'
    typealias 'gss_name_t', 'void *'
    GssNameRef = struct [ "gss_name_t handle" ]
    GssContextRef = struct [ "gss_ctx_id_t handle" ]
    GssCredRef = struct [ "gss_cred_id_t handle" ]
    GssMinorStatusRef = struct [ "OM_uint32 code" ]

    typealias 'gss_qop_t', 'OM_uint32'
    typealias 'gss_cred_usage_t', 'int'

    extern "OM_uint32 gss_acquire_cred (OM_uint32 *, gss_name_t, OM_uint32, gss_OID_set, gss_cred_usage_t, gss_cred_id_t *, gss_OID_set *, OM_uint32 *)"
    extern "OM_uint32 gss_release_cred (OM_uint32 *, gss_cred_id_t *)"
    extern "OM_uint32 gss_import_name (OM_uint32 *, gss_buffer_t, gss_OID, gss_name_t *)"
    extern "OM_uint32 gss_init_sec_context (OM_uint32 *, gss_cred_id_t, gss_ctx_id_t *, gss_name_t, gss_OID, OM_uint32, OM_uint32, void *, gss_buffer_t, gss_OID *, gss_buffer_t, OM_uint32 *, OM_uint32 *)"

    if @LIBS.empty? and ! defined? Net::SSH::Kerberos::SSPI::Context
      $stderr.puts "error: Failed to a find a supported GSS implementation on this platform (#{RUBY_PLATFORM})"
    end
  end

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

  #--
  # GSSAPI / Kerberos 5  OID(s)
  #++
  GSS_C_NT_PRINCIPAL = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"
  GSS_C_NT_MACHINE_UID_NAME = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"
  GSS_C_NT_STRING_UID_NAME = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"
  GSS_C_NT_HOSTBASED_SERVICE = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"
  GSS_C_NT_ANONYMOUS = "\x2b\x06\01\x05\x06\x03"
  GSS_C_NT_EXPORT_NAME = "\x2b\x06\01\x05\x06\x04"
  GSS_KRB5_MECH = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
  GSS_KRB5_MECH_USER2USER = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"

  #--
  # GSSAPI / Kerberos 5  Deprecated / Proprietary OID(s)
  #++
  GSS_C_NT_HOSTBASED_SERVICE_X = "\x2b\x06\x01\x05\x06\x02"

end; end; end; end
