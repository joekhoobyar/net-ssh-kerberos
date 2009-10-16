module Net; module SSH; module Kerberos
  module Constants


    #--
    # GSSAPI Key exchange method specific messages
    #++

    KEXGSS_INIT                       = 30
    KEXGSS_CONTINUE                   = 31
    KEXGSS_COMPLETE                   = 32
    KEXGSS_HOSTKEY                    = 33
    KEXGSS_ERROR                      = 34
    KEXGSS_GROUPREQ                   = 40
    KEXGSS_GROUP                      = 41

    #--
    # GSSAPI User authentication method specific messages
    #++

    USERAUTH_GSSAPI_RESPONSE          = 60
    USERAUTH_GSSAPI_TOKEN             = 61
    USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63
    USERAUTH_GSSAPI_ERROR             = 64
    USERAUTH_GSSAPI_ERRTOK            = 65
    USERAUTH_GSSAPI_MIC               = 66

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
    
  end
end; end; end

