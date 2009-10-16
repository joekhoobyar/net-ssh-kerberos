require File.join(File.dirname(__FILE__), 'test_helper.rb')

class GssTest < Test::Unit::TestCase

  include Net::SSH::Kerberos::GSS

  def test_default_cred
    minor_status = "\0" * 4
    creds = "\0" * 4
    result = API.gss_acquire_cred minor_status, nil, 60, nil, GSS_C_INITIATE, creds, nil, nil
    assert_equal result, 0, "gss_acquire_cred failed: 0x#{result.to_s(16)}"
    assert_equal creds.unpack("P")[0], GSS_C_NO_CREDENTIAL, "Should acquire default credentials"
  end
  
  def test_init_sec_context
    target_name = 'host/usbillingstg.corp.tnsi.com' #'host@'+Socket.gethostbyname('localhost')[0]
    buffer = API::GssBuffer.malloc
    buffer.value = target_name
    buffer.length = target_name.length
    mechs = API::GssOID.malloc
    mechs.elements = GSS_C_NT_HOSTBASED_SERVICE
    mechs.length = GSS_C_NT_HOSTBASED_SERVICE.length
    minor_status = API::GssMinorStatusRef.malloc
    target_name = API::GssNameRef.malloc
    result = API.gss_import_name minor_status, buffer, mechs, target_name
    assert_equal result, 0, "gss_import_name failed: 0x#{result.to_s(16)}"
    assert_equal minor_status.code, 0, "gss_import_name failed: minor status 0x#{minor_status.code.to_s(16)}"
    assert_not_equal target_name.handle, GSS_C_NO_NAME, "Should import the name"

    actual_mech = "\0" * 4
    buffer.value = nil
    buffer.length = 0
    result = API.gss_init_sec_context minor_status, GSS_C_NO_CREDENTIAL,
                GSS_C_NO_CONTEXT, target_name.handle, GSS_C_NO_OID,
                GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, 60,
                GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, actual_mech.to_ptr.ref, buffer, nil, nil
    assert_equal result, 0, "gss_init_sec_context failed: 0x#{result.to_s(16)}"
    assert_equal minor_status.code, 0, "gss_init_sec_context failed: minor status 0x#{minor_status.code.to_s(16)}"

  end
end

