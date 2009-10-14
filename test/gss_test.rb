require File.join(File.dirname(__FILE__), 'test_helper.rb')

class GssTest < Test::Unit::TestCase

  include Net::SSH::Kerberos::GSS

  def test_default_cred
    principal = nil
    req_mechs = nil
    #mechs = API::GssOID.malloc
    #mechs.length = 9
    #mechs.elements = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
    #req_mechs = API::GssOIDSet.malloc
    #req_mechs.count = 1
    #req_mechs.elements = mechs.to_ptr.ref
    minor_status = "\0" * 4
    creds = "\0" * 4
    actual_mechs = "\0" * 4
    
    result = API.gss_acquire_cred minor_status, principal, 60, req_mechs, GSS_C_INITIATE, creds, actual_mechs, nil
    assert_equal 0, result, "gss_acquire_cred failed: 0x#{result.to_s(16)}"
    assert_equal GSS_C_NO_CREDENTIAL, creds.unpack("P")[0], "Should acquire default credentials"
  end
  
  def test_init_sec_context
    target_name = 'host@'+Socket.gethostbyname('localhost')[0]
    buffer = API::GssBuffer.malloc
    buffer.value = target_name
    buffer.length = target_name.length
    mechs = API::GssOID.malloc
    mechs.length = 9
    mechs.elements = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
    minor_status = "\0" * 4
    output = "\0" * 4
    result = API.gss_import_name minor_status, buffer, mechs, output
    assert_equal 0, result, "gss_import_name failed: 0x#{result.to_s(16)}"
    assert_not_equal "\0"*4, output, "Should import the name"
    output = API::GssOID.new(output.to_ptr)
    target_name = output.value[0,output.length]

    minor_status = "\0" * 4
    ctx = "\0" * 4
    actual_mech = "\0" * 4
    buffer = "\0" * 4
    
    result = API.gss_init_sec_context minor_status, GSS_C_NO_CREDENTIAL,
                ctx, target_name, GSS_C_NO_OID,
                GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, 60,
                nil, GSS_C_NO_BUFFER, actual_mech, buffer, nil, nil
  end
end

