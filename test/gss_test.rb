require File.join(File.dirname(__FILE__), 'test_helper.rb')

class GssTest < Test::Unit::TestCase

  include Net::SSH::Kerberos::GSS

  def test_acquire_cred
    minor_status = "\0" * 4
    creds = "\0" * 4
    mechs = API::GssOID.malloc
    mechs.length = 10
    mechs.elements = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"
    req_mechs = API::GssOIDSet.malloc
    req_mechs.count = 1
    req_mechs.elements = mechs.to_ptr.ref
    actual_mechs = "\0" * 4
    
    result = API.gss_acquire_cred minor_status, nil, 10, req_mechs, API::GSS_C_INITIATE, creds, actual_mechs, nil
    assert_equal 0, result, "gss_acquire_cred failed: 0x#{result.to_s(16)}"
  end

end

