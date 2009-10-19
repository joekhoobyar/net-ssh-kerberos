require File.join(File.dirname(__FILE__), 'test_helper.rb')

class GssTest < Test::Unit::TestCase

if defined? Net::SSH::Kerberos::Drivers::GSS::Context

  include Net::SSH::Kerberos::Drivers::GSS

  def test_acquire_cred
    result = API.gss_acquire_cred nil, 60, nil, GSS_C_INITIATE, nil, nil, 0
    assert result.ok?, "gss_acquire_cred failed: #{result}"
    creds = API._args_[4]
    assert_not_equal creds, GSS_C_NO_CREDENTIAL, "Should acquire default credentials"
    begin
      result = API.gss_inquire_cred creds, nil, 0, 0, nil
      assert result.ok?, "gss_inquire_cred failed: #{result}"
      name, oids = API._args_[1], API._args_[4]
      assert_not_equal name, GSS_C_NO_NAME, "Should provide the internal name"
      assert_not_equal oids, GSS_C_NO_OID_SET, "Should provide the supported oids"
      assert oids.count > 0, "Should provide the supported oids"
      begin
        result = API.gss_display_name name, buffer=API::GssBuffer.malloc, nil
        assert result.ok?, "gss_display_name failed: #{result}"
        assert buffer.length > 0, "Should provide the display name"
        begin
          assert_not_equal API._args_[2], GSS_C_NO_OID, "Should provide the supported oid"
          #$stderr.puts "credentials: #{creds.handle.to_i} #{buffer.value} (OID: #{oid.oid.length}, #{oid.oid.to_hex})"
        ensure
          API.gss_release_buffer buffer
        end
      ensure
        API.gss_release_name name
        API.gss_release_oid_set oids
      end
    ensure
      API.gss_release_cred creds
    end
  end
  
  def test_init_sec_context
    target_name = 'host@'+Socket.gethostbyname(`hostname || echo "localhost"`.strip)[0]
    buffer = API::GssBuffer.malloc
    buffer.value = target_name
    buffer.length = target_name.length
    result = API.gss_import_name buffer, GSS_C_NT_HOSTBASED_SERVICE, nil
    assert result.ok?, "gss_import_name failed: #{result}"
    target = API._args_[2]
    assert_not_equal target, GSS_C_NO_NAME, "Should import the name"
    result = API.gss_display_name target, buffer=API::GssBuffer.malloc, nil
    assert result.ok?, "gss_display_name failed: #{result}"
    assert buffer.length > 0, "Should provide the display name"
    #$stderr.puts "target: #{buffer.value} (OID: #{mech.length}, #{mech.to_hex})"
    API.gss_release_buffer buffer

    buffer.value = nil
    buffer.length = 0
    result = API.gss_init_sec_context GSS_C_NO_CREDENTIAL, GSS_C_NO_CONTEXT, target, GSS_C_KRB5,
                                      GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, 60,
                                      GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, nil, buffer, 0, 0
    assert result.ok?, "gss_init_sec_context failed: #{result}"
    context, actual_mech = API._args_[1], API._args_[8]
    assert_not_equal context, GSS_C_NO_CONTEXT, "Should initialize the security context"
    begin
      assert_equal result.status, GSS_S_CONTINUE_NEEDED, "Should need continued initialization of the security context"
      assert buffer.length > 0, "Should output a token to send to the server"
      assert_not_equal actual_mech, GSS_C_NO_OID, "Should initialize the security context"
      #$stderr.puts "context: (#{buffer.length}) (OID: #{actual_mech.oid.length}, #{actual_mech.oid.to_hex})"
      API.gss_release_buffer buffer
    ensure
      API.gss_delete_sec_context context, nil if context and buffer.value.nil?
    end
  end

else
  $stderr.puts "#{__FILE__}: Skipping GSS tests on this platform: no supported GSSAPI library was loaded."

  def test_nothing; assert true end
end

end

