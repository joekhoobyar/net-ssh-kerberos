require File.join(File.dirname(__FILE__), 'test_helper.rb')

class GssTest < Test::Unit::TestCase

  include Net::SSH::Kerberos::GSS

  def test_acquire_cred
    creds = API::GssCredRef.malloc
    result = call_and_assert :gss_acquire_cred, nil, 60, nil, GSS_C_INITIATE, creds, nil, nil
    assert_not_equal 0, creds.handle.to_i, "Should acquire default credentials"
    begin
      name = API::GssNameRef.malloc
      lifetime = API::OM_uint32Ref.malloc
      usage = API::GssCredUsageRef.malloc
      oids = API::GssOIDSetRef.malloc
      result = call_and_assert :gss_inquire_cred, creds.handle, name, nil, usage, oids
      assert_not_equal 0, name.handle.to_i, "Should provide the internal name"
      assert_not_equal 0, oids.oidset.count, "Should provide the supported oids"
      begin
        buffer = API::GssBuffer.malloc
        oid = API::GssOIDRef.malloc
        assert_equal GSS_C_INITIATE, usage.value, "Usage should specify GSS_C_INITIATE"
        result = call_and_assert :gss_display_name, name.handle, buffer, oid
        assert_not_equal 0, buffer.value.to_i, "Should provide the display name"
        begin
          assert_not_equal 0, oid.ptr.to_i, "Should provide the supported oid"
          #$stderr.puts "credentials: #{creds.handle.to_i} #{buffer.value} (OID: #{oid.oid.length}, #{oid.oid.to_hex})"
        ensure
          result = API.gss_release_buffer API::OM_uint32Ref.malloc, buffer
        end
      ensure
        minor_status = API::OM_uint32Ref.malloc
        API.gss_release_name minor_status, name
        API.gss_release_oid_set minor_status, oids
        assert_equal 0, name.handle.to_i, "Should release the internal name"
        assert_equal 0, oids.ptr.to_i, "Should release the supported oids"
      end
    ensure
      minor_status = API::OM_uint32Ref.malloc
      API.gss_release_cred minor_status, creds
    end
  end
  
  def test_init_sec_context
    target_name = 'host@'+Socket.gethostbyname(`hostname || echo "localhost"`.strip)[0]
    buffer = API::GssBuffer.malloc
    buffer.value = target_name
    buffer.length = target_name.length
    mech = API::GssOID.malloc
    mech.elements = GSS_C_NT_HOSTBASED_SERVICE
    mech.length = GSS_C_NT_HOSTBASED_SERVICE.length
    target_name = API::GssNameRef.malloc
    result = call_and_assert :gss_import_name, buffer, mech, target_name
    assert_not_equal target_name.handle, GSS_C_NO_NAME, "Should import the name"

    buffer = API::GssBuffer.malloc
    result = call_and_assert :gss_display_name, target_name.handle, buffer, nil
    assert_not_equal 0, buffer.value.to_i, "Should provide the display name"
    #$stderr.puts "target: #{buffer.value} (OID: #{mech.length}, #{mech.to_hex})"
    call_and_assert :gss_release_buffer, buffer

    mech.elements = GSS_KRB5_MECH
    mech.length = GSS_KRB5_MECH.length
    actual_mech = API::GssOIDRef.malloc
    context = API::GssContextRef.malloc
    context.handle = GSS_C_NO_CONTEXT
    buffer.value = nil
    buffer.length = 0
    result = call_and_assert :gss_init_sec_context, GSS_C_NO_CREDENTIAL, context, target_name.handle, mech,
                              GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, 60,
                              GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, actual_mech, buffer, nil, nil
    assert_not_equal 0, context.handle.to_i, "Should initialize the security context"
    begin
      assert_equal GSS_S_CONTINUE_NEEDED, result, "Should need continued initialization of the security context"
      assert buffer.length > 0, "Should output a token to send to the server"
      #$stderr.puts "context: (#{buffer.length}) (OID: #{actual_mech.oid.length}, #{actual_mech.oid.to_hex})"
      call_and_assert :gss_release_buffer, buffer
    ensure
      minor_status = API::OM_uint32Ref.malloc
      API.gss_delete_sec_context minor_status, context, nil
      if buffer.value.nil?
        assert_equal 0, context.handle.to_i, "Should delete the security context"
      end
    end
  end

private
  
  def call_and_assert(sym, *args)
    minor_status = API::OM_uint32Ref.malloc
    result = API.send sym, minor_status, *args
    assert_equal 0, (result & 0xffff0000), "#{sym} failed: 0x#{result.to_s(16)}"
    assert_equal 0, minor_status.value, "#{sym} failed: minor status 0x#{minor_status.value.to_s(16)}"
    result
  end
end

