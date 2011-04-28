require File.join(File.dirname(__FILE__), 'test_helper.rb')

class SspiTest < Test::Unit::TestCase

if Net::SSH::Kerberos::Drivers.available.include? 'SSPI'

  include Net::SSH::Kerberos::Drivers::SSPI

  def test_query_security_package_info
    result = API.querySecurityPackageInfo "Kerberos", nil
    assert result.ok?, "querySecurityPackageInfo failed: #{result}"
    #$stderr.puts "querySecurityPackageInfo => #{pkg_info.comment} (max_token=#{pkg_info.max_token})"
    pkg_info = API._args_[1]
    assert_equal pkg_info.name.to_s, "Kerberos"
    assert pkg_info.max_token >= 128, "The maximum token size is assumed to be greater than 127 bytes"
    assert pkg_info.max_token <= 12288, "The maximum token size is assumed to be less than 12289 bytes"
    result = API.freeContextBuffer pkg_info.to_ptr
    assert result.ok?, "freeContextBuffer failed: #{result}"
  end

  def test_security_context_initialization
    result = API.acquireCredentialsHandle nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil, nil, nil,
                                          creds=API::SecHandle.malloc, ts=API::TimeStamp.malloc
    unless result.temporary_failure?
      assert result.ok?, "acquireCredentialsHandle failed: #{result}"
      assert ! creds.nil?, "Should acquire a credentials handle"
      begin
        result = API.queryCredentialsAttributes creds, SECPKG_ATTR_NAMES, nil
        assert result.ok?, "queryCredentialsAttributes failed: #{result}"
        names = API._args_[2]
        assert ! names.nil?, "Should return the user name."
        #$stderr.puts "queryCredentialsAttributes: (#{result}) #{names.to_s}"
        begin
          output = API::SecBufferDesc.create(12288)
          result = API.initializeSecurityContext creds, nil, 'host/'+Socket.gethostbyname('localhost')[0], 
                                                 ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY, 0, SECURITY_NATIVE_DREP,
                                                 nil, 0, ctx=API::SecHandle.malloc, output, 0, ts=API::TimeStamp.malloc
          unless result.temporary_failure?
            assert result.ok?, "initializeSecurityContext failed: #{result}"
            begin
              assert ! ctx.nil?, "Should initialize a context handle"
              assert ! output.buffer(0).data.nil?, "Should output a token into the buffer"
              assert output.buffer(0).length <= 12288, "Should output a token into the buffer"
            ensure
              ctx = nil if (result = API.deleteSecurityContext(ctx)).ok?
            end
            assert ctx.nil?, "deleteSecurityContext failed: #{result}"
          end
        ensure
          names = nil if (result = API.freeContextBuffer(names)).ok?
        end
        assert names.nil?, "freeContextBuffer failed: #{result}"
      ensure
        creds = nil if (result = API.freeCredentialsHandle(creds)).ok?
      end
      assert creds.nil?, "freeCredentialsHandle failed: #{result}"
    end
  end
else
  def test_nothing; assert true end
end

end

