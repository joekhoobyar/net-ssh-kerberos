require File.join(File.dirname(__FILE__), 'test_helper.rb')

class SspiTest < Test::Unit::TestCase

if defined? Net::SSH::Kerberos::SSPI::Context

include Win32::SSPI

  def test_query_security_package_info
    pkg_info = SecPkgInfo.new
    result = API::QuerySecurityPackageInfo "Kerberos", pkg_info
    assert result.ok?, "QuerySecurityPackageInfo failed: #{result}"
    assert_equal pkg_info.name, "Kerberos"
    assert pkg_info.max_token >= 128, "The maximum token size is assumed to be greater than 128 bytes"
    assert pkg_info.max_token <= 12288, "The maximum token size is assumed to be less than 12288 bytes"
    result = API::FreeContextBuffer pkg_info
    assert result.ok?, "FreeContextBuffer failed: #{result}"
  end

  def test_security_context_initialization
    creds = SecurityHandle.new
    ts = TimeStamp.new
    result = API::AcquireCredentialsHandle nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil, nil, nil, creds, ts
    unless result.temporary_failure?
      assert result.ok?, "AcquireCredentialsHandle failed: #{result}"
      assert ! creds.nil?, "Should acquire a credentials handle"
      begin
        buff = "\0\0\0\0"
        result = API::QueryCredentialsAttributes creds, SECPKG_CRED_ATTR_NAMES, buff
        assert result.ok?, "QueryCredentialsAttributes failed: #{result}"
        names = buff.to_ptr.ptr
        assert ! names.nil?, "Should return the user name."
        begin
          ts = TimeStamp.new
          output = SecurityBuffer.new
          ctx = CtxtHandle.new
          ctxAttr = "\0" * 4
          req = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH
          result = API::InitializeSecurityContext creds, nil, 'host/'+Socket.gethostbyname('localhost')[0], 
                                                  req, 0, SECURITY_NATIVE_DREP, nil, 0, ctx, output, ctxAttr, ts
          unless result.temporary_failure?
            assert result.ok?, "InitializeSecurityContext failed: #{result}"
            begin
              assert ! ctx.nil?, "Should initialize a context handle"
              assert ! output.token.nil?, "Should output a token into the buffer"
              assert output.bufferSize.nonzero?, "Should output a token into the buffer"
            ensure
              result = API::DeleteSecurityContext ctx
              ctx = nil if result.ok?
            end
            assert ctx.nil?, "DeleteSecurityContext failed: #{result}"
          end
        ensure
          result = API::FreeContextBuffer names
          names = nil if result.ok?
        end
        assert names.nil?, "FreeContextBuffer failed: #{result}"
      ensure
        result = API::FreeCredentialsHandle creds
        creds = nil if result.ok?
      end
      assert creds.nil?, "FreeCredentialsHandle failed: #{result}"
    end
  end
else
  $stderr.puts "Skipping SSPI tests on this platform: Windows SSPI was not loaded."

  def test_nothing; assert true end
end

end

