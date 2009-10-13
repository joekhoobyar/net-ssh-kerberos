require File.join(File.dirname(__FILE__), 'test_helper.rb')

include Win32::SSPI

class SspiTest < Test::Unit::TestCase

if RUBY_PLATFORM.include?('win') && ! RUBY_PLATFORM.include?('dar'); then

  def test_query_security_package_info
    pkg_info = SecPkgInfo.new
    result = SSPIResult.new(API::QuerySecurityPackageInfo.call("Kerberos", pkg_info.to_p))
    assert result.ok?, "QuerySecurityPackageInfo failed: #{result}"
    assert_equal pkg_info.name, "Kerberos"
    assert pkg_info.max_token <= 12288, "The maximum token size is assumed to be less than 12288 bytes"
    result = SSPIResult.new(API::FreeContextBuffer.call(pkg_info.to_p))
    assert result.ok?, "FreeContextBuffer failed: #{result}"
  end

  def test_security_context_initialization
    creds = SecurityHandle.new
    ts = TimeStamp.new
    result = SSPIResult.new(API::AcquireCredentialsHandle.call(
                              nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil,
                              nil, nil, creds.to_p, ts.to_p
                            ))
    unless result.temporary_failure?
      assert result.ok?, "AcquireCredentialsHandle failed: #{result}"
      assert creds.lower.nonzero? || creds.upper.nonzero?, "Should acquire a credentials handle"
      begin
        buff = "\0\0\0\0"
        result = SSPIResult.new(API::QueryCredentialsAttributes.call(creds.to_p, SECPKG_CRED_ATTR_NAMES, buff))
        assert result.ok?, "QueryCredentialsAttributes failed: #{result}"
        names = buff.to_ptr.ptr
        assert ! names.nil?, "Should return the user name."
        begin
          ts = TimeStamp.new
          output = SecurityBuffer.new
          ctx = CtxtHandle.new
          ctxAttr = "\0" * 4
          req = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH
          result = SSPIResult.new(API::InitializeSecurityContext.call(creds.to_p, nil, 'host/'+Socket.gethostbyname('localhost')[0], 
                                  req, 0, SECURITY_NATIVE_DREP, nil, 0, ctx.to_p, output.to_p, ctxAttr, ts.to_p))
          unless result.temporary_failure?
            assert result.ok?, "InitializeSecurityContext failed: #{result}"
            begin
              assert ctx.lower.nonzero? || ctx.upper.nonzero?, "Should initialize a context handle"
              assert ! output.token.nil?, "Should output a token into the buffer"
              assert output.bufferSize.nonzero?, "Should output a token into the buffer"
            ensure
              result = SSPIResult.new(API::DeleteSecurityContext.call(ctx.to_p))
              ctx = nil if result.ok?
            end
            assert ctx.nil?, "DeleteSecurityContext failed: #{result}"
          end
        ensure
          result = SSPIResult.new(API::FreeContextBuffer.call(names))
          names = nil if result.ok?
        end
        assert names.nil?, "FreeContextBuffer failed: #{result}"
      ensure
        result = SSPIResult.new(API::FreeCredentialsHandle.call(creds.to_p))
        creds = nil if result.ok?
      end
      assert creds.nil?, "FreeCredentialsHandle failed: #{result}"
    end
  end
end

end

