require File.join(File.dirname(__FILE__), 'test_helper.rb')

class GssContextTest < Test::Unit::TestCase

if defined? Net::SSH::Kerberos::GSS::Context

  def setup
    @gss = Net::SSH::Kerberos::GSS::Context.new 
  end

  def teardown
    @gss.dispose
  end

  def test_create
    @gss.create ENV['USER'], Socket.gethostbyname(`hostname || echo "localhost"`.strip)[0]
    assert @gss.credentials?, "Should have acquired credentials"
  end

  def test_init
    test_create
    @gss.init nil
    state = @gss.send(:state)
    assert ! state.handle.nil?, "Should have provided an initial context"
    assert ! state.handle.handle.nil?, "Should have provided an initial context"
    assert ! state.token.nil?, "Should have built an initial token"
    assert state.token.length.nonzero?, "Should have built an initial token"
  end

else
  $stderr.puts "Skipping GSS tests on this platform: no supported GSSAPI library was loaded."
end

end

