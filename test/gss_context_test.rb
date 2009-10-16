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

else
  $stderr.puts "Skipping GSS tests on this platform: no supported GSSAPI library was loaded."
end

end

