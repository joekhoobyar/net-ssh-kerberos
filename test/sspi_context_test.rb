require File.join(File.dirname(__FILE__), 'test_helper.rb')

class SspiContextTest < Test::Unit::TestCase

if defined? Net::SSH::Kerberos::Drivers::SSPI::Context

  def setup
    @gss = Net::SSH::Kerberos::Drivers::SSPI::Context.new 
  end

  def teardown
    @gss.dispose
  end

  def test_create
    @gss.create ENV['USER'], Socket.gethostbyname('localhost')[0]
    assert @gss.credentials?, "Should have acquired credentials"
  end

else
  $stderr.puts "Skipping SSPI tests on this platform: Windows SSPI was not loaded."

  def test_nothing; assert true end
end

end

