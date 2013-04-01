require 'spec_helper'
require 'net/ssh'
describe "run commands on a kerberized server" do
  it "it should work" do
    Net::SSH.start(ENV['KERBEROS_TEST_HOST'], ENV['USER'], :auth_methods => ["gssapi-with-mic", "publickey"]).exec!("whoami").strip.should == ENV['USER']
  end
end