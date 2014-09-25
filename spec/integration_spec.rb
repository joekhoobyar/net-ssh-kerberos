require 'spec_helper'
require 'net/ssh'

describe "run commands on a kerberized server" do
  let :conn do
    Net::SSH.start(ENV['KERBEROS_TEST_HOST'], ENV['USER'], :auth_methods => ["gssapi-with-mic", "publickey"])
  end
  
  it "it should work" do
    remote_user_name = conn.exec!("whoami")
    
    expect(remote_user_name.strip).to eq ENV['USER']
  end
end
