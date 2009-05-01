require 'net/ssh/kerberos/kex/krb5_diffie_hellman_group1_sha1'

module Net; module SSH; module Kerberos
  module Kex
    
    MAP = {
      'gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==' => KRB5DiffieHellmanGroup1SHA1,
      'gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==' => KRB5DiffieHellmanGroupExchangeSHA1
    }
    
    Net::SSH::Transport::Kex::MAP.update MAP

  end
end; end; end

