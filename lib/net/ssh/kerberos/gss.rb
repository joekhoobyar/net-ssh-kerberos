if ! defined? Net::SSH::Kerberos::SSPI::Context
  $stderr.puts "warning: Kerberos support using GSSAPI is not yet completed."
end

require 'net/ssh/kerberos/gss/api'
require 'net/ssh/kerberos/gss/context'

module Net; module SSH; module Kerberos; module GSS
end; end; end; end
