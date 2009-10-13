$stderr.puts "warning: Kerberos support for non-Windows systems is not yet implemented."

require 'net/ssh/kerberos/gss/api'
require 'net/ssh/kerberos/gss/context'

module Net; module SSH; module Kerberos; module GSS
end; end; end; end
