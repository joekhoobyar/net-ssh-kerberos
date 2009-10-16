require 'net/ssh'
require 'net/ssh/kerberos/constants'
#require 'net/ssh/kerberos/kex'

if RUBY_PLATFORM.include?('win') && ! RUBY_PLATFORM.include?('dar'); then
  begin
    require 'net/ssh/kerberos/sspi'
  rescue Exception => e
    if RuntimeError === e and e.message =~ /^LoadLibrary: ([^\s]+)/
      $stderr.puts "error: While loading Kerberos SSPI: failed to load library: #{$1}"
    else
      raise e
    end
  end
end
require 'net/ssh/kerberos/gss'
require 'net/ssh/authentication/methods/gssapi_with_mic'

module Net
  module SSH
    module Kerberos
    end
  end
end
