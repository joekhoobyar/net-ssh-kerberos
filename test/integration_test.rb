require 'rubygems'
require File.expand_path(File.join(File.dirname(__FILE__), 'test_helper.rb'))

%w(net/ssh net/ssh/kerberos).each { |lib| require lib }
puts Net::SSH.start(ARGV.shift, ENV['USER'], :auth_methods => ["gssapi-with-mic", "publickey"]).exec! "whoami"
