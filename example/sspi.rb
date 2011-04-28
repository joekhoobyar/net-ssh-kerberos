#$DEBUG = 1

require 'socket'
require 'rubygems'
gem 'net-ssh'
$:.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'net/ssh'
require 'net/ssh/errors'
require 'net/ssh/kerberos'

unless Net::SSH::Kerberos::Drivers.available.include? 'SSPI'
  $stderr.puts "No drivers supporting SSPI could be loaded."
  exit 1
end

include Net::SSH::Kerberos::Drivers::SSPI
include Net::SSH::Kerberos::Constants

result = API.querySecurityPackageInfo "Kerberos", nil
if result.ok?
  pkg_info = API._args_[1]
  $stderr.puts "querySecurityPackageInfo: (#{result}) #{pkg_info.comment} (max_token=#{pkg_info.max_token})"
  @max_token = pkg_info.max_token
  result = API.freeContextBuffer pkg_info.to_ptr
  $stderr.puts "freeContextBuffer: (#{result})"
else
  $stderr.puts "querySecurityPackageInfo: (#{result})"
end

result = API.acquireCredentialsHandle nil, "Kerberos", SECPKG_CRED_OUTBOUND, nil, nil, nil, nil,
                                      creds=API::SecHandle.malloc, ts=API::TimeStamp.malloc
if result.ok?
  $stderr.puts "acquireCredentialsHandle: (#{result})"
  begin
    result = API.queryCredentialsAttributes creds, SECPKG_ATTR_NAMES, nil
    if result.ok?
      names = API._args_[2]
      $stderr.puts "queryCredentialsAttributes: (#{result}) #{names.to_s}"
      result = API.freeContextBuffer names
      $stderr.puts "freeContextBuffer: (#{result})"

      output = API::SecBufferDesc.create @max_token
      if $DEBUG
        $stderr.puts "SecBufferDesc.create: #{output.inspect} => #{output.buffer(0).inspect} => #{output.buffer(0).data.inspect}"
      end
      result = API.initializeSecurityContext creds, nil, 'host/'+Socket.gethostbyname('localhost')[0], 
                                             ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY, 0, SECURITY_NATIVE_DREP,
                                             nil, 0, ctx=API::SecHandle.malloc, output, 0, ts=API::TimeStamp.malloc
      if result.ok?
        $stderr.puts "initializeSecurityContext: (#{result}) ctx=#{! ctx.nil?} token.length=#{output.buffer(0).length}"
        result = API.deleteSecurityContext ctx
        $stderr.puts "deleteSecurityContext: (#{result})"
      else
        $stderr.puts "initializeSecurityContext: (#{result})"
      end
    else
      $stderr.puts "queryCredentialsAttributes: (#{result})"
    end
  ensure
    result = API.freeCredentialsHandle creds
    $stderr.puts "freeCredentialsHandle : (#{result})"
  end
else
  $stderr.puts "acquireCredentialsHandle: (#{result})"
end


