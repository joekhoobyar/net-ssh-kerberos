require 'socket'
require 'rubygems'
gem 'net-ssh'
$:.unshift File.join(File.dirname(__FILE__), '..', 'lib')
require 'net/ssh'
require 'net/ssh/errors'
require 'net/ssh/kerberos'

unless Net::SSH::Kerberos::Drivers.available.include? 'GSS'
  $stderr.puts "No drivers supporting GSSAPI could be loaded."
  exit 1
end

include Net::SSH::Kerberos::Drivers::GSS
include Net::SSH::Kerberos::Constants

result = API.gss_acquire_cred nil, 60, nil, GSS_C_INITIATE, nil, nil, 0
if result.ok?
  creds = API._args_[4]
  $stderr.puts "gss_acquire_cred: (#{result}) => #{creds.to_i}"
  begin
    result = API.gss_inquire_cred creds, nil, 0, 0, nil
    if result.ok?
      name, oids = API._args_[1], API._args_[4]
      $stderr.puts "gss_inquire_cred: (#{result}) #{oids.inspect}"
      begin
        result = API.gss_display_name name, buffer=API::GssBuffer.malloc, nil
        if result.ok?
          oid = API._args_[2]
          $stderr.puts "gss_display_name: (#{result}) #{buffer} #{oid.inspect}"
          result = API.gss_release_buffer buffer
          $stderr.puts "gss_release_buffer: (#{result})"
        else
          $stderr.puts "gss_display_name failed : (#{result})"
        end
      ensure
        result = API.gss_release_oid_set oids
        $stderr.puts "gss_release_oid_set: (#{result})"
        result = API.gss_release_name name
        $stderr.puts "gss_release_name: (#{result})"
      end
    else
      $stderr.puts "gss_inquire_cred failed: (#{result})"
    end


    target_name = 'host@'+Socket.gethostbyname(`hostname || echo "localhost"`.strip)[0]
    buffer = API::GssBuffer.malloc
    buffer.value = target_name
    buffer.length = target_name.length
    API.gss_import_name buffer, GSS_C_NT_HOSTBASED_SERVICE, nil
    if result.ok?
      target = API._args_[2]
      $stderr.puts "gss_import_name: (#{result}) #{target.to_i}"
      begin
        result = API.gss_display_name target, buffer, nil
        if result.ok?
          oid = API._args_[2]
          $stderr.puts "gss_display_name: (#{result}) #{buffer} #{oid.inspect}"
          result = API.gss_release_buffer buffer
          $stderr.puts "gss_release_buffer: (#{result})"
        else
          $stderr.puts "gss_display_name failed : (#{result})"
        end
        result = API.gss_init_sec_context creds, GSS_C_NO_CONTEXT, target, GSS_C_KRB5,
                                          GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, 60,
                                          GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, nil, buffer, 0, 0
        if result.ok?
          context, actual_mech = API._args_[1], API._args_[8]
          $stderr.puts "gss_init_sec_context: (#{result}) token.length=#{buffer.length}, #{actual_mech.inspect}"
          result = API.gss_release_buffer buffer
          $stderr.puts "gss_release_buffer: (#{result})"
          result = API.gss_delete_sec_context context, nil
          $stderr.puts "gss_delete_sec_context: (#{result})"
        else
          $stderr.puts "gss_init_sec_context failed : (#{result})"
        end
      ensure
        result = API.gss_release_name target
        $stderr.puts "gss_release_name: (#{result})"
      end
    else
      $stderr.puts "gss_import_name failed: (#{result})"
    end
  ensure
    result = API.gss_release_cred creds
    $stderr.puts "gss_release_cred: (#{result})"
  end
else
  $stderr.puts "gss_acquire_cred failed: (#{result})"
end
