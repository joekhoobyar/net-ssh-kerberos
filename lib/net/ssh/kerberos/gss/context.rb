require 'net/ssh/kerberos/common/context'
require 'net/ssh/kerberos/gss/api'

module Net; module SSH; module Kerberos; module GSS; class Context < Common::Context

  GssResult = API::GssResult

  def init(token=nil)
    $stderr.puts 'init_sec_context'
    minor_status = API::OM_uint32Ref.malloc
    buffer = API::GssBuffer.malloc
    buffer.value = @server_krb_name.sub('host/','host@')
    buffer.length = @server_krb_name.length
    mech = API::GssOID.malloc
    mech.elements = GSS_C_NT_HOSTBASED_SERVICE
    mech.length = GSS_C_NT_HOSTBASED_SERVICE.length
    target_name = API::GssNameRef.malloc
    result = GssResult.new API.gss_import_name(minor_status, buffer, mech, target_name), minor_status
    result.failure? and raise GeneralError, "Error importing name: #{result} #{input.inspect}"
    begin
      #result = API.gss_display_name minor_status, target_name.handle, buffer, nil
      #API.gss_release_buffer minor_status, buffer

      mech.elements = GSS_KRB5_MECH
      mech.length = GSS_KRB5_MECH.length
      actual_mech = API::GssOIDRef.malloc
      if @state.nil? or @state.handle.nil? or @state.handle.handle.nil?
        context = API::GssContextRef.malloc
        context.handle = GSS_C_NO_CONTEXT
      else
        context = @state.handle
      end
      buffer.value = nil
      buffer.length = 0
      if token.nil?
        input = GSS_C_NO_BUFFER
      else
        input = API::GssBuffer.malloc
        input.value = token
        input.length = token.length
      end
      result = GssResult.new API.gss_init_sec_context(minor_status, @credentials, context, target_name.handle, mech,
                                                      GSS_C_DELEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG, 60,
                                                      GSS_C_NO_CHANNEL_BINDINGS, input, actual_mech, buffer, nil, nil),
                              minor_status
      $stderr.puts "context: #{result} (#{buffer.length}) (OID: #{actual_mech.oid.length rescue nil}, #{actual_mech.oid.to_hex rescue nil})"
      result.failure? and raise GeneralError, "Error initializing security context: #{result} #{input.inspect}"
      begin
        @state = State.new(context, result, (buffer.value && buffer.value.to_s(buffer.length).dup), nil)
        @handle = @state.handle if result.complete?
        $stderr.puts "context: #{result.complete?} (#{@state.token.length}) (#{@state.handle.handle.to_i})"
        return @state.token
      ensure
        API.gss_release_buffer minor_status, buffer unless buffer.value.nil?
      end
    ensure
      API.gss_release_name minor_status, target_name
    end
  rescue => e
    $stderr.puts e.to_s
    $stderr.puts e.backtrace.join("\n\t")
    raise e
  end
  
  def get_mic(token=nil)
    $stderr.puts 'get_mic'
    minor_status = API::OM_uint32Ref.malloc
    input = API::GssBuffer.malloc
    input.value = token
    input.length = token.length
    output = API::GssBuffer.malloc
    @state.result = GssResult.new API.gss_get_mic(minor_status, @handle.handle, GSS_C_QOP_DEFAULT, input, output), minor_status
    unless @state.result.complete? and (token = output.value)
      raise GeneralError, "Error creating the signature: #{@state.result}"
    end
    begin return token.dup
    ensure API.gss_release_buffer minor_status, output
    end
  rescue Exception => e
    $stderr.puts e.to_s
    $stderr.puts e.backtrace.join("\n\t")
    raise e
  end

protected

  def state; @state end
  
private
  
  def acquire_current_credentials
    $stderr.puts 'acquire_current_credentials'
    minor_status = API::OM_uint32Ref.malloc
    creds = API::GssCredRef.malloc
    result = GssResult.new API.gss_acquire_cred(minor_status, nil, 60, nil, GSS_C_INITIATE, creds, nil, nil), minor_status
    result.ok? or raise GeneralError, "Error acquiring credentials: #{result}"
    begin
      name = API::GssNameRef.malloc
      result = GssResult.new API.gss_inquire_cred(minor_status, creds.handle, name, nil, nil, nil), minor_status
      result.ok? or raise GeneralError, "Error inquiring credentials: #{result}"
      begin
        buffer = API::GssBuffer.malloc
        result = GssResult.new API.gss_display_name(minor_status, name.handle, buffer, nil), minor_status
        result.ok? or raise GeneralError, "Error getting display name: #{result}"
        begin return [creds, buffer.value.to_s.dup]
        ensure API.gss_release_buffer API::OM_uint32Ref.malloc, buffer
        end
      ensure
        API.gss_release_name API::OM_uint32Ref.malloc, name
      end
    ensure
      API.gss_release_cred API::OM_uint32Ref.malloc, creds
    end
  rescue Exception => e
    $stderr.puts e.to_s
    $stderr.puts e.backtrace.join("\n\t")
    raise e
  end

  def release_credentials(creds)
    creds.nil? or API.gss_release_cred API::OM_uint32Ref.malloc, creds
  end

  def delete_context(handle)
    handle.nil? or API.gss_delete_sec_context API::OM_uint32Ref.malloc, handle, nil
  end

end; end; end; end; end
