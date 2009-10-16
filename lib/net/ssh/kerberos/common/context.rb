module Net; module SSH; module Kerberos; module Common; class Context

  class GeneralError < StandardError; end

  class State < Struct.new(:handle, :result, :token, :timestamp)
    def complete?; result.complete? end
  end

  attr_reader :cred_name, :cred_krb_name, :server_name, :server_krb_name

  def initialize
    raise "Don't create this class directly - use a subclass" if self.class == Context
  end

  def create(user, host)
    dispose if @credentials or @handle
    creds, name = acquire_current_credentials
    begin
      @cred_name = name.to_s.sub(/^[^\\\/]*[\\\/]/, '')
      @cred_krb_name = @cred_name.gsub('@', '/');
      @server_name = Socket.gethostbyname(host)[0]
      @server_krb_name = "host/" + @server_name

      z = (user.include?('@') ? user.gsub('@','/') : user+'/')
      unless z.downcase == @cred_krb_name[0,z.length].downcase
        raise GeneralError, "Credentials mismatch: current is #{@cred_name}, requested is #{user}"
      end
      @credentials = creds
    ensure
      @credentials or release_credentials creds
    end
  end

  def credentials?; ! @credentials.nil? end
  
  def established?; ! @handle.nil? && (@state.nil? || @state.complete?) end
  
  def init(token=nil); raise NotImplementedError, "subclasses must implement this method" end
  
  def get_mic(token=nil); raise NotImplementedError, "subclasses must implement this method" end
  
  def dispose
    release_credentials @credentials
    delete_context @handle
  ensure
    @handle = @credentials = nil
  end 

private

  def acquire_current_credentials; raise NotImplementedError, "subclasses must implement this method" end

  def release_credentials; raise NotImplementedError, "subclasses must implement this method" end

  def delete_context; raise NotImplementedError, "subclasses must implement this method" end

end; end; end; end; end
