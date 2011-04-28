module Net; module SSH; module Kerberos
  
  class Context

	  class GeneralError < StandardError; end
	
	  class State < Struct.new(:handle, :result, :token, :timestamp)
	    def complete?; result.complete? end
	  end
	
	  attr_reader :cred_name, :cred_krb_name, :server_name, :server_krb_name
	
	  def initialize
	    raise "Don't create this class directly - use a subclass" if self.class == Context
	  end
	
	  def create(user, host)
	    dispose if @credentials or @target or @handle
	
	    creds, name = acquire_current_credentials
	    begin
	      @cred_name = name.to_s.sub(/^[^\\\/]*[\\\/]/, '')
	      @cred_krb_name = @cred_name.gsub('@', '/');
	
	      z = (user.include?('@') ? user.gsub('@','/') : user+'/')
	      @credentials = creds
	    ensure
	      if @credentials.nil?
	        release_credentials creds unless creds.nil?
	        @cred_name = @cred_krb_name = nil
	      end
	    end
	
	    @server_name = Socket.gethostbyname(host)[0]
	    @target, @server_krb_name = import_server_name host
	
	    true
	  end
	
	  def credentials?; ! @credentials.nil? end
	  
	  def established?; ! @handle.nil? && (@state.nil? || @state.complete?) end
	  
	  def init(token=nil); raise NotImplementedError, "subclasses must implement this method" end
	  
	  def get_mic(token); raise NotImplementedError, "subclasses must implement this method" end
	  
	  def dispose
	    @handle and delete_context @handle
	    @credentials and release_credentials @credentials
	    @target and release_server_name @target
	  ensure
	    @credentials = @cred_name = @cred_krb_name = nil
	    @target = @server_name = @server_krb_name = nil
	    @handle = @state = nil
	  end 
	
	private
	
	  def acquire_current_credentials; raise NotImplementedError, "subclasses must implement this method" end
	
	  def release_credentials(creds); raise NotImplementedError, "subclasses must implement this method" end
	
	  def import_server_name(host); raise NotImplementedError, "subclasses must implement this method" end
	
	  def release_server_name(target); raise NotImplementedError, "subclasses must implement this method" end
	
	  def delete_context(handle); raise NotImplementedError, "subclasses must implement this method" end
	
	end

end; end; end
