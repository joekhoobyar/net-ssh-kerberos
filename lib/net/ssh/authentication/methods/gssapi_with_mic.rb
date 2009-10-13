require 'net/ssh/authentication/methods/abstract'
require 'net/ssh/kerberos/constants'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the Kerberos 5 SSH authentication method.
        class GssapiWithMic < Abstract
          include Net::SSH::Kerberbos::Constants
          
	        # OID 1.2.840.113554.1.2.2
          SUPPORTED_OID = "\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"

          # Attempts to perform gssapi-with-mic Kerberos authentication
          def authenticate(next_service, username, password=nil)
            
            # Try to start gssapi-with-mic authentication.
	          debug { "trying kerberos authentication" }
	          client_username = ENV['USER'] || username
	          send_message userauth_request(client_username, next_service, "gssapi-with-mic",
	                                         Buffer.from(:long, 1), SUPPORTED_OID).to_s
	          message = session.next_message
	          case message.type
	            when USERAUTH_GSSAPI_RESPONSE
	              info { "gssapi-with-mic proceeding" }
	            when USERAUTH_FAILURE
	              info { "gssapi-with-mic failed (USERAUTH_FAILURE)" }
	              return false
	            else
	              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
	          end
	          
	          # Try to match the OID.
	          message.read_long
	          message.read_byte
	          message.read_byte
	          if message.read_string != SUPPORTED_OID
              info { "gssapi-with-mic failed (USERAUTH_GSSAPI_RESPONSE)" }
              return false
	          end
	          
	          # Try to complete the handshake.
	          sspi = Net::SSH::Kerberos::SSPI::GSSContext.new
	          sspi.create client_username, hostname
	          until sspi.established?
	            token = sspi.init(token||'')
	            if token
					      send_message Net::SSH::Buffer.from(:byte, USERAUTH_GSSAPI_TOKEN, :string, token)
	              unless sspi.established?
	                message = session.next_message
				          case message.type
				            when USERAUTH_GSSAPI_ERROR
			                message = session.next_message
				            when USERAUTH_GSSAPI_ERRTOK
			                message = session.next_message
				            else
				              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
				          end
				          message.read_long
				          message.read_byte
				          message.read_byte
			            token = message.read_string    
	              end
	            end
	          end
	          
	          # Attempt the actual authentication.
					  mic = context.get_mic Net::SSH::Buffer.from(:byte, USERAUTH_REQUEST, :string, client_username, 
					                                              :string, next_service, :string, "gssapi-with-mic")
            if mic.nil?
              info { "gssapi-with-mic failed (context#get_mic)" }
              return false
            end
			      send_message Net::SSH::Buffer.from(:byte, USERAUTH_GSSAPI_MIC, :string, mic)
			      context.dispose
            message = session.next_message
	          case message.type
	            when USERAUTH_GSSAPI_SUCCESS
	              info { "gssapi-with-mic success" }
	              return true
	            when USERAUTH_FAILURE
	              info { "gssapi-with-mic partial failure (USERAUTH_FAILURE)" }
	              return false
	            else
	              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
	          end
			      
          end

          private

            # Returns the hostname as reported by the underlying socket.
            def hostname
              session.transport.socket.client_name
            end

        end

      end
    end
  end
end
