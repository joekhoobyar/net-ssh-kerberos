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

          # Attempts to perform host-based authorization of the user by trying
          # all known keys.
          def authenticate(next_service, username, password=nil)
            
	          debug { "trying kerberos authentication" }
	          client_username = ENV['USER'] || username
	
	          req = userauth_request(client_username, next_service, "gssapi-with-mic",
	                                 Buffer.from(:long, 1), SUPPORTED_OID).to_s
	          send_message(req)
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
	          
	          message.read_long
	          message.read_byte
	          message.read_byte
	          if message.read_string != SUPPORTED_OID
              info { "gssapi-with-mic failed (USERAUTH_GSSAPI_RESPONSE)" }
              return false
	          end
          end

          private

            # Returns the hostname as reported by the underlying socket.
            def hostname
              session.transport.socket.client_name
            end

            # Build the "core" hostbased request string.
            def build_request(identity, next_service, username, hostname, client_username)
              userauth_request(username, next_service, "gssapi-with-mic", identity.ssh_type,
                Buffer.from(:key, identity).to_s, hostname, client_username).to_s
            end

        end

      end
    end
  end
end
