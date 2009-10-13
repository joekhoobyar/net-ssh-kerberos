require 'net/ssh/authentication/methods/abstract'
require 'net/ssh/kerberos/constants'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the Kerberos 5 SSH authentication method.
        class GssapiWithMic < Abstract
          include Net::SSH::Kerberos::Constants
          
	        # OID 1.2.840.113554.1.2.2
          SUPPORTED_OID = #"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
              [ 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2 ].pack("C*")

          # Attempts to perform gssapi-with-mic Kerberos authentication
          def authenticate(next_service, username, password=nil)
            gss_klass = (defined?(Net::SSH::Kerberos::SSPI::Context) ?
	                           Net::SSH::Kerberos::SSPI::Context : Net::SSH::Kerberos::GSS::Context)
            gss = nil
            
            # Try to start gssapi-with-mic authentication.
	          debug { "trying kerberos authentication" }
	          req = userauth_request(username, next_service, "gssapi-with-mic")
	          req.write_long 1
	          req.write_string SUPPORTED_OID
	          send_message req
	          message = session.next_message
	          case message.type
	            when USERAUTH_GSSAPI_RESPONSE
	              debug { "gssapi-with-mic proceeding" }
	            when USERAUTH_FAILURE
	              info { "gssapi-with-mic failed (USERAUTH_FAILURE)" }
	              return false
	            else
	              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
	          end
	          
	          # Try to match the OID.
	          oid = message.read_string
	          if oid != SUPPORTED_OID
              info { "gssapi-with-mic failed (USERAUTH_GSSAPI_RESPONSE)" }
              return false
	          end
	          
	          # Try to complete the handshake.
	          gss = gss_klass.new
	          gss.create username, hostname
			      debug { "gssapi-with-mic handshaking" }
	          until gss.established?
	            token = gss.init(token)
	            if token && token.length > 0
					      send_message Net::SSH::Buffer.from(:byte, USERAUTH_GSSAPI_TOKEN, :string, token)
	              unless gss.established?
	                message = session.next_message
				          case message.type
				          when USERAUTH_GSSAPI_ERROR
			              message = session.next_message
			              message.get_long
			              message.get_long
				            info { "gssapi-with-mic error (USERAUTH_GSSAPI_ERROR) (#{message.read_string})" }
				          when USERAUTH_GSSAPI_ERRTOK
			              message = session.next_message
				            info { "gssapi-with-mic error (USERAUTH_GSSAPI_ERRTOK) (#{message.read_string})" }
				          when USERAUTH_FAILURE
				            info { "gssapi-with-mic failed (USERAUTH_FAILURE)" }
				            return false
				          end
	                token = message.read_string
	              end
	            end
	          end
	          
	          # Attempt the actual authentication.
			      debug { "gssapi-with-mic authenticating" }
					  mic = gss.get_mic Net::SSH::Buffer.from(:string, session_id, :byte, USERAUTH_REQUEST, :string, username, 
				                                             :string, next_service, :string, "gssapi-with-mic").to_s
            if mic.nil?
              info { "gssapi-with-mic failed (context#get_mic)" }
              return false
            end
			      send_message Net::SSH::Buffer.from(:byte, USERAUTH_GSSAPI_MIC, :string, mic)
            message = session.next_message
	          case message.type
	            when USERAUTH_SUCCESS
	              info { "gssapi-with-mic success" }
	              return true
	            when USERAUTH_FAILURE
	              info { "gssapi-with-mic partial failure (USERAUTH_FAILURE)" }
	              return false
	            else
	              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
	          end
          ensure
			      gss and gss.dispose
          end

          private

            # Returns the hostname as reported by the underlying socket.
            def hostname
              session.transport.host
            end

        end

      end
    end
  end
end
