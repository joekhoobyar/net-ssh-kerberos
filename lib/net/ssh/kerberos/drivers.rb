require 'dl/import'
require 'dl/struct'

module Net; module SSH; module Kerberos;
  
  module Drivers

    # Some useful DL extensions.
	  module DLExtensions
	    PTR_ENC = proc{|v| v && (DL::PtrData===v ? v : v.to_ptr) }
	    PTR_REF_ENC = proc{|v| (v.nil? ? DL::PtrData.new(v) : (DL::PtrData===v ? v : v.to_ptr)).ref }
	      
	    module ClassMethods
		    def PTR_DEC(t) proc{|v| v && t.new(v)} end
		    def PTR_REF_DEC(t) proc{|v| v && v.ptr && t.new(v.ptr)} end
		  
		    def struct2(fields, &block)
		      t = struct fields
		      return t unless block_given?
		      t.instance_variable_set :@methods, Module.new(&block)
		      class << t
		        alias :new_struct :new
		        def new(ptr)
		          mem = new_struct(ptr)
		          mem.extend @methods
		          mem
		        end
		      end
		      t
		    end
	    end
	    
	    def self.included(base)
	      base.extend ClassMethods
	    end
	  end
	  
	  @@available = []
    def self.available; @@available end

		if RUBY_PLATFORM.include?('win') && ! RUBY_PLATFORM.include?('dar'); then
		  begin require 'net/ssh/kerberos/drivers/sspi'; available << 'SSPI'
		  rescue => e
		    raise e unless RuntimeError === e and e.message =~ /^LoadLibrary: ([^\s]+)/
			  $stderr.puts "error: While loading Kerberos SSPI: failed to load library: #{$1}"
		  end
		end
		begin require 'net/ssh/kerberos/drivers/gss'; available << 'GSS'
		rescue => e; raise e if available.empty?
		end
			
		if available.empty?
		  $stderr.puts "error: Failed to a find a supported GSS implementation on this platform (#{RUBY_PLATFORM})"
		end
  end

end; end; end
