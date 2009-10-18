require 'dl/import'
require 'dl/struct'

module Net; module SSH; module Kerberos;
  
  module Drivers

    # Some useful DL extensions.
	  module DLExtensions
	    PTR_ENC = proc{|v| v && v.to_ptr }
	    PTR_REF_ENC = proc{|v| (v.nil? ? DL::PtrData.new(v) : v.to_ptr).ref }
	      
	    module ClassMethods
		    def PTR_DEC(t) proc{|v| v && t.new(v)} end
		    def PTR_REF_DEC(t) proc{|v| v && t.new(v.ptr)} end
		  
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
  end

end; end; end
