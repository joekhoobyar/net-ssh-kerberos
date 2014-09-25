$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'bundler/setup'
require 'rspec'

ruby_engine = defined?(RUBY_ENGINE) ? RUBY_ENGINE : "ruby"
if ENV['COVERAGE'] and RUBY_VERSION =~ /^1.9/ and ruby_engine != "jruby"
  require 'simplecov'
  SimpleCov.start
end

require 'net/ssh/kerberos'

RSpec.configure do |config|
end
