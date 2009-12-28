require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "net-ssh-kerberos"
    gem.summary = %Q{Add Kerberos support to Net::SSH}
    gem.description = <<-EOTEXT
Extends Net::SSH by adding Kerberos authentication capability for password-less logins on multiple platforms.
EOTEXT
    gem.email = "joe@ankhcraft.com"
    gem.homepage = "http://github.com/joekhoobyar/net-ssh-kerberos"
    gem.authors = ["Joe Khoobyar"]
    gem.rubyforge_project = 'net-ssh-krb'
    gem.add_runtime_dependency(%q<net-ssh>, [">= 2.0"])
    gem.required_ruby_version = Gem::Requirement.new("< 1.9")

    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |test|
    test.libs << 'test'
    test.pattern = 'test/**/*_test.rb'
    test.verbose = true
  end
rescue LoadError
  task :rcov do
    abort "RCov is not available. In order to run rcov, you must: sudo gem install spicycode-rcov"
  end
end

Jeweler::RubyforgeTasks.new do |rubyforge|
  rubyforge.doc_task = "rdoc"
  rubyforge.remote_doc_path = ''
end

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
  if File.exist?('VERSION.yml')
    config = YAML.load(File.read('VERSION.yml'))
    version = "#{config[:major]}.#{config[:minor]}.#{config[:patch]}"
  else
    version = ""
  end
  rdoc.options << '--line-numbers' << '--inline-source' <<
    '--main' << 'README.rdoc' <<
    '--charset' << 'utf-8'

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "Net::SSH::Kerberos #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

