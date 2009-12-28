# Generated by jeweler
# DO NOT EDIT THIS FILE
# Instead, edit Jeweler::Tasks in Rakefile, and run `rake gemspec`
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{net-ssh-kerberos}
  s.version = "0.2.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Joe Khoobyar"]
  s.date = %q{2009-12-28}
  s.description = %q{Extends Net::SSH by adding Kerberos authentication capability for password-less logins on multiple platforms.
}
  s.email = %q{joe@ankhcraft.com}
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc"
  ]
  s.files = [
    ".document",
     ".gitignore",
     "LICENSE",
     "README.rdoc",
     "Rakefile",
     "VERSION.yml",
     "example/Capfile",
     "example/gss.rb",
     "example/sspi.rb",
     "lib/net/ssh/authentication/methods/gssapi_with_mic.rb",
     "lib/net/ssh/kerberos.rb",
     "lib/net/ssh/kerberos/constants.rb",
     "lib/net/ssh/kerberos/context.rb",
     "lib/net/ssh/kerberos/drivers.rb",
     "lib/net/ssh/kerberos/drivers/gss.rb",
     "lib/net/ssh/kerberos/drivers/sspi.rb",
     "lib/net/ssh/kerberos/kex.rb",
     "lib/net/ssh/kerberos/kex/krb5_diffie_hellman_group1_sha1.rb",
     "lib/net/ssh/kerberos/kex/krb5_diffie_hellman_group_exchange_sha1.rb",
     "net-ssh-kerberos.gemspec",
     "test/gss_context_test.rb",
     "test/gss_test.rb",
     "test/net_ssh_kerberos_test.rb",
     "test/sspi_context_test.rb",
     "test/sspi_test.rb",
     "test/test_helper.rb"
  ]
  s.homepage = %q{http://github.com/joekhoobyar/net-ssh-kerberos}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new("< 1.9")
  s.rubyforge_project = %q{net-ssh-krb}
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Add Kerberos support to Net::SSH}
  s.test_files = [
    "test/test_helper.rb",
     "test/gss_context_test.rb",
     "test/gss_test.rb",
     "test/net_ssh_kerberos_test.rb",
     "test/sspi_context_test.rb",
     "test/sspi_test.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<net-ssh>, [">= 2.0"])
    else
      s.add_dependency(%q<net-ssh>, [">= 2.0"])
    end
  else
    s.add_dependency(%q<net-ssh>, [">= 2.0"])
  end
end
