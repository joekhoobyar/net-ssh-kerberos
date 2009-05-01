# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{net-ssh-kerberos}
  s.version = "0.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Joe Khoobyar"]
  s.date = %q{2009-04-30}
  s.description = %q{Adds support for Microsoft Kerberos (SSPI) with the Net:SSH gem.
}
  s.email = %q{joe@ankhcraft.com}
  s.extra_rdoc_files = [
    "LICENSE",
    "README.rdoc"
  ]
  s.files = [
    "LICENSE",
    "README.rdoc",
    "Rakefile",
    "lib/net_ssh_kerberos.rb",
    "test/net_ssh_kerberos_test.rb",
    "test/test_helper.rb"
  ]
  s.has_rdoc = true
  s.homepage = %q{http://github.com/joekhoobyar/net-ssh-kerberos}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.2}
  s.summary = %q{Add Kerberos support to Net::SSH}
  s.test_files = [
    "test/net_ssh_kerberos_test.rb",
    "test/test_helper.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<net-ssh>, [">= 2.0"])
      s.add_runtime_dependency(%q<rubysspi>, [">= 1.3"])
    else
      s.add_dependency(%q<net-ssh>, [">= 2.0"])
      s.add_dependency(%q<rubysspi>, [">= 1.3"])
    end
  else
    s.add_dependency(%q<net-ssh>, [">= 2.0"])
    s.add_dependency(%q<rubysspi>, [">= 1.3"])
  end
end
