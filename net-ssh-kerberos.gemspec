# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{net-ssh-kerberos}
  s.version = "0.2.7"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Joe Khoobyar"]
  s.date = %q{2011-04-28}
  s.description = %q{Extends Net::SSH by adding Kerberos authentication capability for password-less logins on multiple platforms.
}
  s.email = %q{joe@ankhcraft.com}
  s.extra_rdoc_files = [
    "LICENSE",
    "README.rdoc"
  ]
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.homepage = %q{http://github.com/joekhoobyar/net-ssh-kerberos}
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{net-ssh-krb}
  s.rubygems_version = %q{1.7.2}
  s.summary = %q{Add Kerberos support to Net::SSH}

  s.add_dependency 'net-ssh', '>= 2.0'
  s.add_dependency 'gssapi', '~> 1.1.2'
end

