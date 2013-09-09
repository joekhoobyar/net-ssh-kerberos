# net-ssh-kerberos

Add Kerberos (password-less) authentication capabilities to Net::SSH, without the need for modifying Net::SSH source code.

This is a great way to help get Capistrano to be accepted in mid-to-large size enterprises with strict security rules.

No more getting locked out of the network because you mis-typed your password - even if your company prohibits
public key or host-based authentication.  If your organization uses Kerberos (many mid-to-large size corporations do),
you can use this package to get password-less authentication without breaking your company's security guidelines.

## How to use with Capistrano

Add the following lines to the top of your Capfile (the relevant :auth_method is "gssapi-with-mic")

```
  require 'net/ssh/kerberos'
  set :ssh_options, { :auth_methods => %w(gssapi-with-mic publickey hostbased password keyboard-interactive) }
```

## How to use with 'net/ssh'

With bundler, add the following lines to Gemfile.

```
  gem 'net-ssh', :require => 'net/ssh'
  gem 'net-ssh-krb'
```

Set :auth_methods in Net::SSH options.

```
  #!/usr/bin/env ruby
  require 'rubygems'
  require 'bundler'
  Bundler.require

  Net::SSH.start('10.3.18.198', 'root', {:auth_methods => ["gssapi-with-mic"]}) do |ssh|
    puts ssh.exec!('hostname')
  end
```

## Contributors

- Joe Khoobyar    http://github.com/joekhoobyar
- Joshua Ballanco http://github.com/jballanc
- Liu Lantao      http://github.com/Lax
- Chris Beer	  http://github.com/cbeer
- Linda Julien    http://github.com/ljulien

## Copyright

Copyright (c) 2009-2011 Joe Khoobyar. See LICENSE for details.
