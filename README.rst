geist.rb
========

An extremely simple self-hosted http paste-bin with syntax highlighting
using `Ruby Rouge`_.

.. _Ruby Rouge: https://github.com/rouge-ruby/rouge

Usage
-----

Usage::

  $ echo "my-secret-key" > ~/.geist-keys
  $ geist.rb -p 8080 2> /dev/null &
  $ curl -F "data=@./foo.txt" -H "GeistApiKey: my-secret-key" localhost:8080
  http://localhost:8080/g/AMZW5E6z/foo.txt

Installation
------------

With Ruby and the `Ruby Bundler`_ installed, geist.rb can be installed
as follows using the provided Makefile::

    # make install

Provided, Ruby Rouge and `WEBrick`_ are installed method and geist.rb
can be run as-is without any further special configuration.

.. _Ruby Bundler: https://bundler.io/
.. _WEBrick: https://github.com/ruby/webrick

Configuration
-------------

geist.rb supports a handful of useful command line options.

::

  $ geist.rb --help
  Usage: geist.rb [options]
      -h, --help                       Display this help.
      -l, --limit-size N               Limit upload size to N bytes.
      -k, --keys PATH                  Path to secret keys file.
      -f, --file-store PATH            Path to file store dir.
      -p, --port PORT                  Port upon which to run.

For HTTPS, grab an SSL certificate from `certbot`_ if you don't already
have one and use a reverse proxy such as `nginx`_. Here is an example
nginx server block that forwards all incoming http traffic to https and
all incoming https traffic to geist.rb, running on port 8080. A firewall
such as UFW can/should be used to block outside access to port 8080, if
desired. (See also ``sample-nginx.conf``).

::

    server {
        # Replace foo.bar with the name of the actual server.
        server_name foo.bar;

        listen [::]:443 ssl;
        listen 443 ssl;

        # Replace these paths with actual keys.
        ssl_certificate /tmp/localhost.crt;
        ssl_certificate_key /tmp/localhost.key;

        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
        }
    }

    server {
        # Replace foo.bar with the name of the actual server.
        server_name foo.bar;

        listen 80;
        listen [::]:80;

        return 301 https://$host$request_uri;
    }

To ensure that geist.rb runs on system boot, it may be convenient to
create a simple systemd unit file. Here is an example of such a file.
(See also ``sample-systemd.service``).

::

    [Unit]
    Description=Sample geist.rb unit file.

    [Service]
    ExecStart=/usr/local/bin/geist.rb -f /var/www/paste -k /etc/geist-keys

    [Install]
    WantedBy=multi-user.target

To conveniently use from Vim, ensure you have cURL installed and drop
the following lines into your .vimrc where appropriate::

    let g:geist_key_cmd = 'echo my-super-secret-key'
    let g:geist_server = 'http://my.awesome.geist.sever:8080'

    function! s:Geist()
        let bn = bufname('%')
        let key = systemlist(g:geist_key_cmd)[0]
        let cmd = 'curl --silent -F "data=@' . bn . '" -H "GeistApiKey: ' . key
        let cmd = cmd . '" ' . g:geist_server
        echo systemlist(cmd)[0]
    endfunction

    com! Geist call s:Geist()

With that in place, ``:Geist`` will upload a paste of the current
buffer and a link to that paste will be displayed. Update
``g:geist_key_cmd`` to a command that when executed will echo your
secret key on the first line of output (ideally this would be an
invocation of `pass`_ or something along those lines) and
``g:geist_server`` to the address of your server.

.. _certbot: https://certbot.eff.org/
.. _nginx: https://nginx.org/
.. _pass: https://www.passwordstore.org/

License
-------

geist.rb is the work of Shawn M. Chapla and is released under the MIT
license.  For more details, see the LICENSE file.
