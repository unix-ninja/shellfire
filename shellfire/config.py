import os
import json
import pkg_resources
import requests
from tokenize import Number
from typing import List
from enum import Enum

## define application modes
class Mode(Enum):
  config = 1
  shell = 2

## define our shell prompts
prompt = {Mode.config: "config", Mode.shell: "shell"}

## session configurable options defined here
class Configs():
  auth: str
  auth_user: str
  auth_pass: str
  cookies: object
  default_headers: object
  encode_chain: List[any]
  files: dict
  fuzzfile: str
  headers: object
  history_file: str
  http_port: Number
  marker: str
  marker_idx: List[int]
  method: str
  payload: str
  payload_type: str
  post_data: object
  url: str
  version: str

  def __init__(self):
    self.version = pkg_resources.require("shellfire")[0].version
    self.url = "http://www.example.com?"
    self.history_file = os.path.abspath(
        os.path.expanduser("~/.shellfire_history"))
    self.post_data = {}
    self.cookies = {}
    self.headers = {
        'User-Agent': '',
        'Referer': ''
    }

    """The default header set for outgoing requests.
    """
    self.default_headers = {
        'User-Agent': ''
    }

    self.method = "get"

    self.auth = None
    self.auth_user = None
    self.auth_pass = None
    self.payload = ""
    self.payload_type = "PHP"
    self.encode_chain = []
    self.encode = None
    self.files = {}
    self.fuzzfile = "default"
    self.marker = "--9453901401ed3551bc94fcedde066e5fa5b81b7ff878c18c957655206fd538da--"
    self.marker_idx = [1]
    self.http_port = 8888

  def dump(self):
    return json.dumps(self.__dict__)

  def load(self, json_cfg):
    self.__dict__.update(json_cfg)
    return


## instantiate our config class
cfg = Configs()


## store our ephemeral state here
class state():
  args = None
  http_running = False
  revshell_running = False
  userinput = None
  input_offset = 0
  exec_cmd = True
  requests = requests.Session()
  mode = Mode.config
