import os
import json
from io import TextIOWrapper
from plugin_collection import plugins
from tokenize import Number
from typing import List, Optional
from urllib.parse import urlparse
from urllib.parse import urlparse

class Configs():
  version: str
  url: str
  history_file: str
  post_data: object
  cookies: object
  headers: object
  default_headers: object
  method: str
  auth: str
  auth_user: str
  auth_pass: str
  payload: str
  payload_type: str
  encode_chain: List[any]
  marker: str
  marker_idx: List[int]
  http_port: Number

  def __init__(self):
    self.version = "0.7.b"
    self.url = "http://www.example.com?"
    self.history_file = os.path.abspath(os.path.expanduser("~/.shellfire_history"))
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
    self.marker = "--9453901401ed3551bc94fcedde066e5fa5b81b7ff878c18c957655206fd538da--"
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
  exec_cmd = True
