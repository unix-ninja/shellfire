"""Data structure of all available shellfire commands.
"""
command_list = {
  "auth": {
    "prefix": ".auth",
    "description": "",
    "help_text": [
      ".auth - show current HTTP Auth credentials\n",
      ".auth <username>:<password> - set the HTTP Auth credentials\n",
    ],
  },
  "config": {
    "prefix": ".config",
    "description": "",
    "help_text": [
      ".config save [name] - save a named config\n",
      ".config load [name] - load a named config\n",
    ],
  },
  "cookies": {
    "prefix": ".cookies",
    "description": "",
    "help_text": [
      ".cookies - show current cookies to be sent with each request\n",
      ".cookies <json> - a json string representing cookies you wish to send\n",
    ],
  },
  "encode": {
    "prefix": ".encode",
    "description": "",
    "help_text": [
      ".encode - show current encoding used before sending commands\n",
      ".encode base64 - encode commands with base64 before sending\n",
      ".encode none - do not encode commands before sending\n",
    ],
  },
  "exit": {
    "prefix": ".exit",
    "description": "",
    "help_text": [
      ".exit - exits this program\n"
    ],
  },
  "find": {
    "prefix": ".find",
    "description": "",
    "help_text": [
      ".find setuid - search for setuid files\n",
      ".find setgid - search for setgid files\n",
    ],
  },
  "help": {
    "prefix": ".help",
    "description": "",
    "help_text": [
      ".help - prints all help topics\n"
    ],
  },
  "history": {
    "prefix": ".history",
    "description": "",
    "help_text": [
      ".history clear - erase history\n",
      ".history nosave - do not write history file\n",
      ".history save - write history file on exit\n",
    ],
  },
  "http": {
    "prefix": ".http",
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
    "prefix": ".marker",
    "description": "",
    "help_text": [
      ".marker <string> - set the payload output marker to string.\n",
    ],
  },
  "method": {
    "prefix": ".method",
    "description": "",
    "help_text": [
      ".method - show current HTTP method\n",
      ".method get - set HTTP method to GET\n",
      ".method post - set HTTP method to POST\n",
    ],
  },
  "phpinfo": {
    "prefix": ".phpinfo",
    "description": "",
    "help_text": [
      ".phpinfo - executes the '_show_phpinfo' command via the PHP payload"
    ],
  },
  "post": {
    "prefix": ".post",
    "description": "",
    "help_text": [
      ".post <json> - a json string representing post data you wish to send\n",
    ]
  },
  "referer": {
    "prefix": ".referer",
    "description": "",
    "help_text": [
      ".referer - show the HTTP referer string\n",
      ".referer <string> - set the value for HTTP referer\n",
    ],
  },
  "headers": {
    "prefix": ".headers",
    "description": "",
    "help_text": [
      ".headers default - sets the headers back to the shellfire defaults\n",
      ".headers {\"X-EXAMPLE\": \"some_value_here\"} - upserts the headers in the JSON object to the header config\n",
    ],
  },
  "shell": {
    "prefix": ".shell",
    "description": "",
    "help_text": [
      ".shell <ip_address> <port> - initiate reverse shell to target\n",
    ]
  },
  "url": {
    "prefix": ".url",
    "description": "",
    "help_text": [
      ".url <string> - set the target URL to string. Use '{}' to specify where command injection goes.\n",
      "                if {} is not set, 'cmd' param will automatically be appended.\n",
    ],
  },
  "useragent": {
    "prefix": ".useragent",
    "description": "",
    "help_text": [
      ".useragent - show the User-Agent string\n",
      ".useragent <string> - set the value for User-Agent\n",
    ],
  },
  "quit": {
    "prefix": ".quit",
    "description": "Alias if \".exit\"",
    "help_text": [
      ".quit - exits this program\n"
    ],
  },
}
