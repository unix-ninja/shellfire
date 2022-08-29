import base64 as b64
import urllib.parse

from shellfire.plugin_collection import Plugin

class Base64(Plugin):
    """Base64 encode your input
    """
    def __init__(self):
        super().__init__()
        self.description = 'Base64'

    def run(self, argument):
        return b64.b64encode(str(argument).encode()).decode()

class urlencode(Plugin):
    """URL encode your input
    """
    def __init__(self):
        super().__init__()
        self.description = 'URL encode'

    def run(self, argument):
        return urllib.parse.quote(argument)
