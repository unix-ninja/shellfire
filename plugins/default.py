import base64 as b64

from plugin_collection import Plugin

class Base64(Plugin):
    """This plugin will just multiply the argument with the value 2
    """
    def __init__(self):
        super().__init__()
        self.description = 'Base64'

    def run(self, argument):
        """The actual implementation of this plugin is to multiple the
        value of the supplied argument by 2
        """
        return b64.b64encode(str(argument).encode()).decode()

class base32(Plugin):
    """This plugin will just multiply the argument with the value 2
    """
    def __init__(self):
        super().__init__()
        self.description = 'Double function'

    def run(self, argument):
        """The actual implementation of this plugin is to multiple the
        value of the supplied argument by 2
        """
        return argument*20
