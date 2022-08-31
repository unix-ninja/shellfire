import inspect
import os
import pkgutil
import sys


class Plugin(object):
  """Base class that each plugin must inherit from. within this class
  you must define the methods that all of your plugins must implement
  """

  def __init__(self):
    self.description = 'UNKNOWN'

  def run(self, argument):
    """The method that we expect all plugins to implement. This is the
    method that our framework will call
    """
    raise NotImplementedError


class PluginCollection(object):
  """Upon creation, this class will read the plugins package for modules
  that contain a class definition that is inheriting from the Plugin class
  """

  debug = False

  def __init__(self, plugin_package, debug=False):
    """Constructor that initiates the reading of all available plugins
    when an instance of the PluginCollection object is created
    """
    if debug:
      self.debug = True
    self.plugin_package = plugin_package
    self.reload_plugins()

  def reload_plugins(self):
    """Reset the list of all plugins and initiate the walk over the main
    provided plugin package to load all available plugins
    """
    self.plugins = {}
    self.seen_paths = []
    if type(self.plugin_package) == list:
      for pkg in self.plugin_package:
        if self.debug:
          print()
          print(f'Looking for plugins under package {pkg}')
        self.walk_package(pkg)
    else:
      if self.debug:
        print()
        print(f'Looking for plugins under package {self.plugin_package}')
      self.walk_package(self.plugin_package)

  def apply(self, name, argument):
    """Apply a plugin on the argument supplied to this function
    """
    try:
      plugin = self.plugins[name]
      argument = plugin.run(argument)
      if self.debug is True:
        print(f' -> {plugin.description} : {argument}')
    except Exception as e:
      print(f"Error in {plugin.description}: {e}")
    return argument

  def apply_all(self, argument):
    """Apply all of the plugins on the argument supplied to this function
    """
    print()
    print(f'Applying all plugins on value {argument}:')
    for plugin in self.plugins:
      try:
        argument = plugin.run(argument)
        if self.debug:
          print(f' -> {plugin.description} : {argument}')
      except Exception as e:
        print(f"Error in {plugin.description}: {e}")
    return argument

  def walk_package(self, package):
    """Recursively walk the supplied package to retrieve all plugins
    """
    try:
      imported_package = __import__(package, fromlist=['n/a'])
    except Exception as e:
      if package != "plugins":
        print(f"Error: {e}")
      return

    for _, pluginname, ispkg in pkgutil.iter_modules(
        imported_package.__path__,
        imported_package.__name__ + '.'):
      if not ispkg:
        plugin_module = __import__(pluginname, fromlist=['n/a'])
        clsmembers = inspect.getmembers(plugin_module, inspect.isclass)
        for (_, c) in clsmembers:
          ## Only add classes that are a sub class of Plugin, NOT Plugin itself
          if issubclass(c, Plugin) & (c is not Plugin):
            if self.debug:
              print(f'  Found plugin: {c.__name__.lower()}')
            ## make sure the key is the lowercase version  of the class name
            self.plugins[c.__name__.lower()] = c()

    ## Now that we have looked at all the modules in the current package,
    ## start looking recursively for additional modules in sub packages.
    all_current_paths = []
    if isinstance(imported_package.__path__, str):
      all_current_paths.append(imported_package.__path__)
    else:
      all_current_paths.extend([x for x in imported_package.__path__])

    for pkg_path in all_current_paths:
      if pkg_path not in self.seen_paths:
        self.seen_paths.append(pkg_path)

        ## Get all sub directory of the current package path directory
        child_pkgs = [p for p in os.listdir(pkg_path)
                      if os.path.isdir(os.path.join(pkg_path, p))]

        ## For each sub directory, apply the walk_package method recursively
        for child_pkg in child_pkgs:
          self.walk_package(package + '.' + child_pkg)
    return


## set the search path for custom plugins
sys.path.append(os.path.expanduser("~/.config/shellfire"))

## initialize our  available plugins
plugins = PluginCollection(['shellfire.default_plugins', 'plugins'], debug=False)
