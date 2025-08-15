#!/usr/bin/env python3
"""
Tab completion for ShellFire CLI
Provides command and subcommand completion for the ShellFire exploitation shell.
"""

import os
import readline
import glob
from typing import List, Optional


class ShellfireCompleter:
    """Tab completion for ShellFire commands and subcommands."""
    
    def __init__(self):
        """Initialize the completer with command lists."""
        # Import the actual command list from shellfire
        try:
            from shellfire.commands import command_list
            self.config_commands = list(command_list.keys())
        except ImportError:
            # Fallback to hardcoded list if import fails
            self.config_commands = [
                'help', 'exit', 'config', 'shell', 'auth', 'cookies', 'encode',
                'files', 'find', 'fuzz', 'headers', 'history', 'http', 'marker',
                'method', 'phpinfo', 'plugins', 'post', 'referer', 'revshell',
                'url', 'useragent', 'quit'
            ]
        
        # Subcommands for config command
        self.config_subcommands = [
            'load', 'save', 'show', 'clear', 'reset'
        ]
        
        # Subcommands for plugin command
        self.plugin_subcommands = [
            'list', 'enable', 'disable', 'reload', 'info'
        ]
        
        # Common file extensions for payloads
        self.payload_extensions = ['.php', '.asp', '.aspx', '.jsp', '.py', '.sh']
        
        # Common HTTP headers
        self.http_headers = [
            'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding',
            'Content-Type', 'Content-Length', 'Authorization', 'Cookie',
            'Referer', 'X-Forwarded-For', 'X-Requested-With'
        ]
        
        # Common user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0', 'wget/1.20.3'
        ]
        
        # Common URL schemes and patterns
        self.url_patterns = [
            'http://', 'https://', 'ftp://', 'file://'
        ]
    
    def complete(self, text: str, state: int) -> Optional[str]:
        """
        Main completion function called by readline.
        
        Args:
            text: The text to complete
            state: The state of completion (0 for first call, 1+ for subsequent)
            
        Returns:
            The completion string or None if no more completions
        """
        if state == 0:
            # First call - build the list of completions
            # Get the full line buffer to understand context
            full_line = readline.get_line_buffer()
            self.matches = self._get_completions(full_line)
        
        # Return the next match or None if no more
        try:
            return self.matches[state]
        except IndexError:
            return None
    
    def _get_completions(self, text: str) -> List[str]:
        """
        Get all possible completions for the given text.
        
        Args:
            text: The text to complete
            
        Returns:
            List of possible completions
        """
        if not text:
            return []
        
        # Check if text ends with space (indicating we want subcommand completion)
        ends_with_space = text.endswith(' ')
        
        # Split the input to understand the context
        parts = text.split()
        
        if len(parts) == 1 and not ends_with_space:
            # First word - complete main commands
            return [cmd for cmd in self.config_commands if cmd.startswith(text)]
        
        elif len(parts) >= 1 and (len(parts) >= 2 or ends_with_space):
            # Second or later word - complete subcommands or arguments
            command = parts[0]
            current_word = parts[-1] if len(parts) > 1 else ""
            
            # If we have a space at the end or current_word is empty, show all subcommands
            if ends_with_space or not current_word:
                if command == 'config':
                    return self._complete_config_subcommand('')
                elif command == 'http':
                    return self._complete_http_subcommand('')
                elif command == 'method':
                    return self._complete_method_subcommand('')
                elif command == 'marker':
                    return self._complete_marker_subcommand('')
                elif command == 'history':
                    return self._complete_history_subcommand('')
                elif command == 'fuzz':
                    return self._complete_fuzz_subcommand('')
                elif command == 'find':
                    return self._complete_find_subcommand('')
                elif command == 'help':
                    return self._complete_help_subcommand('')
                else:
                    return []
            
            # Otherwise complete based on what's typed
            if command == 'config':
                return self._complete_config_subcommand(current_word)
            elif command == 'http':
                return self._complete_http_subcommand(current_word)
            elif command == 'method':
                return self._complete_method_subcommand(current_word)
            elif command == 'marker':
                return self._complete_marker_subcommand(current_word)
            elif command == 'history':
                return self._complete_history_subcommand(current_word)
            elif command == 'fuzz':
                return self._complete_fuzz_subcommand(current_word)
            elif command == 'find':
                return self._complete_find_subcommand(current_word)
            elif command == 'help':
                return self._complete_help_subcommand(current_word)
            elif command in ['load', 'save']:
                return self._complete_file_path(current_word)
            else:
                # For other commands, try file completion
                return self._complete_file_path(current_word)
        
        return []
    
    def _complete_config_subcommand(self, text: str) -> List[str]:
        """Complete config subcommands."""
        config_subcommands = ['save', 'load']
        return [cmd for cmd in config_subcommands if cmd.startswith(text)]
    
    def _complete_http_subcommand(self, text: str) -> List[str]:
        """Complete http subcommands."""
        http_subcommands = ['payload', 'start', 'stop']
        return [cmd for cmd in http_subcommands if cmd.startswith(text)]
    
    def _complete_method_subcommand(self, text: str) -> List[str]:
        """Complete method subcommands."""
        method_subcommands = ['get', 'post', 'form']
        return [cmd for cmd in method_subcommands if cmd.startswith(text)]
    
    def _complete_marker_subcommand(self, text: str) -> List[str]:
        """Complete marker subcommands."""
        marker_subcommands = ['set', 'out']
        return [cmd for cmd in marker_subcommands if cmd.startswith(text)]
    
    def _complete_history_subcommand(self, text: str) -> List[str]:
        """Complete history subcommands."""
        history_subcommands = ['clear', 'nosave', 'save']
        return [cmd for cmd in history_subcommands if cmd.startswith(text)]
    
    def _complete_fuzz_subcommand(self, text: str) -> List[str]:
        """Complete fuzz subcommands."""
        fuzz_subcommands = ['start']
        return [cmd for cmd in fuzz_subcommands if cmd.startswith(text)]
    
    def _complete_find_subcommand(self, text: str) -> List[str]:
        """Complete find subcommands."""
        find_subcommands = ['setuid', 'setgid']
        return [cmd for cmd in find_subcommands if cmd.startswith(text)]
    
    def _complete_help_subcommand(self, text: str) -> List[str]:
        """Complete help subcommands (all available commands)."""
        # Use the same command list as main commands
        return [cmd for cmd in self.config_commands if cmd.startswith(text)]
    
    def _complete_file_path(self, text: str) -> List[str]:
        """Complete file paths with glob patterns."""
        if not text:
            return ['.', '..']
        
        # Handle tilde expansion
        if text.startswith('~'):
            text = os.path.expanduser(text)
        
        # Get the directory and filename parts
        dirname = os.path.dirname(text) or '.'
        basename = os.path.basename(text)
        
        try:
            # List files in the directory
            if os.path.exists(dirname):
                files = os.listdir(dirname)
                matches = []
                
                for file in files:
                    if file.startswith(basename):
                        full_path = os.path.join(dirname, file)
                        if os.path.isdir(full_path):
                            matches.append(full_path + '/')
                        else:
                            matches.append(full_path)
                
                return matches
        except (OSError, PermissionError):
            pass
        
        return []
    
    def _complete_http_header(self, text: str) -> List[str]:
        """Complete HTTP header names."""
        return [header for header in self.http_headers if header.lower().startswith(text.lower())]
    
    def _complete_user_agent(self, text: str) -> List[str]:
        """Complete user agent strings."""
        return [ua for ua in self.user_agents if ua.lower().startswith(text.lower())]
    
    def _complete_url(self, text: str) -> List[str]:
        """Complete URL patterns."""
        return [url for url in self.url_patterns if url.startswith(text)]


def setup_tab_completion():
    """Setup tab completion for the current session."""
    try:
        completer = ShellfireCompleter()
        readline.set_completer(completer.complete)
        
        # Set up tab binding for macOS (libedit) vs GNU readline
        import sys
        if sys.platform == 'darwin':
            # macOS uses libedit which has different binding syntax
            readline.parse_and_bind('bind ^I rl_complete')
        else:
            # GNU readline
            readline.parse_and_bind('tab: complete')
        
        return True
    except Exception as e:
        print(f"[DEBUG] Tab completion setup failed: {e}")
        return False


if __name__ == "__main__":
    # Test the completer
    completer = ShellfireCompleter()
    test_inputs = ['au', 'co', 'pl', 'se']
    
    for test_input in test_inputs:
        completions = completer._get_completions(test_input)
        print(f"'{test_input}' -> {completions}") 