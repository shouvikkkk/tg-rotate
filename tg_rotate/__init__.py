"""tg-rotate: bot token rotation supervisor for Telegram bots.

Rotate a bot token across every copy on a host (config files, shell
environment, running processes) and -- the part everyone skips -- VERIFY
that the running service actually uses the new token instead of merely
verifying that the new token is valid.
"""

__version__ = "0.1.0"
