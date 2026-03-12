""" Exceptions for yara-registry
"""


class YaraNotInstalled(Exception):
    """Error thrown when yara is not installed but a function requiring yara was called"""


class YaraXNotInstalled(Exception):
    """Error thrown when yara-x is not installed but a function requiring yara-x was called"""
