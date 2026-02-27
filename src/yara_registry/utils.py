""" Utilities used by yara_registry
"""
from collections.abc import Callable
from pathlib import Path

from yara_registry.exceptions import YaraNotInstalled, YaraXNotInstalled

try:
    import yara
except ImportError:
    YARA_INSTALLED = False
else:
    YARA_INSTALLED = True
try:
    import yara_x
except ImportError:
    YARA_X_INSTALLED = False
else:
    YARA_X_INSTALLED = True


def yara_required(func: Callable):
    """Decorator for functions that require yara-python be installed to be used"""

    def wrapper(*args, **kwargs):
        if not YARA_INSTALLED:
            raise YaraNotInstalled(f"Cannot use {func.__name__} without yara installed")
        return func(*args, **kwargs)

    return wrapper


def yara_x_required(func: Callable):
    """Decorator for functions that require yara-x be installed to be used"""

    def wrapper(*args, **kwargs):
        if not YARA_X_INSTALLED:
            raise YaraXNotInstalled(
                f"Cannot use {func.__name__} without yara_x installed"
            )
        return func(*args, **kwargs)

    return wrapper


@yara_x_required
def match_x(
    rules: "yara_x.Rules", file_path: Path = None, file_bytes: bytes = None, **kwargs
) -> "yara_x.ScanResults":
    """Match yara rules against provided input using yara_x
    :param rules: Rules to match against
    :type rules: yara_x.Rules
    :param file_path: Path of file to match against, must set this or file_bytes
    :type file_path: Path
    :param file_bytes: bytes content to match against, must set this or file_path
    :type file_bytes: bytes
    :param kwargs: Additional keyword arguments to pass to matching function
    :return: Results of scan that matches on the provided input
    :rtype: ScanResults
    """
    if not file_path and not file_bytes:
        raise ValueError("Must supply either file_path or file_bytes")
    if file_path:
        with open(file_path, "rb") as sample:
            file_bytes = sample.read()
    return rules.scan(file_bytes, **kwargs)


@yara_required
def match(
    rules: "yara.Rules",
    file_path: Path = None,
    file_bytes: bytes = None,
    externals: dict = None,
    **kwargs,
) -> list["yara.Match"]:
    """Match yara rules against provided input using yara
    :param rules: Rules to match against
    :type rules: yara.Rules
    :param file_path: Path of file to match against, must set this or file_bytes
    :type file_path: Path
    :param file_bytes: bytes content to match against, must set this or file_path
    :type file_bytes: bytes
    :param externals: Dictionary of external values to pass to rules.match()
    :type externals: dict
    :param kwargs: Additional keyword arguments to pass to matching function
    :return: List of rules that matches on the provided input
    :rtype: list[yara.Match]
    """
    if externals is None:
        externals = {}
    if not file_path and not file_bytes:
        raise ValueError("Must supply either file_path or file_bytes")
    if file_path:
        return rules.match(str(file_path), externals=externals, **kwargs)
    return rules.match(data=file_bytes, externals=externals, **kwargs)
