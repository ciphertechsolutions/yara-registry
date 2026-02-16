""" Utilities used by yara_registry
"""
from pathlib import Path

import yara
import yara_x


def match_x(
    rules: yara_x.Rules, file_path: Path = None, file_bytes: bytes = None
) -> yara_x.ScanResults:
    """Match yara rules against provided input using yara_x
    :param rules: Rules to match against
    :type rules: yara_x.Rules
    :param file_path: Path of file to match against, must set this or file_bytes
    :type file_path: Path
    :param file_bytes: bytes content to match against, must set this or file_path
    :type file_bytes: bytes
    :return: Results of scan that matches on the provided input
    :rtype: ScanResults
    """
    if not file_path and not file_bytes:
        raise ValueError("Must supply either file_path or file_bytes")
    if file_path:
        with open(file_path, "rb") as sample:
            file_bytes = sample.read()
    return rules.scan(file_bytes)


def match(
    rules: yara.Rules,
    file_path: Path = None,
    file_bytes: bytes = None,
    externals: dict = None,
) -> list[yara.Match]:
    """Match yara rules against provided input using yara
    :param rules: Rules to match against
    :type rules: yara.Rules
    :param file_path: Path of file to match against, must set this or file_bytes
    :type file_path: Path
    :param file_bytes: bytes content to match against, must set this or file_path
    :type file_bytes: bytes
    :param externals: Dictionary of external values to pass to rules.match()
    :type externals: dict
    :return: List of rules that matches on the provided input
    :rtype: list[yara.Match]
    """
    if externals is None:
        externals = {}
    if not file_path and not file_bytes:
        raise ValueError("Must supply either file_path or file_bytes")
    if file_path:
        return rules.match(str(file_path), externals=externals)
    return rules.match(data=file_bytes, externals=externals)
