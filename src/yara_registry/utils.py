from pathlib import Path
from typing import List

import yara_x
import yara

def match_x(rules: yara_x.Rules, file_path: Path = None, file_bytes: bytes = None, exception: bool = False) -> yara_x.ScanResults:
    if not file_path and not file_bytes and not exception:
        return rules.scan(b"")
    if not file_path and not file_bytes:
        raise ValueError("Must provide either file_path or file_bytes")
    if file_path:
        with open(file_path, "rb") as sample:
            file_bytes = sample.read()
    return rules.scan(file_bytes)

def match(rules: yara.Rules, file_path: Path = None, file_bytes: bytes = None, exception: bool = False, externals = {}) -> List[yara.Match]:
    if not file_path and not file_bytes and not exception:
        return rules.scan(b"")
    if not file_path and not file_bytes:
        raise ValueError("Must provide either file_path or file_bytes")
    if file_path:
        return rules.match(str(file_path))
    return rules.match(data=file_bytes, externals=externals)