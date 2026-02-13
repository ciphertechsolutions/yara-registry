from pathlib import Path

import yara
import yara_x


def match_x(
    rules: yara_x.Rules, file_path: Path = None, file_bytes: bytes = None
) -> yara_x.ScanResults:
    if not file_path and not file_bytes:
        raise ValueError("Must supply either file_path or file_bytes")
    if file_path:
        with open(file_path, "rb") as sample:
            file_bytes = sample.read()
    return rules.scan(file_bytes)


def match(
    rules: yara.Rules, file_path: Path = None, file_bytes: bytes = None, externals={}
) -> list[yara.Match]:
    if not file_path and not file_bytes:
        raise ValueError("Must supply either file_path or file_bytes")
    if file_path:
        return rules.match(str(file_path), externals=externals)
    return rules.match(data=file_bytes, externals=externals)
