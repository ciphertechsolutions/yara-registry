import tempfile
from pathlib import Path

# Need to delay importing corpus for test_registry test to work properly


def test_match_bytes():
    from yara_registry import corpus

    matches = corpus.match(file_bytes=b"test")
    assert len(matches) == 4


def test_match_file():
    from yara_registry import corpus

    with tempfile.TemporaryFile() as file:
        file.write(b"test")
        matches = corpus.match(file_path=file.name)
        assert len(matches) == 4


def test_match_none():
    from yara_registry import corpus

    try:
        corpus.match()
    except ValueError:
        assert True
    else:
        assert False


def test_match_x_bytes():
    from yara_registry import corpus

    matches = corpus.match_x(file_bytes=b"test")
    assert len(matches.matching_rules) == 5


def test_match_x_file():
    from yara_registry import corpus

    with tempfile.TemporaryDirectory() as dir:
        path = Path(dir, "test.file")
        file = path.open("wb")
        file.write(b"test")
        file.close()
        matches = corpus.match_x(file_path=path)
        assert len(matches.matching_rules) == 5


def test_match_x_none():
    from yara_registry import corpus

    try:
        corpus.match_x()
    except ValueError:
        assert True
    else:
        assert False
