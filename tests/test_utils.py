import tempfile
from pathlib import Path

from pytest_mock import MockerFixture

# Need to delay importing corpus for test_registry test to work properly


def test_match_bytes(mocker: MockerFixture):
    from yara_registry.yara import YaraCorpus

    mocker.patch("platformdirs.user_data_dir")
    corpus = YaraCorpus()

    matches = corpus.match(file_bytes=b"test")
    assert len(matches) == 4


def test_match_file(mocker: MockerFixture):
    from yara_registry.yara import YaraCorpus

    mocker.patch("platformdirs.user_data_dir")
    corpus = YaraCorpus()

    with tempfile.TemporaryDirectory() as dir:
        path = Path(dir, "test.yara")
        file = path.open("wb")
        file.write(b"test")
        file.close()
        matches = corpus.match(file_path=file.name)
        assert len(matches) == 4


def test_match_none(mocker: MockerFixture):
    from yara_registry.yara import YaraCorpus

    mocker.patch("platformdirs.user_data_dir")
    corpus = YaraCorpus()

    try:
        corpus.match()
    except ValueError:
        assert True
    else:
        assert False


def test_match_x_bytes(mocker: MockerFixture):
    from yara_registry.yara_x import YaraXCorpus

    mocker.patch("platformdirs.user_data_dir")
    corpus = YaraXCorpus()

    matches = corpus.match(file_bytes=b"test")
    assert len(matches.matching_rules) == 5


def test_match_x_file(mocker: MockerFixture):
    from yara_registry.yara_x import YaraXCorpus

    mocker.patch("platformdirs.user_data_dir")
    corpus = YaraXCorpus()

    with tempfile.TemporaryDirectory() as dir:
        path = Path(dir, "test.file")
        file = path.open("wb")
        file.write(b"test")
        file.close()
        matches = corpus.match(file_path=path)
        assert len(matches.matching_rules) == 5


def test_match_x_none(mocker: MockerFixture):
    from yara_registry.yara_x import YaraXCorpus

    mocker.patch("platformdirs.user_data_dir")
    corpus = YaraXCorpus()

    try:
        corpus.match()
    except ValueError:
        assert True
    else:
        assert False
