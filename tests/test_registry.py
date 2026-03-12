import tempfile
from importlib import metadata
from pathlib import Path

from pytest_mock.plugin import MockerFixture


def test_sample_install():
    sample_project = metadata.entry_points(
        group="yara_registry.rules", value="yara_registry_sample"
    )
    assert sample_project
    all_rules = metadata.entry_points(group="yara_registry.rules")
    assert len(all_rules) == 1


def test_corpus(mocker: MockerFixture):
    # Prevent any locally installed rules from being found
    mocker.patch("platformdirs.user_data_dir")
    from yara_registry.registry import Corpus

    corpus = Corpus()
    assert len(corpus) == 1


def test_rule():
    from yara_registry.registry import Corpus

    corpus = Corpus()

    assert "yara_registry_sample" in corpus
    for rule in corpus["yara_registry_sample"].rules:
        if rule.name == "test_yara_x.yara":
            assert not rule.yara_compatible
            assert rule.yara_x_compatible
        else:
            assert rule.yara_compatible
            assert rule.yara_x_compatible
        assert rule.name in [
            "test_1.yara",
            "test_2.yara",
            "test_3.yara",
            "test_4.yara",
            "test_yara_x.yara",
        ]


def test_rule_invalid():
    from yara_registry.registry import Rule

    with tempfile.TemporaryDirectory() as dir, open(Path(dir, "test.yara"), "w") as f:
        f.write("Not a valid yara rule")
        f.seek(0)
        path = Path(f"{f.name}")
        rule = Rule(path)
    assert rule.name == path.name
    assert not rule.yara_compatible
    assert not rule.yara_x_compatible
    assert repr(rule) == f"Rule file at {path}"


def test_source_from_file():
    from yara_registry.yara import YaraSource
    from yara_registry.yara_x import YaraXSource

    with tempfile.TemporaryDirectory() as dir, open(Path(dir, "test.yara"), "w") as f:
        f.write("rule test_str \n{\n\tcondition:\n\ttrue}")
        yara_source = YaraSource("test", Path(dir, "test.yara"))
        yara_x_source = YaraXSource("test", Path(dir, "test.yara"))
        assert yara_source
        assert yara_x_source
        assert len(yara_source.rules) == 1
        assert len(yara_x_source.rules) == 1
        assert (
            str(yara_source) == f"Package test: 1 rules from {Path(dir, 'test.yara')}"
        )
        assert (
            str(yara_x_source) == f"Package test: 1 rules from {Path(dir, 'test.yara')}"
        )
        assert (
            repr(yara_source)
            == f"Package test: 1 rules from {Path(dir, 'test.yara')}: [test.yara]"
        )
        assert (
            repr(yara_x_source)
            == f"Package test: 1 rules from {Path(dir, 'test.yara')}: [test.yara]"
        )
        assert len(yara_source.compatible_rules) == 1
        assert len(yara_x_source.compatible_rules) == 1
        assert yara_source.rules
        assert yara_x_source.rules


def test_corpus_rules(mocker: MockerFixture):
    from yara_registry.yara import YaraCorpus
    from yara_registry.yara_x import YaraXCorpus

    mocker.patch("platformdirs.user_data_dir")
    yara_corpus = YaraCorpus()
    yara_x_corpus = YaraXCorpus()

    assert len(yara_corpus.compatible_rules) == 4
    assert len(yara_x_corpus.compatible_rules) == 5


def test_functions(mocker: MockerFixture):
    from yara_registry.yara import YaraCorpus

    mocker.patch("platformdirs.user_data_dir")
    corpus = YaraCorpus()

    assert corpus.get_source("yara_registry_sample")
    assert len([rule for rule in corpus.get_all_rules_compiled()]) == 4
    assert len(corpus.get_all_rule_paths()) == 4


def test_refresh(mocker: MockerFixture):
    from yara_registry.registry import Corpus

    corpus = Corpus()
    assert corpus
    spy = mocker.spy(metadata, "entry_points")
    corpus.register_rules()
    assert spy.call_count == 0
    corpus.refresh()
    assert spy.call_count == 1


def test_source_conflict(mocker: MockerFixture):
    from yara_registry.yara_x import YaraXSource

    with tempfile.TemporaryDirectory() as dir, open(
        Path(dir, "test1.yara"), "w"
    ) as f1, open(Path(dir, "test2.yara"), "w") as f2:
        f1.write("rule test_str \n{\n\tcondition:\n\ttrue}")
        f2.write("rule test_str \n{\n\tcondition:\n\ttrue}")
        spy = mocker.patch("yara_x.Compiler.add_source")
        source = YaraXSource(dir, Path(dir))
        source._yara_x_compiler
        assert spy.call_count == 2


def test_source_match(mocker: MockerFixture):
    from yara_registry.yara import YaraCorpus

    corpus = YaraCorpus()

    spy = mocker.patch("yara_registry.utils.match")
    source = corpus.get_source("yara_registry_sample")
    source.match(file_bytes=b"")
    assert spy.call_count == 1


def test_source_match_x(mocker: MockerFixture):
    from yara_registry.yara_x import YaraXCorpus

    corpus = YaraXCorpus()

    registry_spy = mocker.patch("yara_registry.utils.match_x")
    yara_x_spy = mocker.patch("yara_x.Compiler.define_global")
    source = corpus.get_source("yara_registry_sample")
    matches = source.match(file_bytes=b"")
    assert registry_spy.call_count == 1
    source.match(file_bytes=b"", externals={"key1": "value1", "key2": "value2"})
    assert registry_spy.call_count == 2
    assert yara_x_spy.call_count == 2


def test_corpus_match(mocker: MockerFixture):
    from yara_registry.yara import YaraCorpus

    corpus = YaraCorpus()

    spy = mocker.patch("yara_registry.utils.match")
    corpus.match(file_bytes=b"")
    assert spy.call_count == 1


def test_corpus_match_x(mocker: MockerFixture):
    from yara_registry.yara_x import YaraXCorpus

    corpus = YaraXCorpus()

    registry_spy = mocker.patch("yara_registry.utils.match_x")
    yara_x_spy = mocker.patch("yara_x.Compiler.define_global")
    corpus.match(file_bytes=b"")
    assert registry_spy.call_count == 1
    corpus.match(file_bytes=b"", externals={"key1": "value1", "key2": "value2"})
    assert registry_spy.call_count == 2
    assert yara_x_spy.call_count == 2
