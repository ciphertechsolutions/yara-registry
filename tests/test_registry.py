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
    import yara_registry

    corpus = yara_registry.corpus
    assert len(corpus) == 1


def test_rule():
    from yara_registry.registry import corpus

    for rule in corpus["yara_registry_sample"].rules:
        assert rule.yara_compatible
        assert rule.yara_x_compatible
        assert rule.name in ["test_1.yara", "test_2.yara", "test_3.yara", "test_4.yara"]


def test_rule_invalid():
    from yara_registry.registry import Rule

    name = "test_registry.py"
    rule = Rule(Path(f"./{name}"))
    print(rule)
    assert rule.name == name
    assert not rule.yara_compatible
    assert not rule.yara_x_compatible
    assert repr(rule) == f"Rule file at {name}"


def test_source_from_file():
    from yara_registry.registry import Source

    with tempfile.TemporaryDirectory() as dir, open(Path(dir, "test.yara"), "w") as f:
        f.write("rule test_str \n{\n\tcondition:\n\ttrue}")
        source = Source("test", Path(dir, "test.yara"))
        assert source
        assert len(source.rules) == 1
        assert str(source) == f"Package test: 1 rules from {Path(dir, 'test.yara')}"
        assert (
            repr(source)
            == f"Package test: 1 rules from {Path(dir, 'test.yara')}: [test.yara]"
        )
        assert len(source._yara_compatible_rules) == 1
        assert len(source._yara_x_compatible_rules) == 1
        assert source.yara_rules
        assert source.yara_x_rules


def test_corpus_rules():
    from yara_registry import corpus

    assert len(corpus._yara_compatible_rules) == 4
    assert len(corpus._yara_x_compatible_rules) == 4


def test_functions():
    from yara_registry import registry

    assert registry.get_source("yara_registry_sample")
    assert len([rule for rule in registry.get_all_yara_rules_compiled()]) == 4
    assert len([rule for rule in registry.get_all_yara_x_rules_compiled()]) == 4
    assert len(registry.get_all_yara_rules()) == 4
    assert len(registry.get_all_yara_x_rules()) == 4
    assert len(registry.get_all_yara_rule_paths()) == 4
    assert len(registry.get_all_yara_x_rule_paths()) == 4


def test_refresh(mocker: MockerFixture):
    from yara_registry import registry

    assert registry.corpus
    spy = mocker.spy(metadata, "entry_points")
    registry.register_rules(refresh=False)
    assert spy.call_count == 0
    registry.register_rules(refresh=True)
    assert spy.call_count == 1


def test_source_conflict(mocker: MockerFixture):
    from yara_registry.registry import Source

    with tempfile.TemporaryDirectory() as dir, open(
        Path(dir, "test1.yara"), "w"
    ) as f1, open(Path(dir, "test2.yara"), "w") as f2:
        f1.write("rule test_str \n{\n\tcondition:\n\ttrue}")
        f2.write("rule test_str \n{\n\tcondition:\n\ttrue}")
        spy = mocker.patch("yara_x.Compiler.add_source")
        source = Source(dir, Path(dir))
        source._yara_x_compiler
        assert spy.call_count == 2


def test_source_match(mocker: MockerFixture):
    from yara_registry import registry

    spy = mocker.patch("yara_registry.utils.match")
    source = registry.get_source("yara_registry_sample")
    source.match(file_bytes=b"")
    assert spy.call_count == 1


def test_source_match_x(mocker: MockerFixture):
    from yara_registry import registry

    registry_spy = mocker.patch("yara_registry.utils.match_x")
    yara_x_spy = mocker.patch("yara_x.Compiler.define_global")
    source = registry.get_source("yara_registry_sample")
    source.match_x(file_bytes=b"")
    assert registry_spy.call_count == 1
    source.match_x(file_bytes=b"", externals={"key1": "value1", "key2": "value2"})
    assert registry_spy.call_count == 2
    assert yara_x_spy.call_count == 2


def test_corpus_match(mocker: MockerFixture):
    from yara_registry import corpus

    spy = mocker.patch("yara_registry.utils.match")
    corpus.match(file_bytes=b"")
    assert spy.call_count == 1


def test_corpus_match_x(mocker: MockerFixture):
    from yara_registry import corpus

    registry_spy = mocker.patch("yara_registry.utils.match_x")
    yara_x_spy = mocker.patch("yara_x.Compiler.define_global")
    corpus.match_x(file_bytes=b"")
    assert registry_spy.call_count == 1
    corpus.match_x(file_bytes=b"", externals={"key1": "value1", "key2": "value2"})
    assert registry_spy.call_count == 2
    assert yara_x_spy.call_count == 2


def test_match(mocker: MockerFixture):
    from yara_registry import match

    spy = mocker.patch("yara_registry.utils.match")
    match(file_bytes=b"")
    assert spy.call_count == 1


def test_match_x(mocker: MockerFixture):
    from yara_registry import match_x

    spy = mocker.patch("yara_registry.utils.match_x")
    match_x(file_bytes=b"")
    assert spy.call_count == 1
