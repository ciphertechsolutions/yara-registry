from pathlib import Path

from click.testing import CliRunner
from pytest_mock import MockerFixture


def test_add_no_args(mocker: MockerFixture):
    mocker.patch("platformdirs.user_data_dir")
    from yara_registry.cli import add

    runner = CliRunner()
    results = runner.invoke(add, [])
    assert results.exit_code == 2
    assert (
        results.output
        == "Usage: add [OPTIONS]\nTry 'add --help' for help.\n\nError: Missing option '--namespace'.\n"
    )


def test_add(mocker: MockerFixture):
    mocker.patch("platformdirs.user_data_dir")
    from yara_registry.cli import add

    runner = CliRunner()
    spy = mocker.patch("shutil.copytree")
    results = runner.invoke(
        add,
        [
            "--namespace",
            "test",
            "--path",
            Path(__file__).parent / "sample" / "src" / "yara_registry_sample",
        ],
    )
    spy.assert_called_once()
    assert results.exit_code == 0


def test_list(mocker: MockerFixture):
    mocker.patch("platformdirs.user_data_dir")
    from yara_registry.cli import _list

    runner = CliRunner()
    results = runner.invoke(_list, [])
    assert results.exit_code == 0
    assert "yara_registry_sample" in results.output
