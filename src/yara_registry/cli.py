""" Collection of CLI commands for interacting with the registry
"""
import shutil
from pathlib import Path

import click
import platformdirs

from yara_registry.registry import Corpus


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main():
    """Collection of CLI commands for interacting with the registry"""


@main.command(
    help="""Add new yara files not contained in a python package. \
    Files are added to the users data directory, \
    so ensure this command is run by the correct user."""
)
@click.option(
    "--namespace",
    required=True,
    type=str,
    help="Scope of rules, this should be considered equivalent to python package name, \
    so ensure it does not conflict \
    ('-', and '_' are considered interchangeable in package naming.)",
)
@click.option(
    "--path",
    required=True,
    type=click.Path(
        exists=True,
        dir_okay=True,
        file_okay=True,
        readable=True,
        path_type=Path,
    ),
    help="Path to directory containing rules, files must end in '.yar' or '.yara'",
)
def add(namespace: str, path: Path):
    """ Add rules from an external source to a location where the registry can find them.
    :param namespace: Namespace to place rule(s) in. \
        Should not conflict with a python package that also contains rules.
    :type namespace: str
    :param path: Description
    :type path: Path
    """
    data_dir = Path(platformdirs.user_data_dir("yara_registry", appauthor=False))
    click.echo(f"Installing rules to {data_dir}")
    rules_namespace_path = data_dir / "rules" / namespace
    shutil.copytree(path, rules_namespace_path, dirs_exist_ok=True)


@main.command(help="""List registered yara files.""", name="list")
@click.option("--source", required=False, type=str)
def _list(source: str = None):
    corpus = Corpus()
    if source:
        click.echo(corpus[source])
        return 0
    for item in corpus.items():
        click.echo(item)
    return 0
