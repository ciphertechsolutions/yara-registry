from pathlib import Path
import shutil

import click
import platformdirs

import yara_registry

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main():
    pass

@main.command(
    help="""Add new yara files not contained in a python package"""
)
@click.option(
    "--namespace",
    required=True,
    type=str,
    help="Scope of rules, this should be considered equivalent to python package name, so ensure it does not conflict ('-', and '_' are considered interchangeable in package naming.)",
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
    data_dir = Path(platformdirs.user_data_dir("yara_registry", appauthor=False))
    click.echo(f"Installing rules to {data_dir}")
    rules_namespace_path = data_dir / "rules" / namespace
    shutil.copytree(path, rules_namespace_path, dirs_exist_ok=True)

@main.command(
    help="""Add new yara files not contained in a python package""",
    name="list"
)
def _list():
    for source in yara_registry.corpus.items():
        click.echo(source)
