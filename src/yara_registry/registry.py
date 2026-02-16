""" Registry of yara rules from various sources with utilities \
    to register sources and work with rules across multiple sources
"""

import logging
from dataclasses import dataclass, field
from functools import cached_property
from importlib import metadata
from pathlib import Path

import platformdirs
import yara
import yara_x

from yara_registry import utils

logger = logging.getLogger(__name__)

YARA_EXTENSIONS = [".yara", ".yar"]


@dataclass
class Rule:
    """Represents a yara rule file"""

    path: Path
    yara_compatible: bool = False
    yara_x_compatible: bool = False

    def __post_init__(self):
        try:
            yara.compile(str(self.path))
        except yara.Error as e:
            logger.warning("Invalid yara rule %s: %s", self.name, e)
        else:
            self.yara_compatible = True
        try:  # pylint: disable=too-many-try-statements
            with open(str(self.path), encoding="utf-8") as f:
                rule_text = f.read()
                yara_x.compile(rule_text)
                self.yara_x_compatible = True
        except (yara_x.CompileError, OSError) as e:
            logger.warning("Invalid yara_x rule %s: %s", self.name, e)

    @cached_property
    def name(self) -> str:
        """Name of the file
        :return: Name of the file
        :rtype: str
        """
        return self.path.name

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"Rule file at {self.path}"


@dataclass
class Source:
    """Represents a source of yara rules in to one easy to use interface.
    Sources should be a either a python packages or a directory in the users data directory.
    """

    name: str
    rules: list[Rule] = field(default_factory=list, init=False)
    path: Path

    def __post_init__(self):
        if not self.path.is_dir():
            if self.path.suffix in YARA_EXTENSIONS:
                self.rules.append(Rule(self.path))
        else:
            for file in self.path.rglob("*"):
                if file.suffix not in YARA_EXTENSIONS:
                    continue
                self.rules.append(Rule(file))

    def __str__(self):
        return f"Package {self.name}: {len(self.rules)} rules from {self.path}"

    def __repr__(self):
        return f"{self.__str__()}: [{', '.join([str(rule) for rule in self.rules])}]"

    @cached_property
    def yara_compatible_rules(self) -> list[Rule]:
        """Get list of all yara rules from this Source
        :return: List of all yara rules from this Source
        :rtype: list[Rule]
        """
        return [rule for rule in self.rules if rule.yara_compatible]

    @cached_property
    def yara_rules(self) -> yara.Rules:
        """Get list of all yara rules from this Source.
        :return: List of all yara rules from this Source
        :rtype: yara.Rules
        """
        yara_compatible_rules = {
            rule.name: str(rule.path) for rule in self.yara_compatible_rules
        }
        return yara.compile(filepaths=yara_compatible_rules)

    @cached_property
    def yara_x_compatible_rules(self) -> list[Rule]:
        """Get list of all yara_x rules from this Source.
        :return: List of all yara_x rules in the corpus
        :rtype: list[Rule]
        """
        return [rule for rule in self.rules if rule.yara_x_compatible]

    @cached_property
    def _yara_x_compiler(self) -> yara_x.Compiler:
        rules = {rule.name: str(rule.path) for rule in self.yara_x_compatible_rules}
        compiler = yara_x.Compiler()
        for namespace, path in rules.items():
            with open(path, encoding="utf-8") as file:
                content = file.read()
                compiler.new_namespace(namespace)
                compiler.add_source(content)
        return compiler

    @cached_property
    def yara_x_rules(self) -> yara_x.Rules:
        """All yara_x rules from this source compiled by yara_x.
        :return: All yara_x rules from this source compiled by yara_x
        :rtype: yara_x.Rules
        """
        return self._yara_x_compiler.build()

    def match_x(
        self, file_path: Path = None, file_bytes: bytes = None, externals: dict = None
    ) -> yara_x.ScanResults:
        """Match input against registered yara_x rules from this Source.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: External variables to pass to yara_x
        :type externals: dict
        :return: Results of scan that matches on the provided input
        :rtype: ScanResults
        """
        if externals:
            compiler = self._yara_x_compiler
            for key, value in externals.items():
                compiler.define_global(key, value)
            rules = compiler.build()
        else:
            rules = self.yara_x_rules
        return utils.match_x(rules, file_path=file_path, file_bytes=file_bytes)

    def match(
        self, file_path: Path = None, file_bytes: bytes = None, externals: dict = None
    ):
        """Match yara rules against provided input using yara.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: Dictionary of external values to pass to rules.match()
        :type externals: dict
        :return: List of rules that matches on the provided input
        :rtype: list[yara.Match]
        """
        return utils.match(
            self.yara_rules,
            file_path=file_path,
            file_bytes=file_bytes,
            externals=externals,
        )


class Corpus(dict[str, Source]):
    """A dictionary that combines multiple sources of yara rules in to one easy to use interface."""

    @cached_property
    def yara_compatible_rules(self) -> list[Rule]:
        """Get list of all yara rules in the corpus
        :return: List of all yara rules in the corpus
        :rtype: list[Rule]
        """
        rules = []
        for source in self.values():
            rules.extend(source.yara_compatible_rules)
        return rules

    @cached_property
    def yara_rules(self) -> yara.Rules:
        """All yara rules in corpus compiled by yara.
        :return: All yara rules in corpus compiled by yara
        :rtype: yara.Rules
        """
        rules = {}
        for source in self.values():
            for rule in source.yara_compatible_rules:
                rules[f"{source.name}.{rule.name}"] = str(rule.path)
        return yara.compile(filepaths=rules)

    @cached_property
    def yara_x_compatible_rules(self) -> list[Rule]:
        """Get list of all yara_x rules in the corpus.
        :return: List of all yara_x rules in the corpus
        :rtype: list[Rule]
        """
        rules = []
        for source in self.values():
            rules.extend(source.yara_x_compatible_rules)
        return rules

    @cached_property
    def _yara_x_compiler(self) -> yara_x.Compiler:
        compiler = yara_x.Compiler()
        for source in self.values():
            for rule in source.yara_x_compatible_rules:
                key = f"{source.name}.{rule.name}"
                with rule.path.open() as file:
                    content = file.read()
                    compiler.new_namespace(key)
                    compiler.add_source(content)
        return compiler

    @cached_property
    def yara_x_rules(self) -> yara_x.Rules:
        """All yara_x rules in corpus compiled by yara_x.
        :return: All yara_x rules in corpus compiled by yara_x
        :rtype: yara_x.Rules
        """
        return self._yara_x_compiler.build()

    def match_x(
        self, file_path: Path = None, file_bytes: bytes = None, externals: dict = None
    ) -> yara_x.ScanResults:
        """Match input against all registered yara_x rules.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: External variables to pass to yara_x
        :type externals: dict
        :return: Results of scan that matches on the provided input
        :rtype: ScanResults
        """
        if externals:
            compiler = self._yara_x_compiler
            for key, value in externals.items():
                compiler.define_global(key, value)
            rules = compiler.build()
        else:
            rules = self.yara_x_rules
        return utils.match_x(rules, file_path=file_path, file_bytes=file_bytes)

    def match(
        self, file_path: Path = None, file_bytes: bytes = None, externals: dict = None
    ) -> list[yara.Match]:
        """Match yara rules against provided input using yara.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: Dictionary of external values to pass to rules.match()
        :type externals: dict
        :return: List of rules that matches on the provided input
        :rtype: list[yara.Match]
        """
        return utils.match(
            self.yara_rules,
            file_path=file_path,
            file_bytes=file_bytes,
            externals=externals,
        )


def get_source(name: str) -> Source:
    """Get a yara rules source by name.
    :param name: Name of the python package/installed rules namespace
    :type name: str
    :return: Source with the given name
    :rtype: Source
    """
    for source in corpus.values():
        if name == source.name:
            return source
    return None


def get_all_yara_rules_compiled() -> yara.Rules:
    """Get all yara rules compiled.
    :return: Get all compatible yara rules compiled by yara
    :rtype: yara.Rules
    """
    return corpus.yara_rules


def get_all_yara_rules() -> list[Rule]:
    """Get all registered yara rules.
    :return: list of all yara compatible rules
    :rtype: list[Rule]
    """
    return corpus.yara_compatible_rules


def get_all_yara_rule_paths() -> list[Path]:
    """Get paths to all registered yara rules.
    :return: list of Paths to all yara rules
    :rtype: list[Path]
    """
    return [rule.path for rule in corpus.yara_compatible_rules]


def get_all_yara_x_rules_compiled() -> yara_x.Rules:
    """Get all yara_x rules compiled.
    :return: Get all compatible yara_x rules compiled by yara_x
    :rtype: yara_x.Rules
    """
    return corpus.yara_x_rules


def get_all_yara_x_rules() -> list[Rule]:
    """Get all registered yara_x rules.
    :return: list of all yara_x compatible rules
    :rtype: list[Rule]
    """
    return corpus.yara_x_compatible_rules


def get_all_yara_x_rule_paths() -> list[Path]:
    """Get paths to all registered yara_x rules.
    :return: list of Paths to all yara_x rules
    :rtype: list[Path]
    """
    return [rule.path for rule in corpus.yara_x_compatible_rules]


corpus = Corpus()


def match(
    file_path: Path = None, file_bytes: bytes = None, externals=None
) -> list[yara.Match]:
    """Match yara rules against provided input using yara.
    :param file_path: Path of file to match against, must set this or file_bytes
    :type file_path: Path
    :param file_bytes: bytes content to match against, must set this or file_path
    :type file_bytes: bytes
    :param externals: Dictionary of external values to pass to rules.match()
    :type externals: dict
    :return: List of rules that matches on the provided input
    :rtype: list[yara.Match]
    """
    return corpus.match(file_path=file_path, file_bytes=file_bytes, externals=externals)


def match_x(
    file_path: Path = None, file_bytes: bytes = None, externals: dict = None
) -> yara_x.ScanResults:
    """Match input against all registered yara_x rules.
    :param file_path: Path of file to match against, must set this or file_bytes
    :type file_path: Path
    :param file_bytes: bytes content to match against, must set this or file_path
    :type file_bytes: bytes
    :param externals: External variables to pass to yara_x
    :type externals: dict
    :return: Results of scan that matches on the provided input
    :rtype: ScanResults
    """
    return corpus.match_x(
        file_path=file_path, file_bytes=file_bytes, externals=externals
    )


def register_rules(refresh: bool = False):
    """ Registers rules found in entry_point: "yara_registry.rules" \
        and user data dir as determined by platformdirs.user_data_dir("yara_registry").
    :param refresh: Refresh rules from disk, deletes existing corpus and repopulates with fresh data
    :type refresh: bool
    """
    global corpus  # pylint: disable=global-statement
    if corpus and not refresh:
        return
    corpus = Corpus()
    for entry in metadata.entry_points(group="yara_registry.rules"):
        try:
            package = entry.load()
        except ModuleNotFoundError:
            logger.warning(
                """ModuleNotFountError: No module named %s.
                Ensure the package entry point is registered as:
                    \n[project.entry-points.'yara_registry.rules']
                    \nrules = \"<package_name>.path.to.rules\"""",
                entry.values,
            )
            continue
        package_path = (
            package.__path__[0]
            if isinstance(package.__path__, list)
            else package.__path__._path[0]  # pylint: disable=protected-access
        )
        corpus[package.__package__] = Source(package.__package__, Path(package_path))
    for namespace in [
        path
        for path in Path(platformdirs.user_data_dir("yara_registry", appauthor=False))
        .joinpath("rules")
        .glob("*")
        if path.is_dir()
    ]:
        if namespace.name in corpus:
            logger.warning(
                "Namespace collision between %s and python package %s",
                str(namespace),
                namespace.name,
            )
        corpus[namespace.name] = Source(namespace.name, namespace)


register_rules()
