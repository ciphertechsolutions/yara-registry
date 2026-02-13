import logging
from dataclasses import dataclass, field
from functools import cached_property
from importlib import metadata
from pathlib import Path

import platformdirs

from yara_registry import utils

logger = logging.getLogger(__name__)

import yara
import yara_x

YARA_EXTENSIONS = [".yara", ".yar"]


@dataclass
class Rule:
    path: Path
    yara_compatible: bool = False
    yara_x_compatible: bool = False

    def __post_init__(self):
        try:
            yara.compile(str(self.path))
            self.yara_compatible = True
        except Exception as e:
            logger.warning(f"Invalid rule {self.name}: {e}")
        try:
            with open(str(self.path)) as f:
                rule_text = f.read()
                yara_x.compile(rule_text)
                self.yara_x_compatible = True
        except Exception as e:
            logger.warning(f"Invalid rule {self.name}: {e}")

    @cached_property
    def name(self) -> str:
        return self.path.name

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"Rule file at {self.path}"


@dataclass
class Source:
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
        return "{}: [{}]".format(
            self.__str__(), ", ".join([str(rule) for rule in self.rules])
        )

    @cached_property
    def _yara_compatible_rules(self) -> list[Rule]:
        return [rule for rule in self.rules if rule.yara_compatible]

    @cached_property
    def yara_rules(self) -> yara.Rules:
        yara_compatible_rules = {
            rule.name: str(rule.path) for rule in self._yara_compatible_rules
        }
        return yara.compile(filepaths=yara_compatible_rules)

    @cached_property
    def _yara_x_compatible_rules(self):
        return [rule for rule in self.rules if rule.yara_x_compatible]

    @cached_property
    def _yara_x_compiler(self) -> yara_x.Compiler:
        rules = {rule.name: str(rule.path) for rule in self._yara_x_compatible_rules}
        compiler = yara_x.Compiler()
        for namespace, path in rules.items():
            with open(path) as file:
                content = file.read()
                compiler.add_source(content)
        return compiler

    @cached_property
    def yara_x_rules(self) -> yara_x.Rules:
        return self._yara_x_compiler.build()

    def match_x(
        self, file_path: Path = None, file_bytes: bytes = None, externals={}
    ) -> yara_x.ScanResults:
        if externals:
            compiler = self._yara_x_compiler
            for key, value in externals.items():
                compiler.define_global(key, value)
            rules = compiler.build()
        else:
            rules = self.yara_x_rules
        return utils.match_x(rules, file_path=file_path, file_bytes=file_bytes)

    def match(self, file_path: Path = None, file_bytes: bytes = None, externals={}):
        return utils.match(
            self.yara_rules,
            file_path=file_path,
            file_bytes=file_bytes,
            externals=externals,
        )


class Corpus(dict[str, Source]):
    @cached_property
    def _yara_compatible_rules(self) -> list[Rule]:
        rules = []
        for source in self.values():
            rules.extend(source._yara_compatible_rules)
        return rules

    @cached_property
    def yara_rules(self) -> yara.Rules:
        rules = {}
        for source in self.values():
            for rule in source._yara_compatible_rules:
                rules[f"{source.name}.{rule.name}"] = str(rule.path)
        return yara.compile(filepaths=rules)

    @cached_property
    def _yara_x_compatible_rules(self):
        rules = []
        for source in self.values():
            rules.extend(source._yara_x_compatible_rules)
        return rules

    @cached_property
    def _yara_x_compiler(self) -> yara_x.Compiler:
        compiler = yara_x.Compiler()
        for source in self.values():
            for rule in source._yara_x_compatible_rules:
                key = f"{source.name}.{rule.name}"
                with rule.path.open() as file:
                    content = file.read()
                    compiler.new_namespace(key)
                    compiler.add_source(content)
        return compiler

    @cached_property
    def yara_x_rules(self) -> yara_x.Rules:
        return self._yara_x_compiler.build()

    def match_x(
        self, file_path: Path = None, file_bytes: bytes = None, externals={}
    ) -> yara_x.ScanResults:
        if externals:
            compiler = self._yara_x_compiler
            for key, value in externals.items():
                compiler.define_global(key, value)
            rules = compiler.build()
        else:
            rules = self.yara_x_rules
        return utils.match_x(rules, file_path=file_path, file_bytes=file_bytes)

    def match(
        self, file_path: Path = None, file_bytes: bytes = None, externals={}
    ) -> list[yara.Match]:
        return utils.match(
            self.yara_rules,
            file_path=file_path,
            file_bytes=file_bytes,
            externals=externals,
        )


def get_source(name: str) -> Source:
    for source in corpus.values():
        if name == source.name:
            return source


def get_all_yara_rules_compiled() -> yara.Rules:
    return corpus.yara_rules


def get_all_yara_rules() -> list[Rule]:
    return corpus._yara_compatible_rules


def get_all_yara_rule_paths() -> list[Path]:
    return [rule.path for rule in corpus._yara_compatible_rules]


def get_all_yara_x_rules_compiled() -> yara_x.Rules:
    return corpus.yara_x_rules


def get_all_yara_x_rules() -> list[Rule]:
    return corpus._yara_x_compatible_rules


def get_all_yara_x_rule_paths() -> list[Path]:
    return [rule.path for rule in corpus._yara_x_compatible_rules]


corpus = Corpus()


def match(
    file_path: Path = None, file_bytes: bytes = None, externals={}
) -> list[yara.Match]:
    return corpus.match(file_path=file_path, file_bytes=file_bytes, externals=externals)


def match_x(
    file_path: Path = None, file_bytes: bytes = None, externals={}
) -> yara_x.ScanResults:
    return corpus.match_x(
        file_path=file_path, file_bytes=file_bytes, externals=externals
    )


def register_rules(refresh=False):
    """
    Registers rules found in entry_point: "yara_registry.rules" and user data dir as determined by platformdirs.user_data_dir("yara_registry")
    :return:
    """
    global corpus
    if corpus and not refresh:
        return
    corpus = Corpus()
    for entry in metadata.entry_points(group="yara_registry.rules"):
        try:
            package = entry.load()
        except ModuleNotFoundError:
            logger.warning(
                f"ModuleNotFountError: No module named {entry.value}.  Ensure the package entry point is registered as: \n[project.entry-points.'yara_registry.rules']\nrules = \"<package_name>.path.to.rules\""
            )
            continue
        if isinstance(package.__path__, list):
            package_path = package.__path__[0]
        else:
            package_path = package.__path__._path[0]
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
                f"Namespace collision between {str(namespace)} and python package {namespace.name}"
            )
        corpus[namespace.name] = Source(namespace.name, namespace)


register_rules()
