""" Registry of yara rules from various sources with utilities \
    to register sources and work with rules across multiple sources
"""

import logging
from dataclasses import dataclass, field
from functools import cached_property
from importlib import metadata
from pathlib import Path

import platformdirs

# pylint: disable=duplicate-code
try:
    import yara
except ImportError:
    YARA_INSTALLED = False
else:
    YARA_INSTALLED = True
try:
    import yara_x
except ImportError:
    YARA_X_INSTALLED = False
else:
    YARA_X_INSTALLED = True

logger = logging.getLogger(__name__)

YARA_EXTENSIONS = [".yara", ".yar"]


@dataclass
class Rule:
    """Represents a yara rule file"""

    path: Path
    yara_compatible: bool = False
    yara_x_compatible: bool = False

    def __post_init__(self):
        self._test_yara_compatibility()
        self._test_yara_x_compatibility()

    def _test_yara_x_compatibility(self):
        if not YARA_X_INSTALLED:
            return
        try:  # pylint: disable=too-many-try-statements
            with open(str(self.path), encoding="utf-8") as f:
                rule_text = f.read()
                yara_x.compile(rule_text)
                self.yara_x_compatible = True
        except (yara_x.CompileError, OSError) as e:
            logger.warning("Invalid yara_x rule %s: %s", self.name, e)

    def _test_yara_compatibility(self):
        if not YARA_INSTALLED:
            return
        try:
            yara.compile(str(self.path))
        except yara.Error as e:
            logger.warning("Invalid yara rule %s: %s", self.name, e)
        else:
            self.yara_compatible = True

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

    def match(
        self,
        file_path: Path = None,
        file_bytes: bytes = None,
        externals: dict = None,
        **kwargs,
    ):
        """Match rules against provided input.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: Dictionary of external values to pass to rules.match()
        :type externals: dict
        :param kwargs: Additional keyword arguments to pass to matching function
        :return: List of rules that matches on the provided input
        """
        raise NotImplementedError(
            "Use YaraSource of YaraXSource to match against rules"
        )

    @cached_property
    def compatible_rules(self) -> list[Rule]:
        """Get list of compatible rules, must be implemented in child class"""
        raise NotImplementedError(
            "Use YaraSource of YaraXSource to get compatible rules"
        )

    @cached_property
    def compiled_rules(self):
        """Get compiled rules, must be implemented in child class"""
        raise NotImplementedError("Use YaraSource of YaraXSource to get compiled rules")

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


class Corpus(dict[str, Source]):
    """A dictionary that combines multiple sources of yara rules in to one easy to use interface."""

    SourceType = Source

    def __init__(self):
        self.register_rules()

    @cached_property
    def compatible_rules(self) -> list[Rule]:
        """Get list of all compatible rules in the corpus.
        :return: List of all compatible rules in the corpus
        :rtype: list[Rule]
        """
        rules = []
        for source in self.values():
            rules.extend(source.compatible_rules)
        return rules

    @cached_property
    def compiled_rules(self):
        """Get compiled rules, must be implemented in child class"""
        raise NotImplementedError("Use YaraCorpus of YaraXCorpus to get compiled rules")

    def get_source(self, name: str) -> Source | None:
        """Get a rules source by name.
        :param name: Name of the python package/installed rules namespace
        :type name: str
        :return: Source with the given name
        :rtype: Source
        """
        return self.get(name, None)

    def get_all_rules_compiled(self):
        """Get all rules compiled.
        :return: Get all compatible rules compiled by engine
        :rtype: yara.Rules
        """
        return self.compiled_rules

    def get_all_rule_paths(self) -> list[Path]:
        """Get paths to all registered yara rules.
        :return: list of Paths to all yara rules
        :rtype: list[Path]
        """
        return [rule.path for rule in self.compatible_rules]

    def match(
        self,
        file_path: Path = None,
        file_bytes: bytes = None,
        externals: dict = None,
        **kwargs,
    ):
        """Match rules against provided input.  Must be implemented by child class.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: Dictionary of external values to pass to rules.match()
        :type externals: dict
        :param kwargs: Additional keyword arguments to pass to matching function
        """
        raise NotImplementedError(
            "Use YaraCorpus of YaraXCorpus to get match against rules"
        )

    def register_rules(self):
        """ Registers rules found in entry_point: "yara_registry.rules" \
            and user data dir as determined by platformdirs.user_data_dir("yara_registry").
        """
        if len(self) != 0:
            return
        self.clear()
        for entry in metadata.entry_points(group="yara_registry.rules"):
            logger.debug("Processing %s", entry)
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
            self[package.__package__] = self.SourceType(
                package.__package__, Path(package_path)
            )
        for namespace in [
            path
            for path in Path(
                platformdirs.user_data_dir("yara_registry", appauthor=False)
            )
            .joinpath("rules")
            .glob("*")
            if path.is_dir()
        ]:
            if namespace.name in self:
                logger.warning(
                    "Namespace collision between %s and python package %s",
                    str(namespace),
                    namespace.name,
                )
            self[namespace.name] = self.SourceType(namespace.name, namespace)

    def refresh(self):
        """Refresh corpus rules.  Deletes existing rules and reprocesses registered sources."""
        self.clear()
        self.register_rules()
