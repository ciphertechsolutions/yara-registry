""" Yara implementation of registry classes """

from functools import cached_property
from pathlib import Path

import yara

from yara_registry import utils
from yara_registry.registry import Corpus, Rule, Source


class YaraSource(Source):
    """Yara implementation of Source class"""

    @cached_property
    def compatible_rules(self) -> list[Rule]:
        """Get list of all yara rules from this Source
        :return: List of all yara rules from this Source
        :rtype: list[Rule]
        """
        return [rule for rule in self.rules if rule.yara_compatible]

    @cached_property
    @utils.yara_required
    def compiled_rules(self) -> yara.Rules:
        """Get list of all yara rules from this Source.
        :return: List of all yara rules from this Source
        :rtype: yara.Rules
        """
        yara_compatible_rules = {
            rule.name: str(rule.path) for rule in self.compatible_rules
        }
        return yara.compile(filepaths=yara_compatible_rules)

    def match(
        self,
        file_path: Path = None,
        file_bytes: bytes = None,
        externals: dict = None,
        **kwargs,
    ) -> list[yara.Match]:
        """Match yara rules against provided input using yara.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: Dictionary of external values to pass to rules.match()
        :type externals: dict
        :param kwargs: Additional keyword arguments to pass to matching function
        :return: List of rules that matches on the provided input
        :rtype: list[yara.Match]
        """
        return utils.match(
            self.rules,
            file_path=file_path,
            file_bytes=file_bytes,
            externals=externals,
        )


class YaraCorpus(Corpus[str, YaraSource]):
    """Yara implementation of Corpus class"""

    SourceType = YaraSource

    @cached_property
    @utils.yara_required
    def compiled_rules(self) -> yara.Rules:
        """All yara rules in corpus compiled by yara.
        :return: All yara rules in corpus compiled by yara
        :rtype: yara.Rules
        """
        rules = {}
        for source in self.values():
            for rule in source.compatible_rules:
                rules[f"{source.name}.{rule.name}"] = str(rule.path)
        return yara.compile(filepaths=rules)

    @utils.yara_required
    def match(
        self,
        file_path: Path = None,
        file_bytes: bytes = None,
        externals: dict = None,
        **kwargs,
    ) -> list[yara.Match]:
        """Match yara rules against provided input using yara.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: Dictionary of external values to pass to rules.match()
        :type externals: dict
        :param kwargs: Additional keyword arguments to pass to matching function
        :return: List of rules that matches on the provided input
        :rtype: list[yara.Match]
        """
        return utils.match(
            self.compiled_rules,
            file_path=file_path,
            file_bytes=file_bytes,
            externals=externals,
        )
