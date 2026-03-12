""" Yara-x implementation of registry classes """

from functools import cached_property
from pathlib import Path

import yara_x

from yara_registry import utils
from yara_registry.registry import Corpus, Rule, Source


class YaraXSource(Source):
    """Yara-x Implementation of Source class"""

    @cached_property
    def compatible_rules(self) -> list[Rule]:
        """Get list of all yara_x rules from this Source.
        :return: List of all yara_x rules in the corpus
        :rtype: list[Rule]
        """
        return [rule for rule in self.rules if rule.yara_x_compatible]

    @cached_property
    @utils.yara_x_required
    def _yara_x_compiler(self) -> yara_x.Compiler:
        return self._new_yara_x_compiler()

    def _new_yara_x_compiler(self, compiler: yara_x.Compiler = None) -> yara_x.Compiler:
        rules = {rule.name: str(rule.path) for rule in self.compatible_rules}
        if not compiler:
            compiler = yara_x.Compiler()
        for namespace, path in rules.items():
            with open(path, encoding="utf-8") as file:
                content = file.read()
                compiler.new_namespace(namespace)
                compiler.add_source(content)
        return compiler

    @cached_property
    @utils.yara_x_required
    def compiled_rules(self) -> yara_x.Rules:
        """All yara_x rules from this source compiled by yara_x.
        :return: All yara_x rules from this source compiled by yara_x
        :rtype: yara_x.Rules
        """
        return self._yara_x_compiler.build()

    @utils.yara_x_required
    def match(
        self,
        file_path: Path = None,
        file_bytes: bytes = None,
        externals: dict = None,
        **kwargs,
    ) -> yara_x.ScanResults:
        """Match input against registered yara_x rules from this Source.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: External variables to pass to yara_x
        :type externals: dict
        :param kwargs: Additional keyword arguments to pass to matching function
        :return: Results of scan that matches on the provided input
        :rtype: ScanResults
        """
        if externals:
            # Yara-x requires defining globals before adding sources, so we must recreate each time
            # https://virustotal.github.io/yara-x/docs/api/python/#define_globalidentifier-value
            compiler = yara_x.Compiler()
            for key, value in externals.items():
                compiler.define_global(key, value)
            compiler = self._new_yara_x_compiler(compiler)
            rules = compiler.build()
        else:
            rules = self.compiled_rules
        return utils.match_x(rules, file_path=file_path, file_bytes=file_bytes)


class YaraXCorpus(Corpus[str, YaraXSource]):
    """Yara-x implementation of Corpus"""

    SourceType = YaraXSource

    @cached_property
    @utils.yara_x_required
    def _yara_x_compiler(self) -> "yara_x.Compiler":
        return self._new_yara_x_compiler()

    def _new_yara_x_compiler(
        self, compiler: "yara_x.Compiler" = None
    ) -> "yara_x.Compiler":
        if not compiler:
            compiler = yara_x.Compiler()
        for source in self.values():
            for rule in source.compatible_rules:
                key = f"{source.name}.{rule.name}"
                with rule.path.open() as file:
                    content = file.read()
                    compiler.new_namespace(key)
                    compiler.add_source(content)
        return compiler

    @cached_property
    @utils.yara_x_required
    def compiled_rules(self) -> yara_x.Rules:
        """All yara_x rules in corpus compiled by yara_x.
        :return: All yara_x rules in corpus compiled by yara_x
        :rtype: yara_x.Rules
        """
        return self._yara_x_compiler.build()

    @utils.yara_x_required
    def match(
        self,
        file_path: Path = None,
        file_bytes: bytes = None,
        externals: dict = None,
        **kwargs,
    ) -> yara_x.ScanResults:
        """Match input against all registered yara_x rules.
        :param file_path: Path of file to match against, must set this or file_bytes
        :type file_path: Path
        :param file_bytes: bytes content to match against, must set this or file_path
        :type file_bytes: bytes
        :param externals: External variables to pass to yara_x
        :type externals: dict
        :param kwargs: Additional keyword arguments to pass to matching function
        :return: Results of scan that matches on the provided input
        :rtype: ScanResults
        """
        if externals:
            # Yara-x requires defining globals before adding sources, so we must recreate each time
            # https://virustotal.github.io/yara-x/docs/api/python/#define_globalidentifier-value
            compiler = yara_x.Compiler()
            for key, value in externals.items():
                compiler.define_global(key, value)
            compiler = self._new_yara_x_compiler(compiler)
            rules = compiler.build()
        else:
            rules = self.compiled_rules
        return utils.match_x(
            rules, file_path=file_path, file_bytes=file_bytes, **kwargs
        )
