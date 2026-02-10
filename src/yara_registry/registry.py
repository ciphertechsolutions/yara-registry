from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Dict, List
import pkg_resources
import logging

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
        if yara:
            yara.compile(str(self.path))
            self.yara_compatible = True
        if yara_x:
            with open(str(self.path), 'r') as f:
                rule_text = f.read()
                yara_x.compile(rule_text)
                self.yara_x_compatible = True

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
    rules: List[Rule] = field(default_factory=list, init=False)
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
        return "{0}: [{1}]".format(self.__str__(), ', '.join([str(rule) for rule in self.rules]))
    
    @cached_property
    def _yara_compatible_rules(self) -> List[Rule]:
        return [rule for rule in self.rules if rule.yara_compatible]

    @cached_property
    def yara_rules(self) -> yara.Rules:
        if not yara:
            return []
        yara_compatible_rules = {rule.name: str(rule.path) for rule in self._yara_compatible_rules}
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
            try:
                compiler.add_source(content)
            except yara_x.CompileError:
                logger.warning(f"Source Rule namespace conflict for {namespace}:{path}")
                compiler.new_namespace(namespace)
                compiler.add_source(content)
        return compiler

    @cached_property
    def yara_x_rules(self) -> yara_x.Rules:
        return self._yara_x_compiler.build()
    
    def match_x(self, file_path: Path = None, file_bytes: bytes = None, exception: bool = False, externals = {}) -> yara_x.ScanResults:
        if externals:
            compiler = self._yara_x_compiler
            for key, value in externals:
                compiler.define_global(key, value)
            rules = compiler.build()
        else:
            rules = self.yara_x_rules
        return utils.match_x(rules, file_path=file_path, file_bytes=file_bytes, exception=exception)

    def match(self, file_path: Path = None, file_bytes: bytes = None, exception: bool = False, externals = {}):
        return utils.match(self.yara_rules, file_path=file_path, file_bytes=file_bytes, exception=exception, externals=externals)

class Corpus(Dict[str, Source]):
    @cached_property
    def _yara_compatible_rules(self) -> List[Rule]:
        rules = []
        for source in self.values():
            rules.extend(source._yara_compatible_rules)
        return rules

    @cached_property
    def yara_rules(self) -> yara.Rules:
        rules = {}
        for source in self.values():
            for rule in source._yara_compatible_rules:
                key = f"{source.name}.{rule.name}"
                if key in rules:
                    logger.warning(f"Rule namespace conflict for {key}, will be overwritten")
                rules[key] = str(rule.path)
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

    def match_x(self, file_path: Path = None, file_bytes: bytes = None, exception: bool = False, externals = {}) -> yara_x.ScanResults:
        if externals:
            compiler = self._yara_x_compiler
            for key, value in externals:
                compiler.define_global(key, value)
            rules = compiler.build()
        else:
            rules = self.yara_x_rules
        return utils.match_x(rules, file_path=file_path, file_bytes=file_bytes, exception=exception)
    
    def match(self, file_path: Path = None, file_bytes: bytes = None, exception: bool = False, externals = {}) -> List[yara.Match]:
        return utils.match(self.yara_rules, file_path=file_path, file_bytes=file_bytes, exception=exception, externals=externals)

def get_source(name: str) -> Source:
    for source in corpus.values():
        if name == source.name:
            return source
        
def get_all_yara_rules_compiled() -> yara.Rules:
    return corpus.yara_rules

def get_all_yara_rules() -> List[Rule]:
    return corpus._yara_compatible_rules

def get_all_yara_rule_paths() -> List[Path]:
    return [rule.path for rule in corpus._yara_compatible_rules]

def get_all_yara_x_rules_compiled() -> yara_x.Rules:
    return corpus.yara_x_rules

def get_all_yara_x_rules() -> List[Rule]:
    return corpus._yara_x_compatible_rules

def get_all_yara_x_rule_paths() -> List[Path]:
    return [rule.path for rule in corpus._yara_x_compatible_rules]

corpus = Corpus()

def match(file_path: Path = None, file_bytes: bytes = None, exception: bool = False, externals = {}) -> List[yara.Match]:
    return corpus.match(file_path=file_path, file_bytes=file_bytes, exception=exception, externals=externals)

def match_x(file_path: Path = None, file_bytes: bytes = None, exception: bool = False, externals = {}) -> yara_x.ScanResults:
    return corpus.match_x(file_path=file_path, file_bytes=file_bytes, exception=exception, externals=externals)

def register_rules():
    """
    Registers rules found in entry_point: "yara_registry.rules" and user data dir as determined by platformdirs.user_data_dir("yara_registry")
    :return:
    """
    if corpus:
        return
    for entry in pkg_resources.iter_entry_points("yara_registry.rules"):
        package = entry.load()
        corpus[package.__package__] = Source(package.__package__, Path(package.__path__._path[0]))
    for namespace in [path for path in Path(platformdirs.user_data_dir("yara_registry", appauthor=False)).joinpath("rules").glob("*") if path.is_dir()]:
        if namespace.name in corpus:
            logger.warning(f"Namespace collision between {str(namespace)} and python package {namespace.name}")
        corpus[namespace.name] = Source(namespace.name, namespace)
    
        
register_rules()