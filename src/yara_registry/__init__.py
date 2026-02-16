""" Expose high level yara_registry features most applicable to users
"""
from yara_registry.registry import corpus, match, match_x  # noqa

rules = corpus.yara_rules
rules_x = corpus.yara_x_rules
