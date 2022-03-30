import re

from pygments.lexer import (ExtendedRegexLexer, RegexLexer, bygroups, combined,
                            default, include, this, using, words)
from pygments.token import *
from pygments.token import (Comment, Keyword, Name, Number, Operator,
                            Punctuation, String, Text, Whitespace)

from netfoundry.utility import DC_PROVIDERS, RESOURCE_STATUSES


class NetFoundryTableLexer(RegexLexer):
    """Parse NF CLI nfctl table output for highlighting."""

    name = 'nfctl-table'
    aliases = []
    filenames = ['*.nfctl']
    _var = r'("(?:\\"|[^"])*")'
    tokens = {
        'root': [
            (r'\bERROR\b', Error),
            (r'\b[0-9]+\.[0-9]+\.[0-9]+', Number),
            (r'\b(([a-z]+)?([A-Z][\w])+)\b', String), # camel words
            (r'\b([A-Za-z0-9]+-?)+\b', String), # kebab words
            (r'\b[0-9]+\b', Number.Integer),
            (r'\b([a-zA-Z0-9]{9,12})\b', String.Other),  # zitiId
            (r'\b('+r'|'.join(RESOURCE_STATUSES)+r')\b', Operator.Word),
            (r'\b('+r'|'.join(DC_PROVIDERS)+r')\b', Generic.Output),
            (r'^\s+\|', Keyword, 'heading'), # push to heading context
            (r'(\+|-{3,}|\|)', Keyword), # borders
            # Names
            (r'\*', Name.Builtin),
            (_var, Name.Variable),
            # Other
            (r'\[', Punctuation, 'attrs'),
            (r'\{|\}|,|;', Punctuation),
        ],
        'heading': [
            (r'\b([\w]+)\b', Generic.Subheading), # column headings
            (r'(\+|-{3,}|\|)', Keyword), # borders
        ],
        'attrs': [
            (r'\]', Punctuation, '#pop'),
            (_var + r'(\s*)(=)(\s*)' + _var,
             bygroups(Name.Attribute, Text.Whitespace, Operator, Text.Whitespace,
                      String)),
            (r',', Punctuation),
        ],
    }
