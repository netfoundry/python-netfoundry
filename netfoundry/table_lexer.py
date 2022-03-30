import re

from pygments.lexer import (ExtendedRegexLexer, RegexLexer, bygroups, combined,
                            default, include, this, using, words)
from pygments.token import *
from pygments.token import (Comment, Keyword, Name, Number, Operator,
                            Punctuation, String, Text, Whitespace)


class NetFoundryTableLexer(RegexLexer):
    """Parse NF CLI nfctl table output for highlighting"""
    name = 'nfctl-table'
    aliases = []
    filenames = ['*.nfctl']

    _var = r'([\w]+|"(?:\\"|[^"])*")'

    tokens = {
        'root': [
            (r'msc\b', Keyword.Type),
            # Options
            (r'(hscale|HSCALE|width|WIDTH|wordwraparcs|WORDWRAPARCS'
             r'|arcgradient|ARCGRADIENT)\b', Name.Property),
            # Operators
            (r'(abox|ABOX|rbox|RBOX|box|BOX|note|NOTE)\b', Operator.Word),
            (r'(\.|-|\|){3}', Keyword),
            (r'(?:-|=|\.|:){2}'
             r'|<<=>>|<->|<=>|<<>>|<:>'
             r'|->|=>>|>>|=>|:>|-x|-X'
             r'|<-|<<=|<<|<=|<:|x-|X-|=', Operator),
            # Names
            (r'\*', Name.Builtin),
            (_var, Name.Variable),
            # Other
            (r'\[', Punctuation, 'attrs'),
            (r'\{|\}|,|;', Punctuation),
        ],
        'attrs': [
            (r'\]', Punctuation, '#pop'),
            (_var + r'(\s*)(=)(\s*)' + _var,
             bygroups(Name.Attribute, Text.Whitespace, Operator, Text.Whitespace,
                      String)),
            (r',', Punctuation),
        ],
    }
