from pygments.lexer import RegexLexer
from pygments.token import Comment, Keyword, Name, Number, Operator, Punctuation, String, Text, Whitespace, Generic, Error

from netfoundry.utility import DC_PROVIDERS, RESOURCE_STATUSES


class NetFoundryTableLexer(RegexLexer):
    """Parse NF CLI nfctl table output for highlighting."""

    name = 'nfctl-table'
    aliases = []
    filenames = ['*.nfctl']
    tokens = {
        'root': [
            (r'\bERROR\b', Error),
            (r'\b[0-9]+\.[0-9]+\.[0-9]+', Number),             # semver
            (r'\b([a-z]([a-z0-9]+)?([A-Z][\w])+)\b', String),  # camel words
            (r'\b([A-Za-z0-9]+-?)+\b', String),                # kebab words
            (r'\b[0-9]+\b', Number.Integer),
            (r'\b([a-zA-Z0-9]{9,12})\b', String.Other),        # zitiId
            (r'\b('+r'|'.join(RESOURCE_STATUSES)+r')\b', Operator.Word),
            (r'\b('+r'|'.join(DC_PROVIDERS)+r')\b', Generic.Output),
            (r'^\s+\|', Keyword, 'heading'),                   # push to heading context
            (r'(\+|-{3,}|\|)', Keyword),                       # borders
            # Names
            (r'\*', Name.Builtin),
            # Other
            (r'\[', Punctuation, 'attrs'),
            (r'\{|\}|,|;', Punctuation),
        ],
        'heading': [
            (r'\b([\w]+)\b', Generic.Subheading),              # column headings
            (r'(\+|-{3,}|\|)', Keyword),                       # borders
        ],
        'attrs': [
            (r'\]', Punctuation, '#pop'),
            (r',', Punctuation),
        ],
    }
