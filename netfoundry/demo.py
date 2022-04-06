#!/usr/bin/env python3
r"""This script demonstrates the NetFoundry Python module.

Usage:
    $ python3 -m netfoundry.demo --network BibbidiBobbidiBoo
"""
import re
import sys

try:
    from importlib.metadata import distribution
except ImportError:
    try:
        from importlib_metadata import distribution
    except ImportError:
        from pkg_resources import load_entry_point


def importlib_load_entry_point(spec, group, name):
    dist_name, _, _ = spec.partition('==')
    matches = (
        entry_point
        for entry_point in distribution(dist_name).entry_points
        if entry_point.group == group and entry_point.name == name
    )
    return next(matches).load()


globals().setdefault('load_entry_point', importlib_load_entry_point)

def main():
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    _args = [sys.argv[0], 'demo'] + sys.argv[1:]
    sys.argv = _args
    sys.exit(load_entry_point('netfoundry', 'console_scripts', 'nfctl')())

if __name__ == '__main__':
    main()
