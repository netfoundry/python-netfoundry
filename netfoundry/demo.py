#!/usr/bin/env python3
r"""This script demonstrates the NetFoundry Python module.

Usage:
    $ python3 -m netfoundry.demo --network BibbidiBobbidiBoo
"""
from subprocess import run
from sys import argv

def main():
    """Run the built-in demo."""
    raw_args = ['nfctl', 'demo']
    if len(argv) > 1:
        raw_args.extend(argv[1:])
    run(raw_args)


if __name__ == '__main__':
    main()
