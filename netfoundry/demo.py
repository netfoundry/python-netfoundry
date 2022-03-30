#!/usr/bin/env python3
r"""This script demonstrates the NetFoundry Python module.

Usage:
    $ python3 -m netfoundry.demo --network BibbidiBobbidiBoo
"""
import argparse
import logging
from sys import argv

from .ctl import main as nfctl


def main():
    # parser.add_argument(
    #     "-y", "--yes",
    #     dest="yes",
    #     default=False,
    #     action="store_true",
    #     help="Skip interactive prompt to confirm destructive actions."
    # )
    # parser.add_argument(
    #     "-n", "--network",
    #     required=True,
    #     help="The name of your demo network"
    # )
    # parser.add_argument(
    #     "-o", "--organization",
    #     help="The label of an alternative organization (default is org of caller)"
    # )
    # parser.add_argument(
    #     "-g", "--network-group",
    #     dest="network_group",
    #     help="The shortname of a Network Group (default is the first, typically singular, Group known to this Org)"
    # )
    # parser.add_argument("--credentials",
    #     default=None,
    #     help="path to API account credentials JSON file overrides NETFOUNDRY_API_ACCOUNT"
    # )
    nfctl(['demo']+argv[1:])


if __name__ == '__main__':
    main()
