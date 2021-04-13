#!/usr/bin/env python3
r"""Command-line interface to the NetFoundry API
Usage::
    $ python3 -m netfoundry.ctl --credentials credentials.json

PYTHON_ARGCOMPLETE_OK
"""
from milc import cli
import pkg_resources  # part of setuptools
import netfoundry

@cli.argument('-c', '--credentials', help='API account JSON file from web console', default='credentials.json')
@cli.argument('-p', '--proxy', help='HTTP proxy URL e.g. http://locahost:8888', default=None)
@cli.subcommand('version', help='print Python module version')
@cli.entrypoint('Greet a user.')

def main(cli):
    cli.log.info('Hello, %s!', cli.config.general.credentials)

    package = "netfoundry"
    version = pkg_resources.require(package)[0].version

    session = netfoundry.Session(
        credentials=cli.config.general.credentials if cli.config.general.credentials else None,
        proxy=cli.config.general.proxy
    )

    # yields a list of Network Groups in Organization.network_groups[], but there's typically only one group
    Organization = netfoundry.Organization(session)

    # use the default Network Group (the first Network Group ID known to the Organization)
    network_group = netfoundry.NetworkGroup(Organization)

if __name__ == '__main__':
    cli()