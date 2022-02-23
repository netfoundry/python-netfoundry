#!/usr/bin/env python3
r"""[Experimental] command-line interface to the NetFoundry API
Usage::
    $ nfctl --help

    # Windows
    $ python3 -m netfoundry.ctl --help

PYTHON_ARGCOMPLETE_OK
"""

import os
import platform
import shutil
import sys
import tempfile

from milc import set_metadata

from ._version import get_versions
from .network import Network
from .network_group import NetworkGroup
from .organization import Organization
from .utility import Utility

set_metadata(version="v"+get_versions()['version']) # must precend import milc.cli
from milc import cli, questions

# TODO: enable config ini file
#import milc.subcommand.config


utility = Utility()

@cli.argument('-n', '--network-name', help='caseless display name of the network to manage', required=True )
@cli.argument('-c', '--credentials', help='API account JSON file from web console', default='credentials.json')
@cli.argument("-g", "--network-group", help="The shortname or ID of a network group to search for network_name")
@cli.argument("-o", "--organization", help="The label of an alternative organization (default is caller's org)" )
@cli.argument('-p', '--proxy', help="'http://localhost:8080' or 'socks5://localhost:9046'", default=None)
@cli.entrypoint('Configure the CLI to manage a network.')
def main(cli):
    text = '{style_bright}{bg_lightblue_ex}{fg_white}|___|\\___|{style_reset_all} ' \
        '{style_bright}{bg_red}{fg_white}main!'
    cli.echo(text)

@cli.argument('-z','--ziti-cli', help='path to ziti CLI executable')
@cli.subcommand('Login to the ziti-controller management API (requires ziti CLI)')
def login(cli):
    if cli.config.login.ziti_cli:
        ziti_cli = cli.config.login.ziti_cli
    else:
        if platform.system() == 'Windows':
            ziti_cli = 'ziti.exe'
        else:
            ziti_cli = 'ziti'
    if shutil.which(ziti_cli):
        cli.log.debug("found executable %s", shutil.which(ziti_cli))
    else:
        cli.log.critical("missing executable '%s' in PATH: %s", ziti_cli, os.environ['PATH'])
        sys.exit(1)

    if 'NETFOUNDRY_API_TOKEN' in os.environ:
        cli.log.debug("using bearer token from environment NETFOUNDRY_API_TOKEN")
    elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
        cli.log.debug("using file path to credentials file from environment NETFOUNDRY_API_ACCOUNT")
    elif 'NETFOUNDRY_CLIENT_ID' in os.environ and 'NETFOUNDRY_PASSWORD' in os.environ and 'NETFOUNDRY_OAUTH_URL' in os.environ:
        cli.log.debug("using API account credentials from environment NETFOUNDRY_CLIENT_ID, NETFOUNDRY_PASSWORD, NETFOUNDRY_OAUTH_URL")
    elif cli.config.general.credentials:
        cli.log.debug("using credentials file %s from args", cli.config.general.credentials)
    else:
        os.environ['NETFOUNDRY_API_TOKEN'] = questions.password(prompt='Enter Bearer Token:', confirm=False, validate=None)

    network_name = cli.config.general.network_name
    
    # use the session with some organization, default is to use the first and there's typically only one
    organization = Organization(
        credentials=cli.config.general.credentials if cli.config.general.credentials else None,
        organization_label=cli.config.general.organization if cli.config.general.organization else None,
        proxy=cli.config.general.proxy
    )
    cli.log.debug("organization label is %s.", organization.label)

    if cli.config.general.network_group:
        network_group = NetworkGroup(
            organization,
            network_group_name=cli.config.general.network_group
        )
        existing_networks = network_group.networks_by_normal_name()
        if not utility.normalize_caseless(network_name) in existing_networks.keys():
            raise Exception("ERROR: failed to find a network named \"{name}\".".format(name=network_name))
    else:
        existing_count = organization.count_networks_with_name(network_name)
        if existing_count == 1:
            existing_networks = organization.get_networks_by_organization(name=network_name)
            existing_network = existing_networks[0]
            network_group = NetworkGroup(
                organization,
                network_group_id=existing_network['networkGroupId']
            )
        elif existing_count > 1:
            raise Exception("ERROR: there were {count} networks named \"{name}\" visible to your identity. Try filtering with '--network-group'.".format(count=existing_count, name=network_name))
        else: #
            raise Exception("ERROR: failed to find a network named \"{name}\".".format(name=network_name))

    # use the Network
    network = Network(network_group, network_name=network_name)
    network.wait_for_status("PROVISIONED",wait=999,progress=True)

    tempdir = tempfile.mkdtemp()

    network_controller = network.get_resource_by_id(type="network-controller", id=network.network_controller['id'])
    ziti_ctrl_ip = network_controller['_embedded']['host']['ipAddress']

    try:
        secrets = network.get_controller_secrets(network.network_controller['id'])
        os.system('curl -sSfk https://'+ziti_ctrl_ip+'/.well-known/est/cacerts | openssl base64 -d | openssl pkcs7 -inform DER -outform PEM -print_certs -out '+tempdir+'/well-known-certs.pem')
        os.system(ziti_cli+' edge login '+ziti_ctrl_ip+' -u '+secrets['zitiUserId']+' -p '+secrets['zitiPassword']+' -c '+tempdir+'/well-known-certs.pem')
        os.system(ziti_cli+' edge --help')
    except:
        raise
    
    text = '{style_bright}{bg_lightblue_ex}{fg_white}|___|\\___|{style_reset_all} ' \
        '{style_bright}{bg_red}{fg_white}login!'
    cli.echo(text)

if __name__ == '__main__':
    cli()
