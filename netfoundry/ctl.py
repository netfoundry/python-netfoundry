#!/usr/bin/env python3
r"""[Experimental] command-line interface to the NetFoundry API
Usage::
    $ nfctl --help
    # Windows
    $ python3 -m netfoundry.ctl --help

PYTHON_ARGCOMPLETE_OK
"""

import argparse
import os
import platform
import shutil
import sys
import tempfile
from base64 import b64decode
from json import dumps as json_dumps
from subprocess import call

from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
from milc import set_metadata
from requests import get
from yaml import dump as yaml_dumps

from ._version import get_versions
from .demo import main as nfdemo
from .network import Network
from .network_group import NetworkGroup
from .organization import Organization
from .utility import RESOURCES, Utility, plural, singular

set_metadata(version="v"+get_versions()['version']) # must precend import milc.cli
from milc import cli, questions

# TODO: enable operating on config ini file
#import milc.subcommand.config


utility = Utility()

class StoreDictKeyPair(argparse.Action):
    """Parse key pairs into a dictionary."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Split comma-separated key=value pairs."""
        my_dict = {}
        for kv in values.split(","):
            k,v = kv.split("=")
            my_dict[k] = v
        setattr(namespace, self.dest, my_dict)

@cli.argument('-c', '--credentials', help='API account JSON file from web console', default=None)
@cli.argument("-o", "--organization", help="label of an alternative organization (default is caller's org)" )
@cli.argument('-n', '--network', dest='network_name', arg_only=True, help='caseless name of the network to manage')
@cli.argument("-g", "--network-group", arg_only=True, help="shortname or ID of a network group to search for network_name")
@cli.argument('-y', '--yes', action='store_true', arg_only=True, help='Answer yes to all questions.')
@cli.argument('-p', '--proxy', help="like http://localhost:8080 or socks5://localhost:9046", default=None)
@cli.entrypoint('configure the CLI to manage a network')
def main(cli):
    """Configure the CLI to manage a network."""

@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
@cli.subcommand('create a resource')
def create(cli):
    """Create a resource."""
    if sys.stdin.isatty():
        create_request_body = edit_template(yaml_dumps(RESOURCES[plural(cli.args.resource_type)]['create_template']))
    else:
        for line in sys.stdin:
            create_request_body+=line
    cli.echo(create_request_body)

@cli.argument('-f','--filter', help="output filter as jq filter expression", default='.')
@cli.argument('-o','--output', help="output format", default="text", choices=["text","json","yaml"])
@cli.argument('-q','--query', arg_only=True, action=StoreDictKeyPair, help="query params as k=v,k=v comma-separated pairs", default=dict())
@cli.argument('-H','--headers', default=True, action='store_boolean', help='print column headers')
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=RESOURCES.keys())
@cli.subcommand('find resources as lists')
def list(cli):
    """Find resources as lists."""
    if cli.config.list.output == "text" and not sys.stdout.isatty():
        cli.log.warn("nfctl does not have a stable CLI interface. Use with caution in scripts.")

    organization = setup_organization()

    if cli.args.resource_type == "networks":
        matches = organization.get_networks_by_organization(**cli.args.query)
        if len(matches) == 0:
            cli.log.info("found no %s matching '%s'", cli.args.resource_type, str(cli.args.query))
            sys.exit(0)
        elif len(matches) >= 1:
            cli.log.debug("found %d %s matching '%s'", len(matches), cli.args.resource_type, str(cli.args.query))

        if cli.config.list.output == "text":
            if not cli.config.list.filter == '.':
                cli.log.warn("ignoring custom output filter '%s' because output format is '%s'", cli.config.list.filter, cli.config.list.output)
            columns = {
                "name": 48,
                "status": 20,
                "id": 37
            }
            if cli.config.list.headers:
                cli.echo('{style_bright}{fg_white}'+'{: ^48} {: ^20} {: ^37}'.format("name", "status", "id"))
                cli.echo('{style_bright}{fg_white}'+'{: <48} {: ^20} {: >37}'.format(
                    ''.join([char*48 for char in '-']),
                    ''.join([char*20 for char in '-']),
                    ''.join([char*37 for char in '-'])
                    )
                )
            for match in matches:
                cli.echo('{style_normal}{fg_white}'+'{: >48} {: ^20} {: >20}'.format(match['name'], match['status'], match['id']))
        elif cli.config.list.output == "yaml":
            cli.echo(yaml_dumps(matches))
        elif cli.config.list.output == "json":
            cli.echo(json_dumps(matches, indent=4))
    else:
        network, network_group = setup_network(organization)
        matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)
        if len(matches) == 0:
            cli.log.info("found no %s '%s'", cli.args.resource_type, cli.args.query)
            sys.exit(0)
        else:
            cli.log.debug("found at least one %s '%s'", cli.args.resource_type, cli.args.query)
            if cli.config.list.output == "text":
                columns = {
                    "name": 32,
                    "zitiId": 10,
                    "id": 37
                }
                if cli.config.list.headers:
                    cli.echo('{style_bright}{fg_white}'+'{: ^48} {: ^12} {: ^37}'.format("name", "zitiId", "id"))
                    cli.echo('{style_bright}{fg_white}'+'{: >48} {: ^12} {: >37}'.format(
                        ''.join([char*48 for char in '-']),
                        ''.join([char*12 for char in '-']),
                        ''.join([char*37 for char in '-'])
                        )
                    )
                for match in matches:
                    cli.echo('{style_normal}{fg_white}'+'{: <48} {: ^12} {: >37}'.format(match['name'], match['zitiId'], match['id']))
            elif cli.config.list.output == "yaml":
                cli.echo(yaml_dumps(matches, indent=4))
            elif cli.config.list.output == "json":
                cli.echo(json_dumps(matches, indent=4))

@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
@cli.argument('-q','--query', arg_only=True, action=StoreDictKeyPair, help="any valid query params for type as k=v,k=v comma-separated pairs", default=dict())
@cli.subcommand('delete a resource')
def delete(cli):
    """Delete a resource."""
    organization = setup_organization()
    network, network_group = setup_network(organization)

    if cli.args.resource_type == "network":
        if cli.args.query is not None:
            cli.log.warn("ignoring name='%s' because this operation applies to the entire network that is already selected", str(cli.args.query))
        if cli.args.yes or questions.yesno("confirm delete network \"{name}\"".format(name=network.name), default=False):
            spinner = cli.spinner(text='deleting {net}'.format(net=network.name), spinner='dots12')
            spinner.start()
            network.delete_network(progress=False)
            spinner.stop()
        else:
            cli.echo("not deleting network \"{name}\".".format(name=network.name))
    else:
        if cli.args.query is None:
            cli.log.error("need query to select a resource")
            raise Exception()
        matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)
        if len(matches) == 0:
            cli.log.info("found no %s '%s'", cli.args.resource_type, str(cli.args.query))
            sys.exit(1)
        elif len(matches) > 1:
            cli.log.error("found more than one %s '%s'", cli.args.resource_type, str(cli.args.query))
            sys.exit(1)
        if len(matches) == 1:
            cli.log.debug("found one %s '%s'", cli.args.resource_type, str(cli.args.query))
            if cli.args.yes or questions.yesno("confirm delete {type} '{name}'".format(type=cli.args.resource_type, name=matches[0]['name']), default=False):
                network.delete_resource(type=cli.args.resource_type, id=matches[0]['id'])
            else:
                cli.echo("not deleting {type} '{name}'".format(type=cli.args.resource_type, name=matches[0]['name']))

@cli.argument('-z','--ziti-cli', help='path to ziti CLI executable')
@cli.subcommand('login to the ziti-controller management API (requires ziti CLI)')
def login(cli):
    """Login to the ziti-controller management API (requires ziti CLI)."""
    if cli.config.login.ziti_cli:
        ziti_cli = cli.config.login.ziti_cli
    else:
        if platform.system() == 'Windows':
            ziti_cli = 'ziti.exe'
        else:
            ziti_cli = 'ziti'
    which_ziti = shutil.which(ziti_cli)
    if which_ziti:
        cli.log.debug("found ziti CLI executable in %s", which_ziti)
    else:
        cli.log.critical("missing executable '%s' in PATH: %s", ziti_cli, os.environ['PATH'])
        sys.exit(1)

    organization = setup_organization()
    network, network_group = setup_network(organization)

    tempdir = tempfile.mkdtemp()

    network_controller = network.get_resource_by_id(type="network-controller", id=network.network_controller['id'])
    if 'domainName' in network_controller.keys() and network_controller['domainName']:
        ziti_ctrl_ip = network_controller['domainName']
    else:
        ziti_ctrl_ip = network_controller['_embedded']['host']['ipAddress']

    try:
        secrets = network.get_controller_secrets(network.network_controller['id'])
    except:
        raise
    else:
        if cli.config.general.proxy:
            proxies = {
                'http': cli.config.general.proxy,
                'https': cli.config.general.proxy
            }
        else:
            proxies = dict()
        
        well_known_response = get('https://'+ziti_ctrl_ip+'/.well-known/est/cacerts', proxies=proxies, verify=False)
        well_known_decoding = b64decode(well_known_response.text)
        well_known_certs = pkcs7.load_der_pkcs7_certificates(well_known_decoding)
        well_known_pem = tempdir+'/well-known-certs.pem'
        with open(well_known_pem, 'wb') as pem:
            for cert in well_known_certs:
                pem.write(cert.public_bytes(Encoding.PEM))
        os.system(ziti_cli+' edge login '+ziti_ctrl_ip+' -u '+secrets['zitiUserId']+' -p '+secrets['zitiPassword']+' -c '+well_known_pem)
        os.system(ziti_cli+' edge --help')
    
def setup_organization():
    """Assume an identity in an organization."""
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

    # use the session with some organization, default is to use the first and there's typically only one
    organization = Organization(
        credentials=cli.config.general.credentials if cli.config.general.credentials else None,
        organization_label=cli.config.general.organization if cli.config.general.organization else None,
        expiry_minimum=0,
        proxy=cli.config.general.proxy
    )
    cli.log.debug("organization label is %s.", organization.label)

    return organization

def setup_network(organization: object):
    """Use a network."""
    if not cli.config.general.network_name:
        cli.log.error("need --network-name to configure a network")
        raise Exception()
    if cli.config.general.network_group:
        network_group = NetworkGroup(
            organization,
            network_group_name=network_group
        )
        existing_networks = network_group.networks_by_normal_name()
        if not utility.normalize_caseless(cli.config.general.network_name) in existing_networks.keys():
            cli.log.error("failed to find a network named \"{name}\".".format(name=cli.config.general.network_name))
            raise Exception()
    else:
        existing_count = organization.count_networks_with_name(cli.config.general.network_name)
        if existing_count == 1:
            existing_networks = organization.get_networks_by_organization(name=cli.config.general.network_name)
            existing_network = existing_networks[0]
            network_group = NetworkGroup(
                organization,
                network_group_id=existing_network['networkGroupId']
            )
        elif existing_count > 1:
            cli.log.error("there were {count} networks named \"{name}\" visible to your identity. Try filtering with '--network-group'.".format(count=existing_count, name=cli.config.general.network_name))
            raise Exception()
        else: #
            cli.log.error("failed to find a network named \"{name}\".".format(name=cli.config.general.network_name))
            raise Exception()

    # use the Network
    network = Network(network_group, network_name=cli.config.general.network_name)
    if cli.config.list.output == "text":
        spinner = cli.spinner(text='waiting for {net} to have status PROVISIONED'.format(net=cli.config.general.network_name), spinner='dots12')
        spinner.start()
        network.wait_for_status("PROVISIONED",wait=999,progress=False)
        spinner.stop()
    return network, network_group

def edit_template(template: object):
    """
    Edit a template and return the saved buffer.

    :param obj template: a deserialized template to edit and return as yaml
    """
    EDITOR = os.environ.get('EDITOR','vim')

    with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
        tf.write(template)
        tf.flush()
        call([EDITOR, tf.name])

        tf.seek(0)
        edited = tf.read()
    return edited

if __name__ == '__main__':
    cli()
