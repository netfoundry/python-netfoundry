#!/usr/bin/env python3
r"""[Experimental] command-line interface to the NetFoundry API
Usage::
    $ nfctl --help
    # Windows
    $ python3 -m netfoundry.ctl --help

PYTHON_ARGCOMPLETE_OK
"""
import argparse
import logging
#import io
import os
import platform
import shutil
import sys
import tempfile
import time
from base64 import b64decode
#from contextlib import redirect_stdout
from json import dumps as json_dumps
from json import loads as json_loads
from subprocess import call

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from jwt.exceptions import PyJWTError
from milc import set_metadata
from requests import get
from tabulate import tabulate
from yaml import dump as yaml_dumps
from yaml import full_load as yaml_loads

from ._version import get_versions
from .exceptions import NFAPINoCredentials
#from .demo import main as nfdemo
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

class StoreListKeys(argparse.Action):
    """Parse comma-separated strings into a list."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Split comma-separated list elements."""
        setattr(namespace, self.dest, values.split(','))

@cli.argument('-C', '--credentials', help='API account JSON file from web console', default=None)
@cli.argument("-O", "--organization", help="label or ID of an alternative organization (default is caller's org)" )
@cli.argument('-N', '--network', help='caseless name of the network to manage')
@cli.argument("-G", "--network-group", help="shortname or ID of a network group to search for network_identifier")
@cli.argument('-O','--output', help="object formats suppress console messages", default="text", choices=['text', 'yaml','json'])
@cli.argument('-Y', '--yes', action='store_true', arg_only=True, help='answer yes to potentially-destructive operations')
@cli.argument('-P', '--proxy', help="like http://localhost:8080 or socks5://localhost:9046", default=None)
@cli.entrypoint('configure the CLI to manage a network')
def main(cli):
    """Configure the CLI to manage a network."""
    organization = use_organization()
    if cli.config.general.network_group and cli.config.general.network:
        cli.log.debug("configuring network %s in group %s", cli.config.general.network, cli.config.general.network_group)
        network, network_group = use_network(
            organization=organization,
            group=cli.config.general.network_group,
            network=cli.config.general.network
        )
    elif cli.config.general.network:
        cli.log.debug("configuring network %s and local group if unique name for this organization", cli.config.general.network)
        network, network_group = use_network(
            organization=organization,
            network=cli.config.general.network
        )
    elif cli.config.general.network_group:
        cli.log.debug("configuring network group %s", cli.config.general.network_group)
        network_group = use_network_group(organization, group=cli.config.general.network_group)
        network = None
    else:
        cli.log.debug("not configuring network or network group")
        network, network_group = None, None

    summary = dict()

    summary['caller'] = whoami(cli, echo=False, organization=organization)
    summary['organization'] = organization.describe
    if network_group:
        summary['network_group'] = network_group.describe
        summary['network_group']['networks_count'] = len(network_group.networks_by_normal_name().keys())
    if network:
        summary['network'] = network.describe

    if cli.config.general.output == "text":
        cli.echo(
            '{fg_lightgreen_ex}'
            +'Logged in as {fullname} ({email}) of {org_name} ({org_label}@{env}) until {expiry_timestamp} ({expiry_seconds}s)'.format(
                fullname=summary['caller']['name'],
                email=summary['caller']['email'],
                org_label=organization.label,
                org_name=organization.name,
                env=organization.environment,
                expiry_timestamp=time.strftime('%Y-%m-%d %H:%M:%S GMT%z', time.localtime(organization.expiry)),
                expiry_seconds=int(organization.expiry_seconds)
            )
        )
        if network_group:
            cli.echo(
                '{fg_lightgreen_ex}'
                +'❯ network group {fullname} ({shortname}) containing {count} networks'.format(
                    fullname=summary['network_group']['name'],
                    shortname=summary['network_group']['organizationShortName'],
                    count=summary['network_group']['networks_count']
                )
            )
        if network:
            cli.echo(
                '{fg_lightgreen_ex}'
                +'❯ network {fullname} ({data_center}) with version {version} and status {status}'.format(
                    fullname=summary['network']['name'],
                    data_center=summary['network']['region'],
                    version=summary['network']['productVersion'],
                    status=summary['network']['status']
                )
            )

    elif cli.config.general.output == "yaml":
        cli.echo(
            '{fg_lightgreen_ex}'
            +yaml_dumps(summary, indent=4)
        )
    elif cli.config.general.output == "json":
        cli.echo(
            '{fg_lightgreen_ex}'
            +json_dumps(summary, indent=4)
        )

@cli.subcommand('get caller identity')
def whoami(cli, echo: bool=True, organization: object=None):
    """Get caller identity."""
    if organization is None:
        organization = use_organization()
    caller = organization.caller
    caller['label'] = organization.label
    caller['environment'] = organization.environment
    if echo:
        if cli.config.general.output in ["yaml","text"]:
            cli.echo(yaml_dumps(caller, indent=4, default_flow_style=False))
        elif cli.config.general.output == "json":
            cli.echo(json_dumps(caller, indent=4))
    else:
        return caller

@cli.argument('-w','--wait', help='seconds to wait for process execution to finish', default=0)
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
@cli.subcommand('create a resource from stdin or editor')
def create(cli):
    """Create a resource."""
    create_yaml = str()
    if sys.stdin.isatty():
        if 'create_template' in RESOURCES[plural(cli.args.resource_type)].keys():
            template = RESOURCES[plural(cli.args.resource_type)]['create_template']
        else:
            template = {"hint": "No template was found for resource type {type}. Replace the contents of this buffer with the request body as YAML or JSON to create a resource. networkId will be added automatically.".format(type=cli.args.resource_type)}
        create_yaml = edit_template(template)
    else:
        for line in sys.stdin:
            create_yaml+=line
    create_object = yaml_loads(create_yaml)

    organization = use_organization()

    if cli.config.create.wait:
        spinner = cli.spinner(text='creating {type} {name}'.format(type=cli.args.resource_type, name=create_object['name']), spinner='dots12')
        spinner.start()

    if cli.args.resource_type == "network":
        if cli.config.general.network_group:
            network_group = use_network_group(organization=organization)
        elif len(organization.get_network_groups_by_organization()) > 1:
            cli.log.error("specify --network-group because there is more than one available to caller's identity")
            raise SystemExit
        else:
            network_group_id = organization.get_network_groups_by_organization()[0]['id']
            network_group = use_network_group(organization=organization, id=network_group_id)
        resource = network.create_resource(type=cli.args.resource_type, properties=create_object, wait=cli.config.create.wait)
        if cli.config.create.wait:
            spinner.stop()
    else:
        network, network_group = use_network(
            organization=organization,
            group=cli.config.general.network_group,
            network=cli.config.general.network
        )
        resource = network.create_resource(type=cli.args.resource_type, properties=create_object, wait=cli.config.create.wait)
        if cli.config.create.wait:
            spinner.stop()

@cli.argument('-q','--query', arg_only=True, action=StoreDictKeyPair, help="query params as k=v,k=v comma-separated pairs", default=dict())
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
@cli.subcommand('get a single resource by id or query')
def get(cli):
    """Get a single resource as a dictionary."""
    organization = use_organization()
    network, network_group = use_network(
        organization=organization,
        group=cli.config.general.network_group,
        network=cli.config.general.network,
        operation='delete'
    )
    if cli.args.query:
        matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)
        if len(matches) == 0:
            cli.log.info("found no %s '%s'", cli.args.resource_type, cli.args.query)
            exit(0)
        if len(matches) == 1:
            cli.log.debug("found exactly one %s '%s'", cli.args.resource_type, cli.args.query)
            match = network.get_resource_by_id(type=cli.args.resource_type, id=matches[0]['id'])
        else:
            cli.log.debug("found more than one %s '%s'", cli.args.resource_type, cli.args.query)
            exit(1)

    if cli.config.general.output in ["yaml","text"]:
        cli.echo(yaml_dumps(match, indent=4, default_flow_style=False))
    elif cli.config.general.output == "json":
        cli.echo(json_dumps(match, indent=4))


@cli.argument('-b','--borders', default=True, action='store_boolean', help='print cell borders in text tables')
@cli.argument('-H','--headers', default=True, action='store_boolean', help='print column headers in text tables')
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)", default=['name','label','organizationShortName','id','createdBy','createdAt','status','zitiId'])
@cli.argument('-q','--query', arg_only=True, action=StoreDictKeyPair, help="query params as k=v,k=v comma-separated pairs", default=dict())
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=RESOURCES.keys())
@cli.subcommand('find resources as lists')
def list(cli):
    """Find resources as lists."""
    if not sys.stdout.isatty():
        cli.log.warn("nfctl does not have a stable CLI interface. Use with caution in scripts.")

    cli.log.debug("filtering keys: %s", str(cli.args.keys))

    organization = use_organization()

    if cli.args.resource_type == "organizations":
        matches = organization.get_organizations(**cli.args.query)
    elif cli.args.resource_type == "network-groups":
        matches = organization.get_network_groups_by_organization(**cli.args.query)
    elif cli.args.resource_type == "identities":
        matches = organization.get_identities(**cli.args.query)
    elif cli.args.resource_type == "networks":
        if cli.config.general.network_group:
            network_group = use_network_group(organization, group=cli.config.general.network_group)
            matches = organization.get_networks_by_group(network_group.id, **cli.args.query)
        else:
            matches = organization.get_networks_by_organization(**cli.args.query)
    else:
        network, network_group = use_network(
            organization=organization,
            group=cli.config.general.network_group,
            network=cli.config.general.network
        )
        matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)

    if len(matches) == 0:
        cli.log.info("found no %s '%s'", cli.args.resource_type, cli.args.query)
        exit(0)
    else:
        cli.log.debug("found at least one %s '%s'", cli.args.resource_type, cli.args.query)

    filtered_matches = []
    valid_keys = matches[0].keys()
    for match in matches:
        filtered_match = { key: match[key] for key in cli.args.keys if key in valid_keys}
        filtered_matches.append(filtered_match)

    if cli.config.general.output == "text":
        if cli.config.list.headers:
            table_headers = filtered_matches[0].keys()
        else:
            table_headers = []
        if cli.config.list.borders:
            table_borders = "github"
        else:
            table_borders = "plain"
        cli.echo(tabulate(tabular_data=[match.values() for match in filtered_matches], headers=table_headers, tablefmt=table_borders))
    elif cli.config.general.output == "yaml":
        cli.echo(yaml_dumps(matches, indent=4, default_flow_style=False))
    elif cli.config.general.output == "json":
        cli.echo(json_dumps(matches, indent=4))

@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
@cli.argument('-q','--query', arg_only=True, action=StoreDictKeyPair, help="any valid query params for type as k=v,k=v comma-separated pairs", default=dict())
@cli.subcommand('delete a resource')
def delete(cli):
    """Delete a resource."""
    organization = use_organization()
    network, network_group = use_network(
        organization=organization,
        group=cli.config.general.network_group,
        network=cli.config.general.network,
        operation='delete'
    )

    if cli.args.resource_type == "network":
        if cli.args.query is not {}:
            cli.log.warn("ignoring name='%s' because this operation applies to the entire network that is already selected", str(cli.args.query))
        if cli.args.yes or questions.yesno("confirm delete network '{name}'".format(name=network.name), default=False):
            spinner = cli.spinner(text='deleting {net}'.format(net=network.name), spinner='dots12')
            spinner.start()
            network.delete_network(progress=False)
            spinner.stop()
        else:
            cli.echo("not deleting network '{name}'.".format(name=network.name))
    else:
        if cli.args.query is {}:
            cli.log.error("need query to select a resource")
            exit(1)
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

@cli.argument('api', help='logout from what?', arg_only=True, default="organization", choices=['organization', 'ziti'])
@cli.subcommand('logout from a management API')
def logout(cli):
    """Logout from an API by deleting the cached token."""
    if cli.args.api == "organization":
        organization = use_organization()
        try:
            organization.logout()
        except Exception as e:
            logging.error("failed to logout with %s", e)
            exit(1)
    elif cli.args.api == "ziti":
        pass

@cli.argument('-s','--shell', help='emit only shell commands to configure terminal environment', arg_only=True, action="store_true", default=False)
@cli.argument('api', help='login to what?', arg_only=True, default="organization", choices=['organization', 'ziti'])
@cli.argument('-z','--ziti-cli', help='path to ziti CLI executable')
@cli.subcommand('login to a management API')
def login(cli):
    """Login to an API and cache the expiring token."""
    organization = use_organization()
    if cli.args.api == "organization":
        cli.echo(
            """
# source this output like
# $ source <(nfctl --credentials credentials.json login organization)
export NETFOUNDRY_API_TOKEN="{token}"
# or, alternatively, silently-paste and export to child procs
# $ read -s NETFOUNDRY_API_TOKEN && export NETFOUNDRY_API_TOKEN
# then logout of organization with
# $ unset NETFOUNDRY_API_TOKEN
""".format(token=organization.token)
        )
    elif cli.args.api == "ziti":
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
        network, network_group = use_network(
            organization=organization,
            group=cli.config.general.network_group,
            network=cli.config.general.network
        )
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
    
def use_organization():
    """Assume an identity in an organization."""
    if cli.config.general.credentials:
        cli.log.debug("using credentials file %s from config or args", cli.config.general.credentials)
    elif 'NETFOUNDRY_API_TOKEN' in os.environ:
        cli.log.debug("using bearer token from environment NETFOUNDRY_API_TOKEN")
    elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
        cli.log.debug("using file path to credentials file from environment NETFOUNDRY_API_ACCOUNT")
    elif 'NETFOUNDRY_CLIENT_ID' in os.environ and 'NETFOUNDRY_PASSWORD' in os.environ and 'NETFOUNDRY_OAUTH_URL' in os.environ:
        cli.log.debug("using API account credentials from environment NETFOUNDRY_CLIENT_ID, NETFOUNDRY_PASSWORD, NETFOUNDRY_OAUTH_URL")
    else:
        cli.log.debug("no token or credentials file provided, trying token cache")

    # use the session with some organization, default is to use the first and there's typically only one
    try:
        organization = Organization(
            credentials=cli.config.general.credentials if cli.config.general.credentials else None,
            organization=cli.config.general.organization if cli.config.general.organization else None,
            expiry_minimum=0,
            proxy=cli.config.general.proxy
        )
    except NFAPINoCredentials as e:
        cli.log.debug("caught no credentials exception from Organization, prompting for token")
        try:
            os.environ['NETFOUNDRY_API_TOKEN'] = questions.password(prompt='Enter Bearer Token:', confirm=False, validate=None)
        except KeyboardInterrupt as e:
            cli.log.debug("input cancelled by user")
        try:
            organization = Organization(
                credentials=cli.config.general.credentials if cli.config.general.credentials else None,
                organization=cli.config.general.organization if cli.config.general.organization else None,
                expiry_minimum=0,
                proxy=cli.config.general.proxy
            )
        except PyJWTError as e:
            exit(1)
    cli.log.debug("logged-in organization label is %s.", organization.label)
    return organization

def use_network_group(organization: object, group: str=None):
    """
    Use a network group.
    
    :param str group: name or UUIDv4 of gropu to use
    """
    # module will use first available group if not specified, and typically there is only one
    network_group = NetworkGroup(
        organization,
        group=group if group else None,
    )
    cli.log.debug("network group is %s", network_group.name)
    return network_group

def use_network(organization: object, network: str=None, group: str=None, operation: str='read'):
    """Use a network."""
    network_identifier = network
    if not network_identifier:
        cli.log.error("need --network to configure a network")
        exit(1)
    if group:
        network_group = use_network_group(organization=organization, group=group)
        existing_networks = network_group.networks_by_normal_name()
        if not utility.normalize_caseless(network_identifier) in existing_networks.keys():
            cli.log.error("failed to find a network named '{name}'.".format(name=network_identifier))
            exit(1)
    else:
        existing_count = organization.count_networks_with_name(network_identifier)
        if existing_count == 1:
            existing_networks = organization.get_networks_by_organization(name=network_identifier)
            existing_network = existing_networks[0]
            network_group = use_network_group(organization, group=existing_network['networkGroupId'])
        elif existing_count > 1:
            cli.log.error("there were {count} networks named '{name}' visible to your identity. Try filtering with '--network-group'.".format(count=existing_count, name=network_identifier))
            exit(1)
        else:
            cli.log.error("failed to find a network named '{name}'.".format(name=network_identifier))
            exit(1)

    # use the Network
    network = Network(network_group, network=network_identifier)
    if cli.config.general.output == "text":
        spinner = cli.spinner(text='waiting for {net} to have status PROVISIONED'.format(net=network_identifier), spinner='dots12')
        spinner.start()
        if operation == delete:
            network.wait_for_statuses(["DELETING","DELETED"],wait=999,progress=False)
        elif operation in ['create','read','update']:
            network.wait_for_status("PROVISIONED",wait=999,progress=False)
        spinner.stop()
    return network, network_group

def edit_template(template: object):
    """
    Edit a template and return the saved buffer.

    :param obj template: a deserialized template to edit and return as yaml
    """
    EDITOR = os.environ.get('EDITOR','vim')
    yaml_dumps(template, default_flow_style=False)
    with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
        tf.write(yaml_dumps(template, default_flow_style=False).encode())
        tf.flush()
        call([EDITOR, tf.name])

        tf.seek(0)
        edited = tf.read()
    return edited

if __name__ == '__main__':
    cli()
