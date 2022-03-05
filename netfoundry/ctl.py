#!/usr/bin/env python3
r"""General-purpose command-line-interface to the NetFoundry API.

Usage::
    $ nfctl --help

PYTHON_ARGCOMPLETE_OK
"""
import argparse
import os
import platform
import shutil
import sys
import tempfile
import time
from base64 import b64decode
from json import dumps as json_dumps
from json import loads as json_loads
from subprocess import call

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from jwt.exceptions import PyJWTError
from milc import set_metadata
from requests import get as http_get
from tabulate import tabulate
from yaml import dump as yaml_dumps
from yaml import full_load as yaml_loads

from ._version import get_versions
from .exceptions import NFAPINoCredentials
from .network import Network
from .network_group import NetworkGroup
from .organization import Organization
from .utility import RESOURCES, Utility, plural, singular

set_metadata(version="v"+get_versions()['version']) # must precend import milc.cli
import milc.subcommand.config
from milc import cli, questions

utility = Utility()

class StoreDictKeyPair(argparse.Action):
    """Parse key pairs into a dictionary."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Split comma-separated key=value pairs."""
        my_dict = {}
        if values is not None: # and len(values.split(',')) > 0:
            for kv in values.split(','):
                k,v = kv.split('=')
                my_dict[k] = v
        setattr(namespace, self.dest, my_dict)

class StoreListKeys(argparse.Action):
    """Parse comma-separated strings into a list."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Split comma-separated list elements."""
        setattr(namespace, self.dest, values.split(','))

@cli.argument('-p','--profile', default='nfctl', help='login profile for storing and retrieving concurrent, discrete sessions')
@cli.argument('-C', '--credentials', help='API account JSON file from web console', default=None)
@cli.argument("-O", "--organization", help="label or ID of an alternative organization (default is caller's org)" )
@cli.argument('-N', '--network', help='caseless name of the network to manage')
@cli.argument("-G", "--network-group", help="shortname or ID of a network group to search for network_identifier")
@cli.argument('-O','--output', help="object formats suppress console messages", default="text", choices=['text', 'yaml','json'])
@cli.argument('-b','--borders', default=True, action='store_boolean', help='print cell borders in text tables')
@cli.argument('-H','--headers', default=True, action='store_boolean', help='print column headers in text tables')
@cli.argument('-Y', '--yes', action='store_true', arg_only=True, help='answer yes to potentially-destructive operations')
@cli.argument('-P', '--proxy', help="like http://localhost:8080 or socks5://localhost:9046", default=None)
@cli.entrypoint('configure the CLI to manage a network')
def main(cli):
    """Configure the CLI to manage a network."""
    login(cli, api="organization")

@cli.argument('api', help=argparse.SUPPRESS, arg_only=True, nargs='?', default="organization", choices=['organization', 'ziti'])
@cli.argument('-s','--shell', help=argparse.SUPPRESS, arg_only=True, action="store_true", default=False)
@cli.argument('-z','--ziti-cli', help=argparse.SUPPRESS)
@cli.subcommand('login to a management API', hidden=True)
def login(cli, api: str=None, shell: bool=None):
    """Login to an API and cache the expiring token."""
    if api:
        cli.args.api = api
    if shell is not None:
        cli.args.shell = shell
    else:
        cli.args.shell = False
    # if logging in to a NF org (default)
    if cli.args.api == "organization":
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

        summary_object = dict()
        summary_object['caller'] = whoami(cli, echo=False, organization=organization)
        summary_object['organization'] = organization.describe
        if network_group:
            summary_object['network_group'] = network_group.describe
            summary_object['network_group']['networks_count'] = len(network_group.networks_by_normal_name().keys())
        if network:
            summary_object['network'] = network.describe

        # compose a summary table from selected details if text, not yaml or
        # json (unless shell which means to suppress normal output and only
        # configure the current shell)
        if not cli.args.shell and cli.config.general.output == "text":
            summary_table = [['domain', 'summary']]
            summary_table.append(['organization', '"{org_name}" ({org_label}@{env}) logged in as {fullname} ({email}) until {expiry_timestamp} ({expiry_seconds}s)'.format(
                    fullname=summary_object['caller']['name'],
                    email=summary_object['caller']['email'],
                    org_label=organization.label,
                    org_name=organization.name,
                    env=organization.environment,
                    expiry_timestamp=time.strftime('%Y-%m-%d %H:%M:%S GMT%z', time.localtime(organization.expiry)),
                    expiry_seconds=int(organization.expiry_seconds)
                )])
            if network_group:
                    summary_table.append(['network group', '"{fullname}" ({shortname}) configured with {count} networks'.format(
                        fullname=summary_object['network_group']['name'],
                        shortname=summary_object['network_group']['organizationShortName'],
                        count=summary_object['network_group']['networks_count']
                )])
            if network:
                    summary_table.append(['network', '"{fullname}" ({data_center}) with version {version} and status {status} configured'.format(
                        fullname=summary_object['network']['name'],
                        data_center=summary_object['network']['region'],
                        version=summary_object['network']['productVersion'],
                        status=summary_object['network']['status']
                )])
            if cli.config.general.borders:
                table_borders = "github"
            else:
                table_borders = "plain"
            cli.echo(
                '{fg_lightgreen_ex}'
                +tabulate(tabular_data=summary_table, headers='firstrow', tablefmt=table_borders)
            )

        elif not cli.args.shell and cli.config.general.output == "yaml":
            cli.echo(
                '{fg_lightgreen_ex}'
                +yaml_dumps(summary_object, indent=4)
            )
        elif not cli.args.shell and cli.config.general.output == "json":
            cli.echo(
                '{fg_lightgreen_ex}'
                +json_dumps(summary_object, indent=4)
            )
        if cli.args.shell:
            cli.echo(
                """
# $ source <(nfctl --credentials credentials.json login organization)
export NETFOUNDRY_API_TOKEN="{token}"
export MOPENV={env}
""".format(token=organization.token, env=organization.environment)
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
            exit(1)
        organization = use_organization()
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
            well_known_response = http_get('https://'+ziti_ctrl_ip+'/.well-known/est/cacerts', proxies=proxies, verify=False)
            well_known_decoding = b64decode(well_known_response.text)
            well_known_certs = pkcs7.load_der_pkcs7_certificates(well_known_decoding)
            well_known_pem = tempdir+'/well-known-certs.pem'
            with open(well_known_pem, 'wb') as pem:
                for cert in well_known_certs:
                    pem.write(cert.public_bytes(Encoding.PEM))
            os.system(ziti_cli+' edge login '+ziti_ctrl_ip+' -u '+secrets['zitiUserId']+' -p '+secrets['zitiPassword']+' -c '+well_known_pem)
            os.system(ziti_cli+' edge --help')

@cli.subcommand('logout from an identity organization')
def logout(cli):
    """Logout by deleting the cached token."""
    organization = use_organization(prompt=False)
    try:
        organization.logout()
    except NFAPINoCredentials as e:
        cli.log.debug("no need to logout because not logged in")
        return True
    except Exception as e:
        cli.log.error("failed to logout with %s", e)
        exit(1)

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

@cli.argument('-f', '--from-file', help='JSON or YAML file')
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

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs", default=None)
@cli.argument('-a', '--accept', arg_only=True, default=None, choices=['create','update'], help="request the as=create or as=update form of the resource")
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
@cli.subcommand('get a single resource by query')
def get(cli):
    """Get a single resource as a dictionary."""
    organization = use_organization()
    match = {}
    matches = []
    if cli.args.resource_type == "organization":
        if 'id' in cli.args.query.keys():
            match = organization.get_organization(id=cli.args.query['id'])
        else:
            matches = organization.get_organizations(**cli.args.query)
            if len(matches) == 1:
                match = organization.get_organization(id=matches[0]['id'])
    elif cli.args.resource_type == "network-group":
        if 'id' in cli.args.query.keys():
            match = organization.get_network_group(network_group_id=cli.args.query['id'])
        else:
            matches = organization.get_network_groups_by_organization(**cli.args.query)
            if len(matches) == 1:
                match = organization.get_network_group(network_group_id=matches[0]['id'])
    elif cli.args.resource_type == "identity":
        if 'id' in cli.args.query.keys():
            match = organization.get_identity(identity_id=cli.args.query['id'])
        else:
            matches = organization.get_identities(**cli.args.query)
            if len(matches) == 1:
                match = matches[0]
    elif cli.args.resource_type == "network":
        if 'id' in cli.args.query.keys():
            match = organization.get_network(network_id=cli.args.query['id'])
        else:
            if cli.config.general.network_group and not cli.config.general.network:
                network_group = use_network_group(organization, group=cli.config.general.network_group)
                matches = organization.get_networks_by_group(network_group.id, **cli.args.query)
            elif cli.config.general.network:
                network, network_group = use_network(
                    organization=organization,
                    network=cli.config.general.network,
                )
                match = network.describe
            else:
                matches = organization.get_networks_by_organization(**cli.args.query)
            if len(matches) == 1:
                match = organization.get_network(network_id=matches[0]['id'], embed="all", accept=cli.args.accept)
    else: # is a resource in the network domain
        network, network_group = use_network(
            organization=organization,
            group=cli.config.general.network_group,
            network=cli.config.general.network,
        )
        if 'id' in cli.args.query.keys():
            match = network.get_resource_by_id(type=cli.args.resource_type, id=cli.args.query['id'], accept=cli.args.accept)
        else:
            matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)
            if len(matches) == 1:
                cli.log.debug("found exactly one %s '%s'", cli.args.resource_type, cli.args.query)
                match = network.get_resource_by_id(type=cli.args.resource_type, id=matches[0]['id'], accept=cli.args.accept)

    if match:
        cli.log.debug("found exactly one %s '%s'", cli.args.resource_type, cli.args.query)
        if cli.config.general.output in ["yaml","text"]:
            cli.echo(yaml_dumps(match, indent=4, default_flow_style=False))
        elif cli.config.general.output == "json":
            cli.echo(json_dumps(match, indent=4))
    elif len(matches) == 0:
        cli.log.info("found no %s '%s'", cli.args.resource_type, cli.args.query)
        return True
    else: # len(matches) > 1:
        cli.log.error("found more than one %s '%s'", cli.args.resource_type, cli.args.query)
        exit(len(matches))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs", default="id=%")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)", default=['name','label','organizationShortName','id','createdBy','createdAt','status','zitiId','provider','locationCode','ipAddress','region','size'])
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=RESOURCES.keys())
@cli.subcommand('find resources as lists')
def list(cli):
    """Find resources as lists."""
    if not sys.stdout.isatty():
        cli.log.warn("nfctl does not have a stable CLI interface. Use with caution in scripts.")

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

    if cli.config.general.output == "text":
        # intersection of the set of valid, observed keys in the first match
        # and the set of configured, desired keys
        valid_keys = set(matches[0].keys()) & set(cli.args.keys)
        cli.log.debug("valid keys: %s", str(valid_keys))
        filtered_matches = []
        for match in matches:
            filtered_match = { key: match[key] for key in cli.args.keys if key in valid_keys}
            filtered_matches.append(filtered_match)
        if cli.config.general.headers:
            table_headers = filtered_matches[0].keys()
        else:
            table_headers = []
        if cli.config.general.borders:
            table_borders = "github"
        else:
            table_borders = "plain"
        cli.echo(
            '{fg_lightgreen_ex}'
            +tabulate(tabular_data=[match.values() for match in filtered_matches], headers=table_headers, tablefmt=table_borders)
        )
    elif cli.config.general.output == "yaml":
        cli.echo(yaml_dumps(matches, indent=4, default_flow_style=False))
    elif cli.config.general.output == "json":
        cli.echo(json_dumps(matches, indent=4))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs", default=None)
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
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
        if not cli.args.query == {}:
            cli.log.warn("ignoring name='%s' because this operation applies to the entire network that is already selected", str(cli.args.query))
        try:
            if cli.args.yes or questions.yesno("confirm delete network '{name}'".format(name=network.name), default=False):
                spinner = cli.spinner(text='deleting {net}'.format(net=network.name), spinner='dots12')
                try:
                    spinner.start()
                    network.delete_network(progress=False)
                    spinner.stop()
                except KeyboardInterrupt as e:
                    cli.log.debug("wait cancelled by user")
            else:
                cli.echo("not deleting network '{name}'.".format(name=network.name))
        except KeyboardInterrupt as e:
            cli.log.debug("input cancelled by user")
    else:
        if not cli.args.query:
            cli.log.error("need query to select a resource")
            exit(1)
        matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)
        if len(matches) == 0:
            cli.log.info("found no %s '%s'", cli.args.resource_type, str(cli.args.query))
            exit(1)
        elif len(matches) > 1:
            cli.log.error("found more than one %s '%s'", cli.args.resource_type, str(cli.args.query))
            exit(1)
        if len(matches) == 1:
            cli.log.debug("found one %s '%s'", cli.args.resource_type, str(cli.args.query))
            try:
                if cli.args.yes or questions.yesno("confirm delete {type} '{name}'".format(type=cli.args.resource_type, name=matches[0]['name']), default=False):
                    network.delete_resource(type=cli.args.resource_type, id=matches[0]['id'])
                else:
                    cli.echo("not deleting {type} '{name}'".format(type=cli.args.resource_type, name=matches[0]['name']))
            except KeyboardInterrupt as e:
                cli.log.debug("input cancelled by user")

def use_organization(prompt: bool=True):
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
            profile=cli.config.general.profile,
            expiry_minimum=0,
            proxy=cli.config.general.proxy
        )
    except NFAPINoCredentials as e:
        if prompt:
            cli.log.debug("caught no credentials exception from organization, prompting for token")
            try:
                os.environ['NETFOUNDRY_API_TOKEN'] = questions.password(prompt='Enter Bearer Token:', confirm=False, validate=None)
            except KeyboardInterrupt as e:
                cli.log.debug("input cancelled by user")
            try:
                organization = Organization(
                    credentials=cli.config.general.credentials if cli.config.general.credentials else None,
                    organization=cli.config.general.organization if cli.config.general.organization else None,
                    profile=cli.config.general.profile,
                    expiry_minimum=0,
                    proxy=cli.config.general.proxy
                )
            except PyJWTError as e:
                exit(1)
        else:
            cli.log.info("not logged in")
            raise NFAPINoCredentials()
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
        if group:
            network_group = use_network_group(organization=organization, group=group)
            existing_networks = network_group.networks_by_name()
        else:
            existing_networks = organization.get_networks_by_organization()
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
            try:
                network.wait_for_statuses(["DELETING","DELETED"],wait=999,progress=False)
            except KeyboardInterrupt as e:
                cli.log.debug("wait cancelled by user")
        elif operation in ['create','read','update']:
            try:
                network.wait_for_status("PROVISIONED",wait=999,progress=False)
            except KeyboardInterrupt as e:
                cli.log.debug("wait cancelled by user")
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
