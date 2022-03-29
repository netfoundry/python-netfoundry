#!/usr/bin/env python3
r"""General-purpose command-line-interface to the NetFoundry API.

Usage::
    $ nfctl --help

PYTHON_ARGCOMPLETE_OK
"""
import argparse
import logging
import platform
import re
import sys
import tempfile
import time
from json import dumps as json_dumps
from json import load as json_load
from json import loads as json_loads
from os import environ, path
from posixpath import split as psplit
from random import choice, sample, shuffle
from re import sub
from shlex import split as shplit
from shutil import which
from subprocess import CalledProcessError

#from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from jwt.exceptions import PyJWTError
from milc import set_metadata
from packaging import version
from pygments import highlight
from pygments.formatters import Terminal256Formatter
from pygments.lexers import get_lexer_by_name
from pygments.styles import get_all_styles
from tabulate import tabulate
from yaml import dump as yaml_dumps
from yaml import full_load as yaml_loads
from yaml import parser

from ._version import get_versions
from .demo import main as nfdemo
from .exceptions import NFAPINoCredentials
from .network import Network
from .network_group import NetworkGroup
from .organization import Organization
from .utility import (MUTABLE_NETWORK_RESOURCES,
                      MUTABLE_RESOURCE_ABBREVIATIONS, RESOURCE_ABBREVIATIONS,
                      RESOURCES, is_jwt, normalize_caseless, plural, singular)

set_metadata(version="v"+get_versions()['version'], author="NetFoundry", name="nfctl") # must precend import milc.cli
import milc.subcommand.config
from milc import cli
from milc import questions


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

@cli.argument('-p','--profile', default='default', help='login profile for storing and retrieving concurrent, discrete sessions')
@cli.argument('-C', '--credentials', help='API account JSON file from web console')
@cli.argument('-O', '--organization', help="label or ID of an alternative organization (default is caller's org)" )
@cli.argument('-N', '--network', help='caseless name of the network to manage')
@cli.argument('-G', '--network-group', help="shortname or ID of a network group to search for network_name")
@cli.argument('-O','--output', arg_only=True, help="format the output", default="text", choices=['text', 'yaml','json'])
@cli.argument('-S', '--style', help="highlighting style", metavar='STYLE', default='monokai', choices=["rrt", "arduino", "monokai", "material", "one-dark", "emacs", "vim", "one-dark"])
@cli.argument('-b','--borders', default=True, action='store_boolean', help='print cell borders in text tables')
@cli.argument('-H','--headers', default=True, action='store_boolean', help='print column headers in text tables')
@cli.argument('-Y', '--yes', action='store_true', arg_only=True, help='answer yes to potentially-destructive operations')
@cli.argument('-P', '--proxy', help="like http://localhost:8080 or socks5://localhost:9046")
@cli.entrypoint('configure the CLI to manage a network')
def main(cli):
    """Configure the CLI to manage a network."""
    cli.args['login_target'] = 'organization'
    cli.args['report'] = False
    cli.args['eval'] = False
    login(cli)

@cli.argument('-r','--report', help="describe the configured organization, network-group, and network", arg_only=True, action="store_true", default=False)
@cli.argument('-e','--eval', help="source or eval output to configure shell environment with a login token", arg_only=True, action="store_true", default=False)
@cli.argument('-v','--ziti-version', help=argparse.SUPPRESS, default='0.22.0') # minium ziti CLI version supports --cli-identity and --read-only
@cli.argument('-c','--ziti-cli', help=argparse.SUPPRESS)
@cli.argument('login_target', help=argparse.SUPPRESS, arg_only=True, nargs='?', default="organization", choices=['organization', 'ziti'])
@cli.subcommand('login to a management API')
def login(cli):
    """Login to an API and cache the expiring token."""
    # if logging in to a NF org (default)
    spinner = get_spinner("working")
    if cli.args.login_target == "organization":
        spinner.text = f"Logging in profile '{cli.config.general.profile}'"
        with spinner:
            organization =  use_organization()
            if cli.config.general.network_group and cli.config.general.network:
                cli.log.debug(f"configuring network {cli.config.general.network} in group {cli.config.general.network_group}")
                network, network_group = use_network(
                    organization=organization,
                    group=cli.config.general.network_group,
                    network_name=cli.config.general.network, 
                    )
            elif cli.config.general.network:
                cli.log.debug(f"configuring network {cli.config.general.network} and local group if unique name for this organization")
                network, network_group = use_network(
                    organization=organization,
                    network_name=cli.config.general.network, 
                    )
            elif cli.config.general.network_group:
                cli.log.debug(f"configuring network group {cli.config.general.network_group}")
                network_group = use_network_group(
                    organization,
                    group=cli.config.general.network_group, 
                    )
                network = None
            else:
                cli.log.debug("not configuring network or network group")
                network, network_group = None, None

            summary_object = dict()
            summary_object['caller'] = organization.caller
            summary_object['organization'] = organization.describe
            if network_group:
                summary_object['network_group'] = network_group.describe
                summary_object['network_group']['networks_count'] = len(network_group.network_ids_by_normal_name.keys())
            if network:
                summary_object['network'] = network.describe

            # compose a summary table from selected details if text, not yaml or
            # json (unless shell which means to suppress normal output and only
            # configure the current shell)
            if not cli.args.eval:
                if cli.args.output == "text" and cli.args.report:
                    summary_table = []
                    summary_table.append(['identity', f"{summary_object['caller']['name']} ({summary_object['caller']['email']}) in {organization.label} ({organization.name})"])
                    if network_group:
                            summary_table.append(['network group', '"{fullname}" ({shortname}) \n with {count} networks'.format(
                                fullname=summary_object['network_group']['name'],
                                shortname=summary_object['network_group']['organizationShortName'],
                                count=summary_object['network_group']['networks_count']
                        )])
                    if network:
                            summary_table.append(['network', '"{fullname}" ({data_center}) \n is {version} and status {status}'.format(
                                fullname=summary_object['network']['name'],
                                data_center=summary_object['network']['region'],
                                version=summary_object['network']['productVersion'],
                                status=summary_object['network']['status']
                        )])
                    if cli.config.general.borders:
                        table_borders = "presto"
                    else:
                        table_borders = "plain"
                    table = tabulate(tabular_data=summary_table, headers=['domain', 'summary'], tablefmt=table_borders)
                    if cli.config.general.color:
                        highlighted = highlight(table, text_lexer, Terminal256Formatter(style=cli.config.general.style))
                        cli.echo(highlighted)
                    else:
                        cli.echo(table)
                        

                elif cli.args.output == "yaml":
                    if cli.config.general.color:
                        highlighted = highlight(yaml_dumps(summary_object, indent=4), yaml_lexer, Terminal256Formatter(style=cli.config.general.style))
                        cli.echo(highlighted)
                    else:
                        cli.echo(yaml_dumps(summary_object, indent=4))
                elif cli.args.output == "json":
                    if cli.config.general.color:
                        highlighted = highlight(json_dumps(summary_object, indent=4), json_lexer, Terminal256Formatter(style=cli.config.general.style))
                        cli.echo(highlighted)
                    else:
                        cli.echo(json_dumps(summary_object, indent=4))

            elif cli.args.eval:
                token_env = f"""
# $ source <(nfctl --credentials=credentials.json login --eval)
export NETFOUNDRY_API_TOKEN="{organization.token}"
{'export MOPENV='+organization.environment if organization.environment else ''}
"""
                if cli.config.general.color:
                    highlighted = highlight(token_env, bash_lexer, Terminal256Formatter(style=cli.config.general.style))
                    cli.echo(highlighted)
                else:
                    cli.echo(token_env)
            else:
                spinner.succeed(f"you are {summary_object['caller']['name']} ({summary_object['caller']['email']}) in {organization.label}")

    elif cli.args.login_target == "ziti":
        if cli.config.login.ziti_cli:
            ziti_cli = cli.config.login.ziti_cli
        else:
            if platform.system() == 'Windows':
                ziti_cli = 'ziti.exe'
            else:
                ziti_cli = 'ziti'
        which_ziti = which(ziti_cli)
        if which_ziti:
            cli.log.debug(f"found ziti CLI executable in {which_ziti}")
        else:
            cli.log.error(f"missing executable '{ziti_cli}' in PATH: {environ['PATH']}")
            exit(1)
        exec = cli.run([ziti_cli, '--version'])
        if exec.returncode == 0:
            cli.log.debug(f"found ziti CLI '{which_ziti}' version '{exec.stdout}'")
        else:
            cli.log.error(f"failed to get ziti CLI version: {exec.stderr}")
            exit(exec.returncode)
        try:
            assert(version.parse(exec.stdout) >= version.parse(cli.config.login.ziti_version))
        except AssertionError as e:
            cli.log.error(f"found ziti CLI '{which_ziti}' but version is not at least {cli.config.login.ziti_version}: {e}")
            exit(1)

        spinner.text = f"Logging in to Ziti controller management API"
        with spinner:
            organization =  use_organization()
            network, network_group = use_network(
                organization=organization,
                group=cli.config.general.network_group,
                network_name=cli.config.general.network, 
                )
            tempdir = tempfile.mkdtemp()
            network_controller = network.get_resource_by_id(type="network-controller", id=network.network_controller['id'])
            if 'domainName' in network_controller.keys() and network_controller['domainName']:
                ziti_ctrl_ip = network_controller['domainName']
            else:
                ziti_ctrl_ip = network_controller['_embedded']['host']['ipAddress']
            try:
                session = network.get_controller_session(network.network_controller['id'])
                ziti_token = session['sessionToken']
            except Exception as e:
                raise RuntimeError(f"failed to get the ziti token from session '{session or None}', got {e}")
            else:
                if cli.config.general.proxy:
                    proxies = {
                        'http': cli.config.general.proxy,
                        'https': cli.config.general.proxy
                    }
                else:
                    proxies = dict()
                ### commented because new ziti CLI has batteries-included certs trust opt-in and caching
                # well_known_response = http_get('https://'+ziti_ctrl_ip+'/.well-known/est/cacerts', proxies=proxies, verify=False)
                # well_known_decoding = b64decode(well_known_response.text)
                # well_known_certs = pkcs7.load_der_pkcs7_certificates(well_known_decoding)
                # well_known_pem = tempdir+'/well-known-certs.pem'
                # with open(well_known_pem, 'wb') as pem:
                #     for cert in well_known_certs:
                #         pem.write(cert.public_bytes(Encoding.PEM))
                network_name_safe = '_'.join(network.name.casefold().split())
                ziti_cli_identity = '-'.join([organization.environment.casefold(), organization.label.casefold(), network_group.name.casefold(), network_name_safe])
                ziti_mgmt_port = "443"
                exec = cli.run([ziti_cli, 'edge', 'login', '--read-only', '--cli-identity', ziti_cli_identity, ziti_ctrl_ip+':'+ziti_mgmt_port, '--token', ziti_token], capture_output=False)
                if exec.returncode == 0: # if succeeded
                    exec = cli.run(shplit(f"{ziti_cli} edge use {ziti_cli_identity}"), capture_output=False)
                    if not exec.returncode == 0: # if error
                        cli.log.error(f"failed to switch default ziti login identity to '{ziti_cli_identity}'")
                        exit(exec.returncode)
                else:
                    cli.log.error("failed to login")
                    exit(exec.returncode)

@cli.subcommand('logout current profile from an organization')
def logout(cli):
    """Logout by deleting the cached token."""
    spinner = get_spinner("working")
    spinner.text = f"Logging out profile '{cli.config.general.profile}'"
    # use the session with some organization, default is to use the first and there's typically only one
    try:
        with spinner:
            organization = Organization(
                profile=cli.config.general.profile,
                logout=True,
                proxy=cli.config.general.proxy
            )
    except Exception as e:
        cli.log.error(f"unexpected error while logging out profile '{cli.config.general.profile}': {e}")
        exit(1)
    else:
        spinner.succeed(sub('Logging', 'Logged', spinner.text))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[choice for group in [[singular(type),RESOURCES[type].abbreviation] for type in MUTABLE_NETWORK_RESOURCES.keys()] for choice in group])
# this allows us to pass the edit subcommand's cli object to function get without further modifying that functions params
@cli.subcommand('duplicate a resource')
def copy(cli):
    """Duplicate a single resource.
    
    Configure env var NETFOUNDRY_EDITOR or EDITOR as path to executable that
    accepts a file to edit as first positional parameter and waits for exit to
    return e.g. "code --wait".
    """
    spinner = get_spinner("working")
    if MUTABLE_RESOURCE_ABBREVIATIONS.get(cli.args.resource_type):
        cli.args.resource_type = singular(MUTABLE_RESOURCE_ABBREVIATIONS[cli.args.resource_type].name)
    spinner.text = f"Getting {cli.args.resource_type} for copying"
    cli.args['accept'] = 'create'
    cli.args['output'] = 'text' # implies tty which allows INFO messages
    with spinner:
        edit_resource_object, network, network_group, organization = get(cli, echo=False)
    cli.log.debug(f"opening {cli.args.resource_type} '{edit_resource_object['name']}' for copying")
    copy_request_object = edit_object_as_yaml(edit_resource_object)
    if not copy_request_object: # is False if editing cancelled by empty buffer
        return True
    else:
        spinner.text = f"Copying {edit_resource_object['name']} to {copy_request_object['name']}"
        with spinner:
            network.create_resource(post=copy_request_object, type=cli.args.resource_type)
        spinner.succeed(sub('Copying', 'Copied', spinner.text))

@cli.argument('-f', '--file', help='JSON or YAML file', type=argparse.FileType('r', encoding='UTF-8'))
@cli.argument('-w','--wait', help='seconds to wait for process execution to finish', default=0)
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[choice for group in [[singular(type),RESOURCES[type].abbreviation] for type in MUTABLE_NETWORK_RESOURCES.keys()] for choice in group])
@cli.subcommand('create a resource from a file')
def create(cli):
    """Create a resource.
    
    If interactive then open template or --file in EDITOR. Then
    send create request upon EDITOR exit. If not interactive then send input
    object as create request immediately.
    """
    spinner = get_spinner("working")
    if MUTABLE_RESOURCE_ABBREVIATIONS.get(cli.args.resource_type):
        cli.args.resource_type = singular(MUTABLE_RESOURCE_ABBREVIATIONS[cli.args.resource_type].name)
    # get the input object if available, else get the lines (serialized YAML or JSON) and try to deserialize
    create_input_object, create_input_lines, create_object = None, str(), None
    if sys.stdin.isatty() and not cli.args.file:
        create_input_object = MUTABLE_NETWORK_RESOURCES[plural(cli.args.resource_type)].create_template
    elif cli.args.file:
        try:
            create_input_lines = cli.args.file.read()
            cli.log.debug(f"got {len(create_input_lines)}B from file: {cli.args.file}")
        except Exception as e:
            raise RuntimeError(f"failed to read the input file: {e}")
    else:
        cli.log.error("need input file '--file=FILE'")
        exit(1)
    if not create_input_object and create_input_lines:
        try:
            create_input_object = yaml_loads(create_input_lines)
        except Exception as e:
            cli.log.debug(f"failed to parse input lines from file as YAML, trying JSON: {e}")
            try:
                create_input_object = json_loads(create_input_lines)
            except Exception as e:
                cli.log.debug(f"failed to parse input lines from file as JSON: {e}")
    if not create_input_object:
        cli.log.error("failed to parse input lines as an object (deserialized JSON or YAML)")
        exit(1)

    create_object = edit_object_as_yaml(create_input_object)

    if not create_object: # is False if editing cancelled by empty buffer
        return True

    spinner.text = f"Creating {cli.args.resource_type}"
    with spinner:
        organization =  use_organization()
        if cli.args.resource_type == "network":
            if cli.config.general.network_group:
                network_group = use_network_group(organization=organization, )
            else:
                org_count = len(organization.get_network_groups_by_organization())
                if org_count > 1:
                    cli.log.error("specify --network-group because there is more than one available to caller's identity")
                    exit(org_count)
                else: # use the only available group
                    network_group_id = organization.get_network_groups_by_organization()[0]['id']
                    network_group = use_network_group(
                        organization=organization, 
                        group=network_group_id)
            resource = network_group.create_network(**create_object)
        else:
            network, network_group = use_network(
                organization=organization,
                group=cli.config.general.network_group,
                network_name=cli.config.general.network)
            resource = network.create_resource(type=cli.args.resource_type, post=create_object, wait=cli.config.create.wait)
    spinner.succeed(f"Created {cli.args.resource_type} '{resource['name']}'")

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[choice for group in [[singular(type),RESOURCES[type].abbreviation] for type in MUTABLE_NETWORK_RESOURCES.keys()] for choice in group])
# this allows us to pass the edit subcommand's cli object to function get without further modifying that functions params
@cli.subcommand('edit a resource with EDITOR')
def edit(cli):
    """Edit a single resource as YAML.
    
    Configure env var NETFOUNDRY_EDITOR or EDITOR as path to executable that
    accepts a file to edit as first positional parameter and waits for exit to
    return e.g. "code --wait".
    """
    spinner = get_spinner("working")
    if MUTABLE_RESOURCE_ABBREVIATIONS.get(cli.args.resource_type):
        cli.args.resource_type = singular(MUTABLE_RESOURCE_ABBREVIATIONS[cli.args.resource_type].name)
    cli.args['accept'] = 'update'
    spinner.text = f"Getting {cli.args.resource_type} for editing"
    cli.log.debug(f"opening {cli.args.resource_type} '{edit_resource_object['name']}' for editing")
    with spinner:
        edit_resource_object, network, network_group, organization = get(cli, echo=False)
    update_request_object = edit_object_as_yaml(edit_resource_object)
    if not update_request_object: # is False if editing cancelled by empty buffer
        return True
    else:
        spinner.text = f"Updating {cli.args.resource_type}"
        with spinner:
            network.put_resource(put=update_request_object, type=cli.args.resource_type)
        spinner.succeed(sub("Updating", "Updated", spinner.text))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('-a', '--as', dest='accept', arg_only=True, choices=['create','update'], help="request the as=create or as=update alternative form of the resource")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[choice for group in [[singular(type),RESOURCES[type].abbreviation] for type in RESOURCES.keys()] for choice in group])
@cli.subcommand('get a single resource by query')
def get(cli, echo: bool=True, embed='all'):
    """
    Get a single resource as YAML or JSON.
    
    :param echo: output to stdout, False for CLI internal use
    :param embed: allow expensive server operations, False for quick get internal use
    """
    spinner = get_spinner("working")
    if RESOURCE_ABBREVIATIONS.get(cli.args.resource_type):
        cli.args.resource_type = singular(RESOURCE_ABBREVIATIONS[cli.args.resource_type].name)
    if not cli.config.general.verbose and cli.args.output in ["yaml","json"]: # don't change level if output=text
        cli.log.setLevel(logging.WARN) # don't emit INFO messages to stdout because they will break deserialization
    match = {}
    matches = []
    query_keys = [*cli.args.query]
    spinner.text = f"Getting {cli.args.resource_type}"
    if not echo:
        spinner.enabled = False
    with spinner:
        organization =  use_organization()
        if cli.args.resource_type == "organization":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warning(f"using 'id' only, ignoring params: '{','.join(query_keys)}'")
                match = organization.get_organization(id=cli.args.query['id'])
            else:
                matches = organization.get_organizations(**cli.args.query)
                if len(matches) == 1:
                    match = organization.get_organization(id=matches[0]['id'])
        elif cli.args.resource_type == "network-group":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warning(f"using 'id' only, ignoring params: '{','.join(query_keys)}'")
                match = organization.get_network_group(network_group_id=cli.args.query['id'])
            else:
                matches = organization.get_network_groups_by_organization(**cli.args.query)
                if len(matches) == 1:
                    match = organization.get_network_group(network_group_id=matches[0]['id'])
        elif cli.args.resource_type == "identity":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warning(f"using 'id' only, ignoring params: '{','.join(query_keys)}'")
                match = organization.get_identity(identity_id=cli.args.query['id'])
            elif not query_keys:
                match = organization.caller
            else:
                matches = organization.get_identities(**cli.args.query)
                if len(matches) == 1:
                    match = matches[0]
        elif cli.args.resource_type == "network":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warning(f"using 'id' only, ignoring params: '{','.join(query_keys)}'")
                match = organization.get_network(network_id=cli.args.query['id'], embed=embed, accept=cli.args.accept)
            else:
                if cli.config.general.network_group and not cli.config.general.network:
                    network_group = use_network_group(
                        organization, 
                        group=cli.config.general.network_group, 
                        )
                    matches = organization.get_networks_by_group(network_group.id, **cli.args.query)
                elif cli.config.general.network:
                    network, network_group = use_network(
                        organization=organization,
                        network_name=cli.config.general.network,
                        )
                    match = organization.get_network(network_id=network.id, embed=embed, accept=cli.args.accept)
                else:
                    matches = organization.get_networks_by_organization(**cli.args.query)
                if len(matches) == 1:
                    network, network_group = use_network(
                        organization=organization,
                        network_name=matches[0]['name'], 
                        )
                    match = organization.get_network(network_id=network.id, embed=embed, accept=cli.args.accept)
        else: # is a resource in the network domain
            if cli.config.general.network:
                network, network_group = use_network(
                    organization=organization,
                    group=cli.config.general.network_group, # None unless configured
                    network_name=cli.config.general.network, 
                    )
            else:
                cli.log.error("first configure a network to get resources in a network e.g. --network ACMENet")
                exit(1)
            if cli.args.resource_type == "data-center":
                if cli.args.accept:
                    cli.log.warning("'accept' param not applicable to data-centers")
                if 'id' in query_keys:
                    cli.log.warning("data centers fetched by ID may not support this network's product version, try provider or locationCode params for safety")
                    if len(query_keys) > 1:
                        query_keys.remove('id')
                        cli.log.warning(f"using 'id' only, ignoring params: '{','.join(query_keys)}'")
                    match = network.get_data_center_by_id(id=cli.args.query['id'])
                else:
                    matches = network.get_edge_router_data_centers(**cli.args.query)
                    if len(matches) == 1:
                        match = network.get_data_center_by_id(id=matches[0]['id'])
            else:
                if 'id' in query_keys:
                    if len(query_keys) > 1:
                        query_keys.remove('id')
                        cli.log.warning(f"using 'id' only, ignoring params: '{','.join(query_keys)}'")
                    match = network.get_resource_by_id(type=cli.args.resource_type, id=cli.args.query['id'], accept=cli.args.accept)
                else:
                    matches = network.get_resources(type=cli.args.resource_type, accept=cli.args.accept, **cli.args.query)
                    if len(matches) == 1:
                        match = matches[0]

    if match:
        cli.log.debug(f"found exactly one {cli.args.resource_type} by '{','.join(query_keys)}'")
        if not echo: # edit() uses echo=False to get a match for updating
            return match, network, network_group, organization
        else:
            if cli.args.keys:
                # intersection of the set of observed, present keys in the
                # match and the set of desired keys
                valid_keys = set(match.keys()) & set(cli.args.keys)
                if valid_keys: # if at least one element in intersection set
                    cli.log.debug(f"valid keys: {str(valid_keys)}")
                    filtered_match = { key: match[key] for key in match.keys() if key in valid_keys}
                else:
                    cli.log.error(f"no valid keys requested in list: {','.join(cli.args.keys)}, need at least one of {','.join(match.keys())}")
                    exit(1)
            else:
                cli.log.debug("not filtering output keys")
                filtered_match = match
            if cli.args.output in ["yaml","text"]:
                if cli.config.general.color:
                    highlighted = highlight(yaml_dumps(filtered_match, indent=4), yaml_lexer, Terminal256Formatter(style=cli.config.general.style))
                    cli.echo(highlighted)
                else:
                    cli.echo(yaml_dumps(filtered_match, indent=4))
            elif cli.args.output == "json":
                if cli.config.general.color:
                    highlighted = highlight(json_dumps(filtered_match, indent=4), json_lexer, Terminal256Formatter(style=cli.config.general.style))
                    cli.echo(highlighted)
                else:
                    cli.echo(json_dumps(filtered_match, indent=4))
    elif len(matches) == 0:
        cli.log.warning(f"found no {cli.args.resource_type} by '{','.join(query_keys)}'")
        exit(1)
    else: # len(matches) > 1:
        if cli.args.query:
            cli.log.error(f"found more than one {cli.args.resource_type} by param(s): '{','.join(query_keys)}', try a more specific query")
        else:
            cli.log.error(f"found more than one {cli.args.resource_type}, try using a query like 'name=AcmeThing%' (% is wildcard)")
        exit(len(matches))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('-a', '--as', dest='accept', arg_only=True, choices=['create','update'], help="request the as=create or as=update alternative form of the resources")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[choice for group in [[type,RESOURCES[type].abbreviation] for type in RESOURCES.keys()] for choice in group])
@cli.subcommand('find resources as lists')
def list(cli):
    """Find resources as lists."""
    spinner = get_spinner("working")
    if RESOURCE_ABBREVIATIONS.get(cli.args.resource_type):
        cli.args.resource_type = RESOURCE_ABBREVIATIONS[cli.args.resource_type].name
    if cli.args.accept and not MUTABLE_NETWORK_RESOURCES.get(cli.args.resource_type):
        cli.log.warn("the --as=ACCEPT param is not applicable to resources outside the network domain")
    if cli.args.output == "text":
        if not sys.stdout.isatty():
            cli.log.warning("{fg_yello}nfctl does not have a stable CLI interface. Use with caution in scripts. Please raise a GitHub issue if that's something you would value.")
    else: # output is YAML or JSON
        # don't emit INFO messages to stdout because they will break deserialization
        cli.log.setLevel(logging.WARN)
    query_keys = [*cli.args.query]
    if cli.args.query:
        spinner.text = f"Finding {cli.args.resource_type} {'by' if query_keys else '...'} {','.join(query_keys)}"
    else:
        spinner.text = f"Finding all {cli.args.resource_type}"
    with spinner:
        organization =  use_organization()
        if cli.args.resource_type == "organizations":
            matches = organization.get_organizations(**cli.args.query)
        elif cli.args.resource_type == "network-groups":
            matches = organization.get_network_groups_by_organization(**cli.args.query)
        elif cli.args.resource_type == "identities":
            matches = organization.get_identities(**cli.args.query)
        elif cli.args.resource_type == "networks":
            if cli.config.general.network_group:
                network_group = use_network_group(
                    organization, 
                    group=cli.config.general.network_group, 
                    )
                matches = organization.get_networks_by_group(network_group.id, accept=cli.args.accept, **cli.args.query)
            else:
                matches = organization.get_networks_by_organization(accept=cli.args.accept, **cli.args.query)
        else:
            if cli.config.general.network:
                network, network_group = use_network(
                    organization=organization,
                    group=cli.config.general.network_group, # None unless configured
                    network_name=cli.config.general.network, 
                    )
            else:
                cli.log.error("first configure a network to list resources in a network e.g. --network ACMENet")
                exit(1)
            if cli.args.resource_type == "data-centers":
                matches = network.get_edge_router_data_centers(**cli.args.query)
            else:
                matches = network.get_resources(type=cli.args.resource_type, accept=cli.args.accept, **cli.args.query)

    if len(matches) == 0:
        spinner.fail(f"found zero {cli.args.resource_type} by '{','.join(query_keys)}'")
        exit(0)
    else:
        cli.log.debug(f"found at least one {cli.args.resource_type} by '{','.join(query_keys)}'")

    valid_keys = set()
    if cli.args.keys:
        # intersection of the set of valid, observed keys in the first match
        # and the set of configured, desired keys
        valid_keys = set(matches[0].keys()) & set(cli.args.keys)
    elif cli.args.output == "text":
        valid_keys = set(matches[0].keys()) & set(['name','label','organizationShortName','id','edgeRouterAttributes','serviceAttributes','endpointAttributes','status','zitiId','provider','locationCode','ipAddress','region','size','attributes','email','productVersion'])

    if valid_keys:
        cli.log.debug(f"valid keys: {str(valid_keys)}")
        filtered_matches = []
        for match in matches:
            filtered_match = { key: match[key] for key in match.keys() if key in valid_keys}
            filtered_matches.append(filtered_match)
    else:
        cli.log.debug("not filtering output keys")
        filtered_matches = matches

    if cli.args.output == "text":
        if cli.config.general.headers:
            table_headers = filtered_matches[0].keys()
        else:
            table_headers = []
        if cli.config.general.borders:
            table_borders = "presto"
        else:
            table_borders = "plain"
        table = tabulate(tabular_data=[match.values() for match in filtered_matches], headers=table_headers, tablefmt=table_borders)
        if cli.config.general.color:
            highlighted = highlight(table, text_lexer, Terminal256Formatter(style=cli.config.general.style))
            cli.echo(highlighted)
        else:
            cli.echo(table)
    elif cli.args.output == "yaml":
        if cli.config.general.color:
            highlighted = highlight(yaml_dumps(filtered_matches, indent=4), yaml_lexer, Terminal256Formatter(style=cli.config.general.style))
            cli.echo(highlighted)
        else:
            cli.echo(yaml_dumps(filtered_matches, indent=4))
    elif cli.args.output == "json":
        if cli.config.general.color:
            highlighted = highlight(json_dumps(filtered_matches, indent=4), json_lexer, Terminal256Formatter(style=cli.config.general.style))
            cli.echo(highlighted)
        else:
            cli.echo(json_dumps(filtered_matches, indent=4))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[choice for group in [[singular(type),RESOURCES[type].abbreviation] for type in RESOURCES.keys()] for choice in group])
@cli.argument('-w','--wait', help='seconds to wait', default=0)
@cli.subcommand('delete a resource in the network domain')
def delete(cli):
    """Delete a resource in the network domain."""
    spinner = get_spinner("working")
    query_keys = [*cli.args.query]
    if MUTABLE_RESOURCE_ABBREVIATIONS.get(cli.args.resource_type):
        cli.args.resource_type = singular(MUTABLE_RESOURCE_ABBREVIATIONS[cli.args.resource_type].name)
    cli.args['accept'] = None
    spinner.text = f"Finding {cli.args.resource_type} {'by' if query_keys else '...'} {','.join(query_keys)}"
    with spinner:
        match, network, network_group, organization = get(cli, echo=False, embed=None)
    if cli.args.resource_type == 'network':
        try:
            delete_confirmed = False
            if cli.args.yes:
                delete_confirmed = True
            else:
                scrambled = []
                for i in range(4):
                    scrambled.extend([''.join(sample(network.name, len(match['name'])))])
                scrambled.extend([match['name']])
                shuffle(scrambled)
                descrambled = questions.choice("{style_bright}Enter the number of the unscrambled {fg_yellow}network{fg_reset} name to {fg_red}IRREVERSIBLY DELETE", scrambled, default=None, confirm=True, prompt='{style_bright}{fg_red}DELETE{fg_reset} which {fg_yellow}network? ')
                if match['name'] == descrambled:
                    delete_confirmed = True

            if delete_confirmed:
                spinner.text = f"Deleting network '{match['name']}'"
                try:
                    with spinner:
                        network.delete_network(progress=False, wait=cli.config.delete.wait)
                except Exception as e:
                    cli.log.error(f"unknown error deleting network, got {e}")
                    exit(1)
                else:
                    spinner.succeed(sub('Deleting', 'Deleted', spinner.text))
            else:
                spinner.fail(f"Not deleting network '{match['name']}'.")
        except KeyboardInterrupt as e:
            spinner.fail("Cancelled")
            exit(1)
        except Exception as e:
            cli.log.error(f"unknown error in {e}")
            exit(1)
    else: # network child resource, not the network itself
        try:
            if cli.args.yes or questions.yesno("{style_bright}{fg_red}IRREVERSIBLY DELETE{fg_yellow} "+cli.args.resource_type+" {fg_cyan}"+match['name']+" {fg_reset}", default=False):
                spinner.text = f"Deleting {cli.args.resource_type} '{match['name'] or match['id']}'"
                try:
                    with spinner:
                        network.delete_resource(type=cli.args.resource_type, id=match['id'])
                except KeyboardInterrupt as e:
                    spinner.fail("Cancelled")
                    exit(1)
                except Exception as e:
                    cli.log.error(f"unknown error in {e}")
                    exit(1)
                else:
                    spinner.succeed(sub('Deleting', 'Deleted', spinner.text))
            else:
                spinner.fail(f"Not deleting {cli.args.resource_type} '{match['name']}'")
        except KeyboardInterrupt as e:
            spinner.fail("Cancelled")
            exit(1)
        except Exception as e:
            cli.log.error(f"unknown error in {e}")
            exit(1)

@cli.subcommand('create a functioning demo network')
def demo(cli):
    """Create a functioning demo network."""
    spinner = get_spinner("working")
    spinner.text = "Checking credentials"
    with spinner:
        organization =  use_organization()
    if cli.config.general.network:
        network_name = cli.config.general.network
    else:
        resources_dir = path.join(path.dirname(__file__), 'resources')
        friendly_words_filename = path.join(resources_dir, "friendly-words/generated/words.json")
        with open(friendly_words_filename, 'r') as friendly_words_path:
            friendly_words = json_load(friendly_words_path)
        network_name = f"{choice(friendly_words['predicates'])}-{choice(friendly_words['objects'])}"
    demo_params = ['--network', network_name]
    if cli.config.general.proxy:
        demo_params.extend(['--proxy', cli.config.general.proxy])
    if cli.args.yes or questions.yesno(f"Create demo resources in network {network_name} ({organization.label}) now?"):
        try:
            nfdemo(demo_params)
        except Exception as e:
            raise RuntimeError(f"unknown problem while running the demo")
        else:
            spinner.succeed("Demo network is ready")
    else:
        spinner.fail("Demo cancelled")
        cli.log.info(f"You may access the full demo with more flexible options by running it directly: \n\n$ nfdemo --help")
        cli.run(command=["nfdemo", "--help"], capture_output=False)

def use_organization(prompt: bool=True):
    """Cache an expiring token for your identity in organization."""
    spinner = get_spinner("working")
    spinner.text = f"Loading profile '{cli.config.general.profile}'"
    # use the session with some organization, default is to use the first and there's typically only one
    try:
        with spinner:
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
                token_from_prompt = questions.password(prompt='Enter Bearer Token:', confirm=False, validate=is_jwt)
            except KeyboardInterrupt as e:
                spinner.fail("Cancelled")
                exit(1)
            except Exception as e:
                cli.log.error(f"unknown error in {e}")
                exit(1)

            try:
                spinner.text = "Trying token for profile '{:s}'".format(cli.config.general.profile)
                with spinner:
                    organization = Organization(
                        token=token_from_prompt,
                        organization=cli.config.general.organization if cli.config.general.organization else None,
                        profile=cli.config.general.profile,
                        expiry_minimum=0,
                        proxy=cli.config.general.proxy
                    )
            except PyJWTError as e:
                spinner.fail("Not a valid token")
                exit(1)
            except Exception as e:
                raise RuntimeError(f"unknown error in {e}")
        else:
            spinner.fail("Not logged in")
            raise NFAPINoCredentials()
    spinner.succeed(f"Logged in profile '{cli.config.general.profile}'")
    cli.log.debug(f"logged-in organization label is {organization.label}.")
    return organization

def use_network_group(organization: object, group: str=None):
    """
    Use a network group.

    :param spinner: the spinner object from parent flow is used and returned
    :param organization: the netfoundry.Organization object representing the current session
    :param str group: name or UUIDv4 of group to use
    """
    spinner = get_spinner("working")
    # module will use first available group if not specified, and typically there is only one
    spinner.text = f"Configuring network group {group}"
    network_group = NetworkGroup(
        organization,
        group=group if group else None,
    )
    spinner.succeed(f"Configured network group {network_group.name}")
    cli.log.debug(f"network group is {network_group.name}")
    return network_group

def use_network(organization: object, network_name: str=None, group: str=None):
    """
    Use a network.
    
    :param spinner: the spinner object from parent flow is used and returned
    :param organization: the netfoundry.Organization object representing the current session
    :param network_name: name of the network to use, optional if there's only one
    :param group: a network group name or UUID, optional if network name is unique across all available groups
    """
    spinner = get_spinner("working")
    if not network_name:
        spinner.text = f"Finding networks"
        if group:
            network_group = use_network_group(
                organization=organization, 
                group=group)
            existing_networks = network_group.networks_by_name()
        else:
            existing_networks = organization.get_networks_by_organization()
        if len(existing_networks) == 1:
            network_name = existing_networks[0]['name']

            cli.log.debug(f"using the only available network: '{network_name}'")
        else:
            cli.log.error("You have multiple networks, which one would you like to use? Need 'nfctl --network=NETWORK' or 'nfctl config.general.network=NETWORK'.")
            exit(1)
    elif group:
        network_group = use_network_group(
            organization=organization, 
            group=group)
        existing_networks = network_group.network_ids_by_normal_name
        if not existing_networks.get(normalize_caseless(network_name)):
            cli.log.error(f"failed to find a network named '{network_name}' in network group '{network_group['name']}'.")
            exit(1)
    else:
        existing_count = organization.count_networks_with_name(network_name)
        if existing_count == 1:
            existing_networks = organization.get_networks_by_organization(name=network_name)
            existing_network = existing_networks[0]
            network_group = use_network_group(
                organization, 
                group=existing_network['networkGroupId'])
        elif existing_count > 1:
            cli.log.error(f"there were {existing_count} networks named '{network_name}' visible to your identity. Try narrowing the search with '--network-group=NETWORK_GROUP'.")
            exit(1)
        else:
            cli.log.error(f"failed to find a network named '{network_name}'.")
            exit(1)

    # use the Network
    network = Network(network_group, network_name=network_name)
    if network.status == 'ERROR':
        cli.log.error(f"network {network.name} has status ERROR")
    elif not cli.config.delete.wait:
        cli.log.debug("delete command is configured to not wait for a healthy status")
    elif not network.status == 'PROVISIONED':
        try:
            spinner.text = f"Waiting for network {network.name} to progress from status {network.status} to PROVISIONED"
            network.wait_for_status("PROVISIONED",wait=999,progress=False)
        except KeyboardInterrupt as e:
            spinner.fail("Cancelled")
            exit(1)
        except Exception as e:
            raise RuntimeError(f"unknown error in {e}")
        else:
            spinner.succeed(f"Network '{network_name}' is ready")

    return network, network_group

def edit_object_as_yaml(edit: object):
    """Edit a resource object as YAML and return as object upon exit.
    
    :param obj input: a deserialized (object) to edit and return as yaml
    """
    # unless --yes (config general.yes), if stdout is connected to a terminal
    # then open input for editing and send on exit
    if cli.args.yes or not sys.stdout.isatty():
        return edit
    save_error = False
    editor = environ.get('NETFOUNDRY_EDITOR',environ.get('EDITOR','vim'))
    instructions_bytes = "# save and exit this editor to confirm, or\n#  abort by saving an empty file, comments ignored\n".encode()
    edit_bytes = yaml_dumps(edit, default_flow_style=False).encode()
    with tempfile.NamedTemporaryFile(suffix=".yml", delete=False) as tf:
        temp_file = tf.name
        tf.write(instructions_bytes + edit_bytes)
        tf.flush()
        completed = cli.run(command=editor.split()+[tf.name], capture_output=False)
        tf.seek(0)
        edited = tf.read().decode("utf-8")
    try:
        completed.check_returncode()
    except CalledProcessError:
        cli.log.error(f"editor returned an error: '{completed.stdout}'")
        save_error = True
    else:
        cli.log.debug(f"editor returned without error: '{completed.stdout}'")
        # prune comments from buffer
        edited_no_comments = str()
        for line in edited.splitlines():
            edited_no_comments += re.sub('^(\s+)?#.*','',line)
        if len(edited_no_comments) == 0:
            return False
        else:
            try:
                edited_object = yaml_loads(edited)
            except parser.ParserError as e:
                cli.log.error(f"invalid YAML or JSON: {e}")
                save_error = True
            except Exception as e:
                cli.log.error(f"unknown error in {e}")
                save_error = True
            else:
                return edited_object
    if save_error:
        cli.log.error(f"your buffer was saved and you may continue editing it  'create TYPE --file {temp_file}'")
        exit(1)

def get_spinner(text):
    """
    Get a spinner.
    
    Enabled if stdout is a tty and log level is >= INFO, else disabled to not
    corrupt structured output.
    """
    inner_spinner = cli.spinner(text=text, spinner='dots12', placement='left', color='green', stream=sys.stderr)
    if not sys.stdout.isatty() or ('eval' in dir(cli.args) and cli.args.eval):
        inner_spinner.enabled = False
        cli.log.debug("spinner disabled because stdout is not a tty")
    elif cli.config.general.verbose:
        inner_spinner.enabled = False
        cli.log.debug("spinner disabled because DEBUG is enabled")
    else:
        inner_spinner.enabled = True
        cli.log.debug("spinner enabled because stdout is a tty and DEBUG is not enabled")
    return inner_spinner

yaml_lexer = get_lexer_by_name("yaml", stripall=True)
json_lexer = get_lexer_by_name("json", stripall=True)
bash_lexer = get_lexer_by_name("bash", stripall=True)
text_lexer = get_lexer_by_name("Mscgen", stripall=True)


if __name__ == '__main__':
    cli()
