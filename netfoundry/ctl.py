#!/usr/bin/env python3
r"""General-purpose command-line-interface to the NetFoundry API.

Usage::
    $ nfctl --help

PYTHON_ARGCOMPLETE_OK
"""
import argparse
import logging
import os
import platform
import random
import re
import sys
import tempfile
import time
from json import dumps as json_dumps
from json import loads as json_loads
from posixpath import split
from re import sub
from shlex import split
from shutil import which
from subprocess import CalledProcessError

#from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from jwt.exceptions import PyJWTError
from milc import set_metadata
from nanoid import non_secure_generate
from packaging import version
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
from .utility import (MUTABLE_NETWORK_RESOURCES, NETWORK_RESOURCES, RESOURCES,
                      is_jwt, normalize_caseless, plural, singular)

set_metadata(version="v"+get_versions()['version'], author="NetFoundry", name="nfctl") # must precend import milc.cli
from milc import cli, questions
import milc.subcommand.config


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
@cli.argument('-C', '-credentials', help='API account JSON file from web console')
@cli.argument('-O', '--organization', help="label or ID of an alternative organization (default is caller's org)" )
@cli.argument('-N', '--network', help='caseless name of the network to manage')
@cli.argument('-G', '--network-group', help="shortname or ID of a network group to search for network_name")
@cli.argument('-O','--output', arg_only=True, help="format the output", default="text", choices=['text', 'yaml','json'])
@cli.argument('-b','--borders', default=True, action='store_boolean', help='print cell borders in text tables')
@cli.argument('-H','--headers', default=True, action='store_boolean', help='print column headers in text tables')
@cli.argument('-Y', '--yes', action='store_true', arg_only=True, help='answer yes to potentially-destructive operations')
@cli.argument('-P', '--proxy', help="like http://localhost:8080 or socks5://localhost:9046")
@cli.entrypoint('configure the CLI to manage a network')
def main(cli):
    """Configure the CLI to manage a network."""
    cli.args['login_target'] = 'organization'
    cli.args['full_summary'] = False
    cli.args['shell'] = False
    login(cli)

@cli.argument('-F','--full', dest='full_summary', help="describe the configured organization, network-group, and network", arg_only=True, action="store_true", default=False)
@cli.argument('-s','--shell', help="only print a shell source script for configuring the parent shell with a token", arg_only=True, action="store_true", default=False)
@cli.argument('-O','--output', arg_only=True, help="format the output", default="text", choices=['text', 'yaml','json'])
@cli.argument('-v','--ziti-version', help=argparse.SUPPRESS, default='0.22.0') # minium ziti CLI version supports --cli-identity and --read-only
@cli.argument('-c','--ziti-cli', help=argparse.SUPPRESS)
@cli.argument('login_target', help=argparse.SUPPRESS, arg_only=True, nargs='?', default="organization", choices=['organization', 'ziti'])
@cli.subcommand('login to a management API')
def login(cli):
    """Login to an API and cache the expiring token."""
    # if logging in to a NF org (default)
    if cli.args.login_target == "organization":
        spinner = get_spinner(f"Logging in profile {cli.config.general.profile}")
        with spinner:
            organization = use_organization()
            if cli.config.general.network_group and cli.config.general.network:
                cli.log.debug(f"configuring network {cli.config.general.network} in group {cli.config.general.network_group}")
                network, network_group = use_network(
                    organization=organization,
                    group=cli.config.general.network_group,
                    network_name=cli.config.general.network
                )
            elif cli.config.general.network:
                cli.log.debug(f"configuring network {cli.config.general.network} and local group if unique name for this organization")
                network, network_group = use_network(
                    organization=organization,
                    network_name=cli.config.general.network
                )
            elif cli.config.general.network_group:
                cli.log.debug(f"configuring network group {cli.config.general.network_group}")
                network_group = use_network_group(organization, group=cli.config.general.network_group)
                network = None
            else:
                cli.log.debug("not configuring network or network group")
                network, network_group = None, None

            summary_object = dict()
            summary_object['caller'] = organization.caller
            summary_object['organization'] = organization.describe
            if network_group:
                summary_object['network_group'] = network_group.describe
                summary_object['network_group']['networks_count'] = len(network_group.networks_by_normal_name().keys())
            if network:
                summary_object['network'] = network.describe

            # compose a summary table from selected details if text, not yaml or
            # json (unless shell which means to suppress normal output and only
            # configure the current shell)
            if cli.args.full_summary and not cli.args.shell:
                if cli.args.output == "text":
                    summary_table = []
                    summary_table.append(['organization', 'logged in to "{org_name}" ({org_label}@{env}) \nas {fullname} ({email}) \nuntil {expiry_timestamp} (T-{expiry_seconds}s)'.format(
                            fullname=summary_object['caller']['name'],
                            email=summary_object['caller']['email'],
                            org_label=organization.label,
                            org_name=organization.name,
                            env=organization.environment,
                            expiry_timestamp=time.strftime('%H:%M GMT%z', time.localtime(organization.expiry)),
                            expiry_seconds=int(organization.expiry_seconds)
                        )])
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
                    cli.echo(
                        '{fg_lightgreen_ex}'
                        +tabulate(tabular_data=summary_table, headers=['domain', 'summary'], tablefmt=table_borders)
                    )

                elif cli.args.full_summary and not cli.args.shell and cli.args.output == "yaml":
                    cli.echo(
                        '{fg_lightgreen_ex}'
                        +yaml_dumps(summary_object, indent=4)
                    )
                elif cli.args.full_summary and not cli.args.shell and cli.args.output == "json":
                    cli.echo(
                        '{fg_lightgreen_ex}'
                        +json_dumps(summary_object, indent=4)
                    )

            elif cli.args.shell:
                cli.echo(
                    f"""
# $ source <(nfctl --credentials credentials.json login organization)
export NETFOUNDRY_API_TOKEN="{organization.token}"
export MOPENV={organization.environment}
""")
            else:
                cli.log.info('logged in to "{org_name}" ({org_label}@{env}) as {fullname} ({email}) until {expiry_timestamp} (T-{expiry_seconds}s)'.format(
                            fullname=summary_object['caller']['name'],
                            email=summary_object['caller']['email'],
                            org_label=organization.label,
                            org_name=organization.name,
                            env=organization.environment,
                            expiry_timestamp=time.strftime('%H:%M GMT%z', time.localtime(organization.expiry)),
                            expiry_seconds=int(organization.expiry_seconds)
                ))

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
            cli.log.critical(f"missing executable '{ziti_cli}' in PATH: {os.environ['PATH']}")
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

        spinner = get_spinner(f"Logging in to Ziti controller management API")
        with spinner:
            organization = use_organization()
            network, network_group = use_network(
                organization=organization,
                group=cli.config.general.network_group,
                network_name=cli.config.general.network
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
                    exec = cli.run(f"{ziti_cli} edge use {ziti_cli_identity}".shutil.split(), capture_output=False)
                    if not exec.returncode == 0: # if error
                        cli.log.error(f"failed to switch default ziti login identity to '{ziti_cli_identity}'")
                        exit(exec.returncode)
                else:
                    cli.log.error("failed to login")
                    exit(exec.returncode)

@cli.subcommand('logout current profile from an organization')
def logout(cli):
    """Logout by deleting the cached token."""
    spinner = get_spinner(f"Logging out profile '{cli.config.general.profile}'")
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
    else:
        cli.log.info(sub('Logging', 'Logged', spinner.text))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[singular(type) for type in MUTABLE_NETWORK_RESOURCES.keys()])
# this allows us to pass the edit subcommand's cli object to function get without further modifying that functions params
@cli.subcommand('edit a single resource selected by query with editor defined in NETFOUNDRY_EDITOR or EDITOR')
def copy(cli):
    """Duplicate a single resource.
    
    Configure env var NETFOUNDRY_EDITOR or EDITOR as path to executable that
    accepts a file to edit as first positional parameter and waits for exit to
    return e.g. "code --wait".
    """
    spinner = get_spinner(f"Getting {cli.args.resource_type} for copying")
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
        cli.log.info(sub('Copying', 'Copied', spinner.text))

@cli.argument('-f', '--file', help='JSON or YAML file', type=argparse.FileType('r', encoding='UTF-8'))
@cli.argument('-w','--wait', help='seconds to wait for process execution to finish', default=0)
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[singular(type) for type in MUTABLE_NETWORK_RESOURCES.keys()])
@cli.subcommand('create a resource from a file')
def create(cli):
    """Create a resource.
    
    If interactive then open template or --file in EDITOR. Then
    send create request upon EDITOR exit. If not interactive then send input
    object as create request immediately.
    """
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
        cli.log.warning("you may input from a file with --file")
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

    spinner = get_spinner(f"Creating {cli.args.resource_type}")
    with spinner:
        organization = use_organization()
        if cli.args.resource_type == "network":
            if cli.config.general.network_group:
                network_group = use_network_group(organization=organization)
            else:
                org_count = len(organization.get_network_groups_by_organization())
                if org_count > 1:
                    cli.log.error("specify --network-group because there is more than one available to caller's identity")
                    exit(org_count)
                else: # use the only available group
                    network_group_id = organization.get_network_groups_by_organization()[0]['id']
                    network_group = use_network_group(organization=organization, group=network_group_id)
            resource = network_group.create_network(**create_object)
        else:
            network, network_group = use_network(
                organization=organization,
                group=cli.config.general.network_group,
                network_name=cli.config.general.network
            )
            resource = network.create_resource(type=cli.args.resource_type, post=create_object, wait=cli.config.create.wait)
    cli.log.info(f"Created {cli.args.resource_type} '{resource['name']}'")

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[singular(type) for type in MUTABLE_NETWORK_RESOURCES.keys()])
# this allows us to pass the edit subcommand's cli object to function get without further modifying that functions params
@cli.subcommand('edit a single resource selected by query with editor defined in NETFOUNDRY_EDITOR or EDITOR')
def edit(cli):
    """Edit a single resource as YAML.
    
    Configure env var NETFOUNDRY_EDITOR or EDITOR as path to executable that
    accepts a file to edit as first positional parameter and waits for exit to
    return e.g. "code --wait".
    """
    cli.args['accept'] = 'update'
    spinner = get_spinner(f"Getting {cli.args.resource_type} for editing")
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
        cli.log.info(sub("Updating", "Updated", spinner.text))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('-O','--output', arg_only=True, help="format the output", default="yaml", choices=['text', 'yaml','json'])
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('-a', '--as', dest='accept', arg_only=True, choices=['create','update'], help="request the as=create or as=update form of the resource")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[singular(type) for type in RESOURCES.keys()])
@cli.subcommand('get a single resource by query')
def get(cli, echo: bool=True, embed='all'):
    """
    Get a single resource as YAML or JSON.
    
    :param echo: output to stdout, False for CLI internal use
    :param embed: allow expensive server operations, False for quick get internal use
    """
    if not cli.config.general.verbose and cli.args.output in ["yaml","json"]: # don't change level if output=text
        cli.log.setLevel(logging.WARN) # don't emit INFO messages to stdout because they will break deserialization
    match = {}
    matches = []
    query_keys = [*cli.args.query]
    spinner = get_spinner(f"Getting {cli.args.resource_type}")
    if not echo:
        spinner.enabled = False
    with spinner:
        organization = use_organization()
        if cli.args.resource_type == "organization":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warning(f"using 'id' only, ignoring query params: '{','.join(query_keys)}'")
                match = organization.get_organization(id=cli.args.query['id'])
            else:
                matches = organization.get_organizations(**cli.args.query)
                if len(matches) == 1:
                    match = organization.get_organization(id=matches[0]['id'])
        elif cli.args.resource_type == "network-group":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warning(f"using 'id' only, ignoring query params: '{','.join(query_keys)}'")
                match = organization.get_network_group(network_group_id=cli.args.query['id'])
            else:
                matches = organization.get_network_groups_by_organization(**cli.args.query)
                if len(matches) == 1:
                    match = organization.get_network_group(network_group_id=matches[0]['id'])
        elif cli.args.resource_type == "identity":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warning(f"using 'id' only, ignoring query params: '{','.join(query_keys)}'")
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
                    cli.log.warning(f"using 'id' only, ignoring query params: '{','.join(query_keys)}'")
                match = organization.get_network(network_id=cli.args.query['id'], embed=embed, accept=cli.args.accept)
            else:
                if cli.config.general.network_group and not cli.config.general.network:
                    network_group = use_network_group(organization, group=cli.config.general.network_group)
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
                        network_name=matches[0]['name']
                    )
                    match = organization.get_network(network_id=network.id, embed=embed, accept=cli.args.accept)
        else: # is a resource in the network domain
            if cli.config.general.network:
                network, network_group = use_network(
                    organization=organization,
                    group=cli.config.general.network_group, # None unless configured
                    network_name=cli.config.general.network
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
                        cli.log.warning(f"using 'id' only, ignoring query params: '{','.join(query_keys)}'")
                    match = network.get_data_center_by_id(id=cli.args.query['id'])
                else:
                    matches = network.get_edge_router_data_centers(**cli.args.query)
                    if len(matches) == 1:
                        match = network.get_data_center_by_id(id=matches[0]['id'])
            else:
                if 'id' in query_keys:
                    if len(query_keys) > 1:
                        query_keys.remove('id')
                        cli.log.warning(f"using 'id' only, ignoring query params: '{','.join(query_keys)}'")
                    match = network.get_resource_by_id(type=cli.args.resource_type, id=cli.args.query['id'], accept=cli.args.accept)
                else:
                    matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)
                    if len(matches) == 1:
                        match = network.get_resource_by_id(type=cli.args.resource_type, id=matches[0]['id'], accept=cli.args.accept)

    if match:
        cli.log.debug(f"found exactly one {cli.args.resource_type} '{cli.args.query}'")
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
                cli.echo('{fg_lightgreen_ex}'+yaml_dumps(filtered_match, indent=4, default_flow_style=False))
            elif cli.args.output == "json":
                cli.echo(json_dumps(filtered_match, indent=4))
    elif len(matches) == 0:
        cli.log.warning(f"found no {cli.args.resource_type} '{cli.args.query}'")
        exit(1)
    else: # len(matches) > 1:
        cli.log.error(f"found more than one {cli.args.resource_type} '{cli.args.query}'")
        exit(len(matches))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('-O','--output', arg_only=True, help="format the output", default="text", choices=['text', 'yaml','json'])
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[type for type in RESOURCES.keys()])
@cli.subcommand('find resources as lists')
def list(cli):
    """Find resources as lists."""
    if cli.args.output == "text":
        if not sys.stdout.isatty():
            cli.log.warning("nfctl does not have a stable CLI interface. Use with caution in scripts.")
    else: # output is YAML or JSON
        # don't emit INFO messages to stdout because they will break deserialization
        cli.log.setLevel(logging.WARN)

    organization = use_organization()
    if cli.args.query:
        spinner = get_spinner(f"Finding {cli.args.resource_type} by {str(cli.args.query)}")
    else:
        spinner = get_spinner(f"Finding all {cli.args.resource_type}")
    if cli.args.resource_type == "organizations":
        with spinner:
            matches = organization.get_organizations(**cli.args.query)
    elif cli.args.resource_type == "network-groups":
        with spinner:
            matches = organization.get_network_groups_by_organization(**cli.args.query)
    elif cli.args.resource_type == "identities":
        with spinner:
            matches = organization.get_identities(**cli.args.query)
    elif cli.args.resource_type == "networks":
        if cli.config.general.network_group:
            with spinner:
                network_group = use_network_group(organization, group=cli.config.general.network_group)
                matches = organization.get_networks_by_group(network_group.id, **cli.args.query)
        else:
            with spinner:
                matches = organization.get_networks_by_organization(**cli.args.query)
    else:
        if cli.config.general.network:
            network, network_group = use_network(
                organization=organization,
                group=cli.config.general.network_group, # None unless configured
                network_name=cli.config.general.network
            )
        else:
            cli.log.error("first configure a network to list resources in a network e.g. --network ACMENet")
            exit(1)
        if cli.args.resource_type == "data-centers":
            with spinner:
                matches = network.get_edge_router_data_centers(**cli.args.query)
        else:
            with spinner:
                matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)

    if len(matches) == 0:
        cli.log.info(f"found no {cli.args.resource_type} '{cli.args.query}'")
        exit(0)
    else:
        cli.log.debug(f"found at least one {cli.args.resource_type} '{cli.args.query}'")

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
        cli.echo(
            '{fg_lightgreen_ex}'
            +tabulate(tabular_data=[match.values() for match in filtered_matches], headers=table_headers, tablefmt=table_borders)
        )
    elif cli.args.output == "yaml":
        cli.echo(yaml_dumps(filtered_matches, indent=4, default_flow_style=False))
    elif cli.args.output == "json":
        cli.echo(json_dumps(filtered_matches, indent=4))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE", choices=[singular(type) for type in MUTABLE_NETWORK_RESOURCES.keys()])
@cli.argument('-w','--wait', help='seconds to wait for completion of delete', default=0)
@cli.subcommand('delete a resource in the network domain')
def delete(cli):
    """Delete a resource in the network domain."""
    cli.args['accept'] = None
    match, network, network_group, organization = get(cli, echo=False, embed=None)
    if cli.args.resource_type == 'network':
        try:
            delete_confirmed = False
            if cli.args.yes:
                delete_confirmed = True
            else:
                scrambled = []
                for i in range(4):
                    scrambled.extend([''.join(random.sample(network.name, len(match['name'])))])
                scrambled.extend([match['name']])
                random.shuffle(scrambled)
                descrambled = questions.choice("{style_bright}Enter the number of the unscrambled {fg_yellow}network{fg_reset} name to {fg_red}IRREVERSIBLY DELETE", scrambled, default=None, confirm=True, prompt='{style_bright}{fg_red}DELETE{fg_reset} which {fg_yellow}network? ')
                if match['name'] == descrambled:
                    delete_confirmed = True

            if delete_confirmed:
                spinner = get_spinner(f"deleting network '{match['name']}'")
                try:
                    with spinner:
                        network.delete_network(progress=False, wait=cli.config.delete.wait)
                except KeyboardInterrupt as e:
                    cli.log.info("Cancelled")
                    exit(1)
                except Exception as e:
                    cli.log.error(f"unknown error in {e}")
                    exit(1)
                else:
                    cli.log.info(sub('deleting', 'deleted', spinner.text))
            else:
                cli.echo(f"not deleting network '{match['name']}'.")
        except KeyboardInterrupt as e:
            cli.log.info("Cancelled")
            exit(1)
        except Exception as e:
            cli.log.error(f"unknown error in {e}")
            exit(1)
    else: # network child resource, not the network itself
        try:
            if cli.args.yes or questions.yesno("{warn_color}IRREVERSIBLY DELETE {type_color}{type} {name_color}'{name}'{fg_reset}".format(warn_color='{style_bright}{fg_red}', type_color='{fg_yellow}', type=cli.args.resource_type, name_color='{fg_cyan}', name=match['name'], fg_reset='{fg_reset}'), default=False):
                spinner = get_spinner(f"deleting {cli.args.resource_type} '{match['name'] or match['id']}'")
                try:
                    with spinner:
                        network.delete_resource(type=cli.args.resource_type, id=match['id'])
                except KeyboardInterrupt as e:
                    cli.log.info("Cancelled")
                    exit(1)
                except Exception as e:
                    cli.log.error(f"unknown error in {e}")
                    exit(1)
                else:
                    cli.log.info(sub('deleting', 'deleted', spinner.text))
            else:
                cli.echo("not deleting {type} '{name}'".format(type=cli.args.resource_type, name=match['name']))
        except KeyboardInterrupt as e:
            cli.log.info("Cancelled")
            exit(1)
        except Exception as e:
            cli.log.error(f"unknown error in {e}")
            exit(1)

@cli.subcommand('create a functioning demo network')
def demo(cli):
    """Create a functioning demo network."""
    use_organization()
    if cli.config.general.network:
        network_name = cli.config.general.network
    else:
        network_name = f'BibbidiBobbidiBoo{non_secure_generate("1234567890abcdef", 5)}'
    demo_params = ['--network', network_name]
    if cli.config.general.proxy:
        demo_params.extend(['--proxy', cli.config.general.proxy])
    nfdemo(demo_params)


def use_organization(prompt: bool=True):
    """Assume an identity in an organization."""
    if cli.config.general.credentials:
        cli.log.debug(f"will use credentials file {cli.config.general.credentials} from config or args to renew token")
    elif 'NETFOUNDRY_API_TOKEN' in os.environ:
        cli.log.debug("using bearer token from environment NETFOUNDRY_API_TOKEN")
    elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
        cli.log.debug("will use file path to credentials file from environment NETFOUNDRY_API_ACCOUNT to renew token")
    elif 'NETFOUNDRY_CLIENT_ID' in os.environ and 'NETFOUNDRY_PASSWORD' in os.environ and 'NETFOUNDRY_OAUTH_URL' in os.environ:
        cli.log.debug("will use API account credentials from environment NETFOUNDRY_CLIENT_ID, NETFOUNDRY_PASSWORD, NETFOUNDRY_OAUTH_URL to renew token")
    else:
        cli.log.debug("no token or credentials file provided, trying token cache")
    spinner = get_spinner("Loading profile '{:s}'".format(cli.config.general.profile))
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
                cli.log.info("Cancelled")
                exit(1)
            except Exception as e:
                cli.log.error(f"unknown error in {e}")
                exit(1)

            try:
                spinner.text = "trying token for profile '{:s}'".format(cli.config.general.profile)
                with spinner:
                    organization = Organization(
                        token=token_from_prompt,
                        organization=cli.config.general.organization if cli.config.general.organization else None,
                        profile=cli.config.general.profile,
                        expiry_minimum=0,
                        proxy=cli.config.general.proxy
                    )
            except PyJWTError as e:
                cli.log.error("caught JWT error in %e", e)
                exit(1)
            except Exception as e:
                cli.log.error(f"unknown error in {e}")
                exit(1)
        else:
            cli.log.info("not logged in")
            raise NFAPINoCredentials()
    cli.log.debug(f"logged-in organization label is {organization.label}.")
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
    cli.log.debug(f"network group is {network_group.name}")
    return network_group

def use_network(organization: object, network_name: str=None, group: str=None, operation: str='read'):
    """Use a network."""
    if not network_name:
        if group:
            network_group = use_network_group(organization=organization, group=group)
            existing_networks = network_group.networks_by_name()
        else:
            existing_networks = organization.get_networks_by_organization()
        cli.log.error("need 'nfctl --network NETWORK' or 'nfctl config.general.network=NETWORK' to configure a network")
        exit(1)
    if group:
        network_group = use_network_group(organization=organization, group=group)
        existing_networks = network_group.network_ids_by_normal_name
        if not existing_networks.get(normalize_caseless(network_name)):
            cli.log.error("failed to find a network named '{name}'.".format(name=network_name))
            exit(1)
    else:
        existing_count = organization.count_networks_with_name(network_name)
        if existing_count == 1:
            existing_networks = organization.get_networks_by_organization(name=network_name)
            existing_network = existing_networks[0]
            network_group = use_network_group(organization, group=existing_network['networkGroupId'])
        elif existing_count > 1:
            cli.log.error("there were {count} networks named '{name}' visible to your identity. Try filtering with '--network-group'.".format(count=existing_count, name=network_name))
            exit(1)
        else:
            cli.log.error(f"failed to find a network named '{network_name}'.")
            exit(1)

    # use the Network
    network = Network(network_group, network=network_name)
    if operation == delete:
        spinner = get_spinner(f"waiting for {network_name} to have status DELETING or DELETED")
        try:
            with spinner:
                network.wait_for_statuses(["DELETING","DELETED"],wait=999,progress=False)
        except KeyboardInterrupt as e:
            cli.log.info("Cancelled")
            exit(1)
        except Exception as e:
            raise RuntimeError(f"unknown error in {e}")
        else:
            cli.log.info(f"network '{network_name}' deleted")
    elif operation in ['create','read','update']:
        if not network.status == 'PROVISIONED':
            try:
                network.wait_for_status("PROVISIONED",wait=999,progress=False)
            except KeyboardInterrupt as e:
                cli.log.info("Cancelled")
                exit(1)
            except Exception as e:
                raise RuntimeError(f"unknown error in {e}")
            else:
                cli.log.info(f"network '{network_name}' ready")

    return network, network_group

def edit_object_as_yaml(edit: object):
    """Edit a resource object as YAML and return as object upon exit.
    
    :param obj input: a deserialized (object) to edit and return as yaml
    """
    # unless --yes (config general.yes), if stdout is connected to a terminal
    # then open input for editing and send on exit
    if not sys.stdout.isatty() or cli.args.yes:
        return edit
    save_error = False
    editor = os.environ.get('NETFOUNDRY_EDITOR',os.environ.get('EDITOR','vim'))
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
            cli.log.info("Cancelled")
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
        cli.log.warning(f"your buffer was saved and you may continue editing it  'create TYPE --file {temp_file}'")
        exit(1)

def get_spinner(text):
    """
    Return an enabled spinner if appropriate.
    
    Enabled if stdout is a tty and log level is >= INFO, else disabled because
    it will mangle debug output and isn't useful if output is redirected.
    """
    spinner = cli.spinner(text=text, spinner='dots12', placement='right', color='green', stream=sys.stderr)
    if not sys.stdout.isatty():
        spinner.enabled = False
        cli.log.debug("spinner disabled because stdout is not a tty")
    elif cli.config.general.verbose:
        spinner.enabled = False
        cli.log.debug("spinner disabled because DEBUG is enabled")
    else:
        spinner.enabled = True
        cli.log.debug("spinner enabled because stdout is a tty and DEBUG is not enabled")
    return spinner

if __name__ == '__main__':
    cli()
