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
import logging
#from base64 import b64decode
from json import dumps as json_dumps
from json import loads as json_loads
from re import sub
from subprocess import call

#from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from jwt.exceptions import PyJWTError
from milc import set_metadata
from packaging import version
#from requests import get as http_get
from tabulate import tabulate
from yaml import dump as yaml_dumps
from yaml import full_load as yaml_loads
from yaml import parser

from ._version import get_versions
from .exceptions import NFAPINoCredentials
from .network import Network
from .network_group import NetworkGroup
from .organization import Organization
from .utility import (MUTABLE_NETWORK_RESOURCES, NETWORK_RESOURCES, RESOURCES,
                      Utility, plural, singular)

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

@cli.argument('-p','--profile', default='default', help='login profile for storing and retrieving concurrent, discrete sessions')
@cli.argument('-C', '--credentials', help='API account JSON file from web console')
@cli.argument('-O', '--organization', help="label or ID of an alternative organization (default is caller's org)" )
@cli.argument('-N', '--network', help='caseless name of the network to manage')
@cli.argument('-G', '--network-group', help="shortname or ID of a network group to search for network_identifier")
@cli.argument('-O','--output', help="object formats suppress console messages", default="text", choices=['text', 'yaml','json'])
@cli.argument('-b','--borders', default=True, action='store_boolean', help='print cell borders in text tables')
@cli.argument('-H','--headers', default=True, action='store_boolean', help='print column headers in text tables')
@cli.argument('-Y', '--yes', action='store_true', arg_only=True, help='answer yes to potentially-destructive operations')
@cli.argument('-P', '--proxy', help="like http://localhost:8080 or socks5://localhost:9046")
@cli.entrypoint('configure the CLI to manage a network')
def main(cli):
    """Configure the CLI to manage a network."""
    login(cli, api="organization")

@cli.argument('api', help=argparse.SUPPRESS, arg_only=True, nargs='?', default="organization", choices=['organization', 'ziti'])
@cli.argument('-s','--shell', help=argparse.SUPPRESS, arg_only=True, action="store_true", default=False)
@cli.argument('-v','--ziti-version', help=argparse.SUPPRESS, default='0.22.0') # minium ziti CLI version supports --cli-identity and --read-only
@cli.argument('-c','--ziti-cli', help=argparse.SUPPRESS)
@cli.subcommand('login to a management API')
def login(cli, api: str=None, shell: bool=None):
    """Login to an API and cache the expiring token."""
    if api:
        cli.args['api'] = api
    if shell is not None:
        cli.args['shell'] = shell
    elif 'shell' not in cli.args.keys():
        cli.args['shell'] = False
    elif cli.args.shell:
        pass
    else:
        cli.args['shell'] = False
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
        if not cli.args.shell and cli.config.general.output == "text":
            summary_table = []
            summary_table.append(['organization', '"{org_name}" ({org_label}@{env}) logged in \n{fullname} ({email}) \nuntil {expiry_timestamp} (T-{expiry_seconds}s)'.format(
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
        exec = cli.run([ziti_cli, '--version'])
        if exec.returncode == 0:
            cli.log.debug("found ziti CLI '{ziti_cli}' version '{ziti_version}'".format(ziti_cli=which_ziti, ziti_version=exec.stdout))
        else:
            cli.log.error("failed to get ziti CLI version: %s", exec.stderr)
            exit(exec.returncode)
        try:
            assert(version.parse(exec.stdout) >= version.parse(cli.config.login.ziti_version))
        except AssertionError as e:
            cli.log.error("found ziti CLI '{ziti_cli}' but version is not at least {ziti_version}: {e}".format(ziti_cli=which_ziti, ziti_version=cli.config.login.ziti_version, e=e))
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
            session = network.get_controller_session(network.network_controller['id'])
            ziti_token = session['sessionToken']
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
            ### commented because new ziti CLI has built-in certs opt-in and caching
            # well_known_response = http_get('https://'+ziti_ctrl_ip+'/.well-known/est/cacerts', proxies=proxies, verify=False)
            # well_known_decoding = b64decode(well_known_response.text)
            # well_known_certs = pkcs7.load_der_pkcs7_certificates(well_known_decoding)
            # well_known_pem = tempdir+'/well-known-certs.pem'
            # with open(well_known_pem, 'wb') as pem:
            #     for cert in well_known_certs:
            #         pem.write(cert.public_bytes(Encoding.PEM))
            network_name_safe = '_'.join(network.name.casefold().split())
            ziti_cli_identity = '-'.join([organization.environment.casefold(), organization.label.casefold(), network_group.name.casefold(), network_name_safe])
            ziti_mgmt_port = str(443)
            exec = cli.run([ziti_cli, 'edge', 'login', '--read-only', '--cli-identity', ziti_cli_identity, ziti_ctrl_ip+':'+ziti_mgmt_port, '--token', ziti_token], capture_output=False)
            if exec.returncode == 0: # if succeeded
                exec = cli.run('{ziti} edge use {identity}'.format(ziti=ziti_cli, identity=ziti_cli_identity).split(), capture_output=False)
                if not exec.returncode == 0: # if error
                    cli.log.error("failed to switch default ziti login identity to '%s'", ziti_cli_identity)
                    exit(exec.returncode)
            else:
                cli.log.error("failed to login")
                exit(exec.returncode)

@cli.subcommand('logout from an identity organization')
def logout(cli):
    """Logout by deleting the cached token."""
    try:
        organization = use_organization(prompt=False)
    except NFAPINoCredentials:
        cli.log.debug("no need to logout profile '%s'", cli.config.general.profile)
    else:
        organization.logout()

@cli.argument('-f', '--file', help='JSON or YAML file', type=argparse.FileType('r', encoding='UTF-8'))
@cli.argument('-w','--wait', help='seconds to wait for process execution to finish', default=0)
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in MUTABLE_NETWORK_RESOURCES.keys()])
@cli.subcommand('create a resource from stdin or file')
def create(cli):
    """Create a resource.
    
    If interactive then open template or stdin or --file in EDITOR. Then
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
            cli.log.debug("got lines from file: %s", str(create_input_lines))
        except Exception as e:
            cli.log.error("failed to read the input file: %s", e)
            raise e
    else:
        for line in sys.stdin:
            create_input_lines += line
            cli.log.debug("got lines from stdin: %s", str(create_input_lines))
    if not create_input_object and create_input_lines:
        try:
            create_input_object = yaml_loads(create_input_lines)
        except Exception as e:
            cli.log.debug("failed to parse input lines from file as YAML, trying JSON: %s", e)
            try:
                create_input_object = json_loads(create_input_lines)
            except Exception as e:
                cli.log.debug("failed to parse input lines from file as JSON: %s", e)
    if not create_input_object:
        cli.log.error("failed to parse input lines as an object (deserialized JSON or YAML)")
        exit(1)

    create_object = edit_object_as_yaml(create_input_object)

    if not create_object: # is False if editing cancelled by empty buffer
        return True

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
        network = network_group.create_network(**create_object)
    else:
        network, network_group = use_network(
            organization=organization,
            group=cli.config.general.network_group,
            network=cli.config.general.network
        )
        resource = network.create_resource(type=cli.args.resource_type, properties=create_object, wait=cli.config.create.wait)

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in MUTABLE_NETWORK_RESOURCES.keys()])
# this allows us to pass the edit subcommand's cli object to function get without further modifying that functions params
@cli.argument('-a', '--accept', arg_only=True, default='update', help=argparse.SUPPRESS)
@cli.subcommand('edit a single resource selected by query with editor defined in NETFOUNDRY_EDITOR or EDITOR')
def edit(cli):
    """Edit a single resource as YAML.
    
    Configure env var NETFOUNDRY_EDITOR or EDITOR as path to executable that
    accepts a file to edit as first positional parameter and waits for exit to
    return e.g. "code --wait".
    """
    edit_resource_object, network, network_group, organization = get(cli, echo=False)
    cli.log.debug("opening %s named '%s' for editing", cli.args.resource_type, edit_resource_object['name'])
    update_request_object = edit_object_as_yaml(edit_resource_object)
    if not update_request_object: # is False if editing cancelled by empty buffer
        return True

    network.put_resource(put=update_request_object, type=cli.args.resource_type)

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('-a', '--accept', arg_only=True, choices=['create','update'], help="request the as=create or as=update form of the resource")
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in RESOURCES.keys()])
@cli.subcommand('get a single resource by query')
def get(cli, echo: bool=True):
    """Get a single resource as YAML or JSON"""
    cli.log.setLevel(logging.WARN) # don't emit INFO messages to stdout because they will break deserialization
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
        elif not cli.args.query.keys():
            match = organization.caller
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
                match = organization.get_network(network_id=network.id, embed="all", accept=cli.args.accept)
            else:
                matches = organization.get_networks_by_organization(**cli.args.query)
            if len(matches) == 1:
                match = organization.get_network(network_id=matches[0]['id'], embed="all", accept=cli.args.accept)
    else: # is a resource in the network domain
        if cli.config.general.network:
            network, network_group = use_network(
                organization=organization,
                group=cli.config.general.network_group, # None unless configured
                network=cli.config.general.network
            )
        else:
            cli.log.error("first configure a network to get resources in a network e.g. --network ACMENet")
            exit(1)
        if cli.args.resource_type == "data-center":
            if cli.args.accept:
                cli.log.warn("'accept' param not applicable to data-centers")
            if 'id' in cli.args.query.keys():
                cli.log.warn("data centers fetched by ID may not support this network's product version, try provider or locationCode params for safety")
                match = network.get_data_center_by_id(id=cli.args.query['id'])
            else:
                matches = network.get_edge_router_data_centers(**cli.args.query)
                if len(matches) == 1:
                    match = network.get_data_center_by_id(id=matches[0]['id'])
        else:
            if 'id' in cli.args.query.keys():
                match = network.get_resource_by_id(type=cli.args.resource_type, id=cli.args.query['id'], accept=cli.args.accept)
            else:
                matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)
                if len(matches) == 1:
                    match = network.get_resource_by_id(type=cli.args.resource_type, id=matches[0]['id'], accept=cli.args.accept)

    if match:
        cli.log.debug("found exactly one %s '%s'", cli.args.resource_type, cli.args.query)
        if not echo:
            return match, network, network_group, organization
        else:
            if cli.args.keys:
                # intersection of the set of observed, present keys in the
                # match and the set of configured, desired keys
                valid_keys = set(match.keys()) & set(cli.args.keys)
                if valid_keys: # if at least one element in intersection set
                    cli.log.debug("valid keys: %s", str(valid_keys))
                    filtered_match = { key: match[key] for key in match.keys() if key in valid_keys}
                else:
                    cli.log.error("no valid keys requested in list: %s, need at least one of %s", str(cli.args.keys), str(match.keys()))
                    exit(1)
            else:
                cli.log.debug("not filtering output keys")
                filtered_match = match
            if cli.config.general.output in ["yaml","text"]:
                cli.echo(yaml_dumps(filtered_match, indent=4, default_flow_style=False))
            elif cli.config.general.output == "json":
                cli.echo(json_dumps(filtered_match, indent=4))
    elif len(matches) == 0:
        cli.log.info("found no %s '%s'", cli.args.resource_type, cli.args.query)
        return True
    else: # len(matches) > 1:
        cli.log.error("found more than one %s '%s'", cli.args.resource_type, cli.args.query)
        exit(len(matches))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[type for type in RESOURCES.keys()])
@cli.subcommand('find resources as lists')
def list(cli):
    """Find resources as lists."""
    if cli.config.general.output == "text":
        if not sys.stdout.isatty():
            cli.log.warn("nfctl does not have a stable CLI interface. Use with caution in scripts.")
    else: # output is YAML or JSON
        # don't emit INFO messages to stdout because they will break deserialization
        cli.log.setLevel(logging.WARN)

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
        if cli.config.general.network:
            network, network_group = use_network(
                organization=organization,
                group=cli.config.general.network_group, # None unless configured
                network=cli.config.general.network
            )
        else:
            cli.log.error("first configure a network to list resources in a network e.g. --network ACMENet")
            exit(1)
        if cli.args.resource_type == "data-centers":
            matches = network.get_edge_router_data_centers(**cli.args.query)
        else:
            matches = network.get_resources(type=cli.args.resource_type, **cli.args.query)

    if len(matches) == 0:
        cli.log.info("found no %s '%s'", cli.args.resource_type, cli.args.query)
        exit(0)
    else:
        cli.log.debug("found at least one %s '%s'", cli.args.resource_type, cli.args.query)

    valid_keys = set()
    if cli.args.keys:
        # intersection of the set of valid, observed keys in the first match
        # and the set of configured, desired keys
        valid_keys = set(matches[0].keys()) & set(cli.args.keys)
    elif cli.config.general.output == "text":
        valid_keys = set(matches[0].keys()) & set(['name','label','organizationShortName','id','edgeRouterAttributes','serviceAttributes','endpointAttributes','status','zitiId','provider','locationCode','ipAddress','region','size','attributes','email','productVersion'])

    if valid_keys:
        cli.log.debug("valid keys: %s", str(valid_keys))
        filtered_matches = []
        for match in matches:
            filtered_match = { key: match[key] for key in match.keys() if key in valid_keys}
            filtered_matches.append(filtered_match)
    else:
        cli.log.debug("not filtering output keys")
        filtered_matches = matches

    if cli.config.general.output == "text":
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
    elif cli.config.general.output == "yaml":
        cli.echo(yaml_dumps(filtered_matches, indent=4, default_flow_style=False))
    elif cli.config.general.output == "json":
        cli.echo(json_dumps(filtered_matches, indent=4))

@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', choices=[singular(type) for type in MUTABLE_NETWORK_RESOURCES.keys()])
@cli.argument('-w','--wait', help='seconds to wait for confirmation of delete', default=0)
@cli.subcommand('delete a resource in the network domain')
def delete(cli):
    """Delete a resource in the network domain."""
    organization = use_organization()
    network, network_group = use_network(
        organization=organization,
        group=cli.config.general.network_group,
        network=cli.config.general.network,
        operation='delete'
    )

    spinner = cli.spinner(text=str(), spinner='dots12', stream=sys.stderr)
    if sys.stdout.isatty():
        spinner.enabled = True
    else:
        spinner.enabled = False
        cli.log.debug("spinner disabled")

    if cli.args.resource_type == "network":
        if not cli.args.query == {}:
            cli.log.warn("ignoring name='%s' because this operation applies to the entire network that is already selected", str(cli.args.query))
        try:
            if cli.args.yes or questions.yesno("confirm delete network '{name}'".format(name=network.name), default=False):
                spinner.text = "deleting network '{net}'".format(net=network.name)
                try:
                    with spinner:
                        network.delete_network(progress=False, wait=cli.config.delete.wait)
                except KeyboardInterrupt as e:
                    cli.log.debug("wait cancelled by user")
                except Exception as e:
                    cli.log.error("unknown error in %s", e)
                    exit(1)
                else:
                    cli.log.info(sub('deleting', 'deleted', spinner.text))
            else:
                cli.echo("not deleting network '{name}'.".format(name=network.name))
        except KeyboardInterrupt as e:
            cli.log.debug("input cancelled by user")
        except Exception as e:
            cli.log.error("unknown error in %s", e)
            exit(1)
    else:
        if not cli.args.query:
            cli.log.error("need query to select a resource")
            exit(1)
        if 'id' in cli.args.query.keys():
            matches = [network.get_resource_by_id(type=cli.args.resource_type, id=cli.args.query['id'])]
        else:
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
                    spinner.text = "deleting {type} '{name}'".format(type=cli.args.resource_type, name=matches[0]['name'])
                    try:
                        with spinner:
                            network.delete_resource(type=cli.args.resource_type, id=matches[0]['id'])
                    except KeyboardInterrupt as e:
                        cli.log.debug("wait cancelled by user")
                    except Exception as e:
                        cli.log.error("unknown error in %s", e)
                        exit(1)
                    else:
                        cli.log.info(sub('deleting', 'deleted', spinner.text))
                else:
                    cli.echo("not deleting {type} '{name}'".format(type=cli.args.resource_type, name=matches[0]['name']))
            except KeyboardInterrupt as e:
                cli.log.debug("input cancelled by user")
            except Exception as e:
                cli.log.error("unknown error in %s", e)
                exit(1)

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
                os.environ['NETFOUNDRY_API_TOKEN'] = questions.password(prompt='Enter Bearer Token:', confirm=False, validate=utility.is_jwt)
            except KeyboardInterrupt as e:
                cli.log.debug("input cancelled by user")
                exit(1)
            except Exception as e:
                cli.log.error("unknown error in %s", e)
                exit(1)
            try:
                organization = Organization(
                    credentials=cli.config.general.credentials if cli.config.general.credentials else None,
                    organization=cli.config.general.organization if cli.config.general.organization else None,
                    profile=cli.config.general.profile,
                    expiry_minimum=0,
                    proxy=cli.config.general.proxy
                )
            except PyJWTError as e:
                cli.log.error("caught JWT error in %e", e)
                exit(1)
            except Exception as e:
                cli.log.error("unknown error in %s", e)
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
        cli.log.error("need 'nfctl --network NETWORK' or 'nfctl config general.network=NETWORK' to configure a network")
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

    spinner = cli.spinner(text=str(), spinner='dots12', stream=sys.stderr)
    if sys.stdout.isatty() and cli.log.getEffectiveLevel() <= logging.INFO:
        spinner.enabled = True
    else:
        spinner.enabled = False
        cli.log.debug("spinner disabled")

    # use the Network
    network = Network(network_group, network=network_identifier)
    if operation == delete:
        spinner.text = 'waiting for {net} to have status DELETING or DELETED'.format(net=network_identifier)
        try:
            with spinner:
                network.wait_for_statuses(["DELETING","DELETED"],wait=999,progress=False)
        except KeyboardInterrupt as e:
            cli.log.debug("wait cancelled by user")
        except Exception as e:
            cli.log.error("unknown error in %s", e)
            exit(1)
        else:
            cli.log.info("network '{net}' deleted".format(net=network_identifier))
    elif operation in ['create','read','update']:
        if not network.status == 'PROVISIONED':
            spinner.text = 'waiting for {net} to have status PROVISIONED'.format(net=network_identifier)
            try:
                with spinner:
                    network.wait_for_status("PROVISIONED",wait=999,progress=False)
            except KeyboardInterrupt as e:
                cli.log.debug("wait cancelled by user")
            except Exception as e:
                cli.log.error("unknown error in %s", e)
                exit(1)
            else:
                cli.log.info("network '{net}' ready".format(net=network_identifier))

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
    EDITOR = os.environ.get('NETFOUNDRY_EDITOR',os.environ.get('EDITOR','vim'))
    instructions_bytes = "# just exit to confirm, or\n#  abort by saving an empty file\n".encode()
    edit_bytes = yaml_dumps(edit, default_flow_style=False).encode()
    with tempfile.NamedTemporaryFile(suffix=".yml") as tf:
        tf.write(instructions_bytes + edit_bytes)
        tf.flush()
        return_code = call(EDITOR.split()+[tf.name])

        tf.seek(0)
        edited = tf.read()
    if return_code == 0:
        if len(edited) == 0:
            cli.log.info("cancelled due to empty file")
            return False
        else:
            try:
                edited_object = yaml_loads(edited)
            except parser.ParserError as e:
                cli.log.error("invalid YAML or JSON: %s", e)
                save_error = True
            except Exception as e:
                cli.log.error("unknown error in %s", e)
                save_error = True
            else:
                return edited_object
    else:
        cli.log.error("editor returned an error")
        save_error = True
    if save_error:
        with tempfile.NamedTemporaryFile(suffix=".yml") as tf:
            tf.write(edited.encode())
            cli.log.warn("your buffer was saved in %s and you may edit and redirect to the same command as stdin or --file", tf.name)
        exit(1)


if __name__ == '__main__':
    cli()
