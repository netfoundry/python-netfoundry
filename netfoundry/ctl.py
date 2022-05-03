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
import signal
import tempfile
from json import dumps as json_dumps
from json import load as json_load
from json import loads as json_loads
from os import environ, path  # , stat
from random import choice, sample, shuffle
from re import sub
from subprocess import CalledProcessError
from sys import exit as sysexit
from sys import stderr, stdin, stdout
from xml.sax.xmlreader import InputSource

from jwt.exceptions import PyJWTError
from milc import set_metadata  # this function needed to set metadata immediately below
from pygments import highlight
from pygments.formatters import Terminal256Formatter
from pygments.lexers import get_lexer_by_name, load_lexer_from_file
from tabulate import tabulate
from yaml import dump as yaml_dumps
from yaml import full_load as yaml_loads
from yaml import parser

from netfoundry import __version__ as netfoundry_version

from .exceptions import NeedUserInput, NFAPINoCredentials
from .network import Network, Networks
from .network_group import NetworkGroup
from .organization import Organization
from .utility import DC_PROVIDERS, EMBED_NET_RESOURCES, MUTABLE_NET_RESOURCES, MUTABLE_RESOURCE_ABBREV, RESOURCE_ABBREV, RESOURCES, is_jwt, normalize_caseless, plural, singular

set_metadata(version=f"v{netfoundry_version}", author="NetFoundry", name="nfctl")  # must precend import milc.cli
from milc import cli, questions  # this uses metadata set above
from milc.subcommand import config  # this creates the config subcommand

if platform.system() == 'Linux':
    # this allows the app the terminate gracefully when piped to a truncating consumer like `head`
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


class StoreDictKeyPair(argparse.Action):
    """Parse key pairs into a dictionary."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Split comma-separated key=value pairs."""
        my_dict = {}
        if values is not None:                 # and len(values.split(',')) > 0:
            for kv in values.split(','):
                try:
                    k, v = kv.split('=')
                except ValueError:
                    # logging is not set up yet because MILC redirects to null
                    # device until decorators are exec'd and metadata is
                    # configured and cli() is invoked
                    stderr.write(f"invalid value '{kv}', expected a comma-sep list of one or more k=v pairs e.g. name=ACMENet,productVersion=1.2.3\n")
                    stderr.flush()
                    exit(1)
                else:
                    my_dict[k] = v
        setattr(namespace, self.dest, my_dict)


class StoreListKeys(argparse.Action):
    """Parse comma-separated strings into a list."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Split comma-separated list elements."""
        setattr(namespace, self.dest, values.split(','))


@cli.argument('-P', '--profile', default='default', help='login profile for storing and retrieving concurrent, discrete sessions')
@cli.argument('-C', '--credentials', help='API account JSON file from web console')
@cli.argument('-O', '--organization', help="label or ID of an alternative organization (default is caller's org)")
@cli.argument('-N', '--network', help='caseless name of the network to manage')
@cli.argument('-G', '--network-group', help="shortname or ID of a network group to search for network_name")
@cli.argument('-o', '--output', arg_only=True, help="format the output", default="text", choices=['text', 'yaml', 'json'])
@cli.argument('-S', '--style', help="highlighting style", default='material', choices=["bw", "rrt", "arduino", "monokai", "material", "emacs", "vim", "one-dark"])
@cli.argument('-B', '--borders', default=True, action='store_boolean', help='print cell borders in text tables')
@cli.argument('-H', '--headers', default=True, action='store_boolean', help='print column headers in text tables')
@cli.argument('-Y', '--yes', action='store_true', arg_only=True, help='answer yes to potentially-destructive operations')
@cli.argument('-W', '--wait', help='seconds to wait for long-running processes to finish', default=900)
@cli.argument('--proxy', help=argparse.SUPPRESS)
@cli.entrypoint('configure the CLI to manage a network')
def main(cli):
    """Configure the CLI to manage a network."""
    # assign the default values for options that are evaluted by login() since they're not set by main()'s options
    cli.args['autocomplete'] = True
    cli.args['eval'] = False
    login(cli)
    cli.log.info(f"try running '{cli.prog_name} list networks'")


@cli.argument('-a', '--autocomplete', action='store_boolean', default=True, help="include tab autocomplete configuration in shell eval")
@cli.argument('-e', '--eval', help="source or eval output to configure shell environment with a login token", arg_only=True, action="store_true", default=False)
@cli.subcommand('login to NetFoundry with a user token or API account credentials')
def login(cli):
    """Login to an API and cache the expiring token."""
    # if logging in to a NF org (default)
    spinner = get_spinner(cli, "working")
    spinner.text = f"Logging in profile '{cli.config.general.profile}'"
    with spinner:
        organization, networks = use_organization(cli, spinner)
        if cli.config.general.network_group and cli.config.general.network:
            cli.log.debug(f"configuring network {cli.config.general.network} in group {cli.config.general.network_group}")
            network, network_group = use_network(
                cli,
                organization=organization,
                group=cli.config.general.network_group,
                network_name=cli.config.general.network)
        elif cli.config.general.network:
            cli.log.debug(f"configuring network {cli.config.general.network} and local group if unique name for this organization")
            network, network_group = use_network(
                cli,
                organization=organization,
                network_name=cli.config.general.network)
        elif cli.config.general.network_group:
            cli.log.debug(f"configuring network group {cli.config.general.network_group}")
            network_group = use_network_group(
                cli,
                organization,
                group=cli.config.general.network_group)
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
            if cli.args.output == "text":
                summary_table = []
                summary_table.append(['Caller ID', f"{summary_object['caller']['name']} ({summary_object['caller']['email']}) in {organization.label} ({organization.name})"])
                if network_group:
                    summary_table.append(['Network Resource Group', f"{summary_object['network_group']['name']} ({summary_object['network_group']['organizationShortName']}) with {summary_object['network_group']['networks_count']} networks"])
                if network:
                    summary_table.append(['Configured Network', f"{summary_object['network']['name']} - {summary_object['network']['productVersion']} - {summary_object['network']['status']}"])
                if cli.config.general.borders:
                    table_borders = "presto"
                else:
                    table_borders = "plain"
                table = tabulate(tabular_data=summary_table, headers=['Domain', 'Summary'], tablefmt=table_borders)
                if cli.config.general.color:
                    highlighted = highlight(table, text_lexer, Terminal256Formatter(style=cli.config.general.style))
                    try:
                        cli.echo(highlighted)
                    except ValueError:
                        print(highlighted)
                else:
                    try:
                        cli.echo(table)
                    except ValueError:
                        print(table)
            elif cli.args.output == "yaml":
                if cli.config.general.color:
                    highlighted = highlight(yaml_dumps(summary_object, indent=4), yaml_lexer, Terminal256Formatter(style=cli.config.general.style))
                    try:
                        cli.echo(highlighted)
                    except ValueError:
                        print(highlighted)
                else:
                    try:
                        cli.echo(yaml_dumps(summary_object, indent=4))
                    except ValueError:
                        print(yaml_dumps(summary_object, indent=4))
            elif cli.args.output == "json":
                if cli.config.general.color:
                    highlighted = highlight(json_dumps(summary_object, indent=4), json_lexer, Terminal256Formatter(style=cli.config.general.style))
                    try:
                        cli.echo(highlighted)
                    except ValueError:
                        print(highlighted)
                else:
                    try:
                        cli.echo(json_dumps(summary_object, indent=4))
                    except ValueError:
                        print(json_dumps(summary_object, indent=4))
        else:             # if eval
            nonf = """
# helper function logs out from NetFoundry
function nonf(){
    unset   NETFOUNDRY_API_ACCOUNT NETFOUNDRY_API_TOKEN \
            NETFOUNDRY_CLIENT_ID NETFOUNDRY_PASSWORD NETFOUNDRY_OAUTH_URL \
            NETFOUNDRY_ORGANIZATION NETFOUNDRY_NETWORK NETFOUNDRY_NETWORK_GROUP \
            MOPENV MOPURL
}
"""
            noaws = """
# helper function logs out from AWS
function noaws(){
    unset   AWS_SECURITY_TOKEN AWS_SESSION_TOKEN \
            AWS_ACCESS_KEY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY \
            AWS_REGION AWS_DEFAULT_REGION AWS_SHARED_CREDENTIALS_FILE
}
"""
            autocomplete = f'eval "$(register-python-argcomplete {cli.prog_name})"'
            token_env = f"""
# $ eval "$({cli.prog_name} --credentials={organization.credentials} login --eval)"
export NETFOUNDRY_API_TOKEN="{organization.token}"
export NETFOUNDRY_API_ACCOUNT="{organization.credentials if hasattr(organization, 'credentials') else ''}"
export NETFOUNDRY_ORGANIZATION="{organization.id}"
{'export NETFOUNDRY_NETWORK="'+network.id+'"' if network else '# NETFOUNDRY_NETWORK'}
{'export NETFOUNDRY_NETWORK_GROUP="'+network_group.id+'"' if network_group else '# NETFOUNDRY_NETWORK_GROUP'}
export MOPENV="{organization.environment}"
export MOPURL="{organization.audience}"
{autocomplete if cli.config.login.autocomplete else '# autocomplete skipped'}
{nonf}
{noaws if cli.prog_name == 'nfsupport' else ''}
"""
            if cli.config.general.color:
                highlighted = highlight(token_env, bash_lexer, Terminal256Formatter(style=cli.config.general.style))
                try:
                    cli.echo(highlighted)
                except ValueError:
                    print(highlighted)
            else:
                try:
                    cli.echo(token_env)
                except ValueError:
                    print(token_env)


@cli.subcommand('logout your identity for the current current profile')
def logout(cli):
    """Logout by deleting the cached token."""
    spinner = get_spinner(cli, "working")
    spinner.text = f"Logging out profile '{cli.config.general.profile}'"
    # use the session with some organization, default is to use the first and there's typically only one
    try:
        with spinner:
            Organization(
                profile=cli.config.general.profile,
                logout=True,
                proxy=cli.config.general.proxy
            )
    except Exception as e:
        cli.log.error(f"unexpected error while logging out profile '{cli.config.general.profile}': {e}")
        sysexit(1)
    else:
        spinner.succeed(sub('Logging', 'Logged', spinner.text))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE",
              choices=[choice for group in [[singular(type), MUTABLE_NET_RESOURCES[type].abbreviation] for type in MUTABLE_NET_RESOURCES.keys()] for choice in group])
# this allows us to pass the edit subcommand's cli object to function get without further modifying that functions params
@cli.subcommand('duplicate a resource')
def copy(cli):
    """Duplicate a single resource.

    Configure env var NETFOUNDRY_EDITOR or EDITOR as path to executable that
    accepts a file to edit as first positional parameter and waits for exit to
    return e.g. "code --wait".
    """
    spinner = get_spinner(cli, "working")
    if MUTABLE_RESOURCE_ABBREV.get(cli.args.resource_type):
        cli.args.resource_type = singular(MUTABLE_RESOURCE_ABBREV[cli.args.resource_type].name)
    spinner.text = f"Getting {cli.args.resource_type} for copying"
    cli.args['accept'] = 'create'
    cli.args['embed'] = None
    cli.args['output'] = 'text'       # implies tty which allows INFO messages
    with spinner:
        edit_resource_object, network, network_group, organization = get(cli, echo=False, spinner=spinner)
    cli.log.debug(f"opening {cli.args.resource_type} '{edit_resource_object['name']}' for copying")
    copy_request_object = edit_object_as_yaml(cli, edit_resource_object)
    if not copy_request_object:       # is False if editing cancelled by empty buffer
        return True
    else:
        spinner.text = f"Copying {edit_resource_object['name']} to {copy_request_object['name']}"
        with spinner:
            network.create_resource(post=copy_request_object, type=cli.args.resource_type)
        spinner.succeed(sub('Copying', 'Copied', spinner.text))


@cli.argument('-f', '--file', help='JSON or YAML file', type=argparse.FileType('r', encoding='UTF-8'))
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE",
              choices=[choice for group in [[singular(type), RESOURCES[type].abbreviation] for type in MUTABLE_NET_RESOURCES.keys()] for choice in group])
@cli.subcommand('create a resource from a file')
def create(cli):
    """Create a resource.

    If interactive then open template or --file in EDITOR. Then
    send create request upon EDITOR exit. If not interactive then send input
    object as create request immediately.
    """
    spinner = get_spinner(cli, "working")
    if MUTABLE_RESOURCE_ABBREV.get(cli.args.resource_type):
        cli.args.resource_type = singular(MUTABLE_RESOURCE_ABBREV[cli.args.resource_type].name)
    # get the input object if available, else get the lines (serialized YAML or JSON) and try to deserialize
    create_input_object, create_input_lines, create_object = None, str(), None
    if not cli.args.file:
        create_input_object = MUTABLE_NET_RESOURCES[plural(cli.args.resource_type)].create_template
    elif cli.args.file:
        try:
            create_input_lines = cli.args.file.read()
            cli.log.debug(f"got {len(create_input_lines)}B from file: {cli.args.file}")
        except Exception as e:
            raise RuntimeError(f"failed to read the input file: {e}")
    else:
        cli.log.error("need input file '--file=FILE'")
        sysexit(1)
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
        sysexit(1)

    create_object = edit_object_as_yaml(cli, create_input_object)
    if not create_object:              # False if editing cancelled by empty buffer
        cli.log.debug = f"Creating {cli.args.resource_type} cancelled"
        return True
    else:
        spinner.text = f"Creating {cli.args.resource_type}"
    with spinner:
        organization, networks = use_organization(cli, spinner)
        if cli.args.resource_type == "network":
            if cli.config.general.network_group:
                network_group = use_network_group(cli, organization=organization, )
            else:
                org_count = len(organization.find_network_groups_by_organization())
                if org_count > 1:
                    cli.log.error("specify --network-group because there is more than one available to caller's identity")
                    sysexit(org_count)
                else:                   # use the only available group
                    network_group_id = organization.find_network_groups_by_organization()[0]['id']
                    network_group = use_network_group(
                        cli,
                        organization=organization,
                        group=network_group_id)
            resource = network_group.create_network(**create_object)
        else:
            network, network_group = use_network(
                cli,
                organization=organization,
                group=cli.config.general.network_group,
                network_name=cli.config.general.network)
            resource = network.create_resource(type=cli.args.resource_type, post=create_object, wait=cli.config.general.wait)
    spinner.succeed(f"Created {cli.args.resource_type} '{resource['name']}'")


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE",
              choices=[choice for group in [[singular(type), RESOURCES[type].abbreviation] for type in MUTABLE_NET_RESOURCES.keys()] for choice in group])
# this allows us to pass the edit subcommand's cli object to function get without further modifying that functions params
@cli.subcommand('edit a resource with EDITOR')
def edit(cli):
    """Edit a single resource as YAML.

    Configure env var NETFOUNDRY_EDITOR or EDITOR as path to executable that
    accepts a file to edit as first positional parameter and waits for exit to
    return e.g. "code --wait".
    """
    spinner = get_spinner(cli, "working")
    if MUTABLE_RESOURCE_ABBREV.get(cli.args.resource_type):
        cli.args.resource_type = singular(MUTABLE_RESOURCE_ABBREV[cli.args.resource_type].name)
    cli.args['accept'] = None
    cli.args['embed'] = None
    spinner.text = f"Getting {cli.args.resource_type} for editing"
    cli.log.debug(f"opening {cli.args.resource_type} for editing")
    with spinner:
        edit_resource_object, network, network_group, organization = get(cli, echo=False, spinner=spinner)
    update_request_object = edit_object_as_yaml(cli, edit_resource_object)
    with spinner:
        if not update_request_object:          # is False if editing cancelled by empty buffer
            spinner.text = f"Editing {cli.args.resource_type} cancelled"
            return True
        else:
            spinner.text = f"Updating {cli.args.resource_type}"
            with spinner:
                network.put_resource(put=update_request_object, type=cli.args.resource_type)
            spinner.succeed(sub("Updating", "Updated", spinner.text))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="id=UUIDv4 or query params as k=v,k=v comma-separated pairs")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('-a', '--as', dest='accept', arg_only=True, choices=['create'], help="request the as=create alternative form of the resource")
@cli.argument('-e', '--embed', arg_only=True, nargs='+',
              help="applies to 'get network': optionally embed space-sep list of resource types or 'all' of a network's resource collections",
              choices=[plural(type) for type in EMBED_NET_RESOURCES.keys()].extend('all'))
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE",
              choices=[choice for group in [[singular(type), RESOURCES[type].abbreviation] for type in RESOURCES.keys()] for choice in group])
@cli.subcommand('get a single resource by type and query')
def get(cli, echo: bool = True, spinner: object = None):
    """
    Get a single resource as YAML or JSON.

    :param echo: False allows the caller to capture the return instead of printing the match
    """
    if RESOURCE_ABBREV.get(cli.args.resource_type):
        cli.args.resource_type = singular(RESOURCE_ABBREV[cli.args.resource_type].name)
    if not cli.config.general.verbose and cli.args.output in ["yaml", "json"]:    # don't change level if output=text
        cli.log.setLevel(logging.WARN)                                            # don't emit INFO messages to stdout because they will break deserialization
    if cli.args.accept and not MUTABLE_NET_RESOURCES.get(plural(cli.args.resource_type)):
        logging.warning("ignoring --as=create because it is applicable only to mutable resources in the network domain")
        cli.args['accept'] = None
    match = {}
    matches = []
    query_keys = [*cli.args.query]
    if not spinner:
        spinner = get_spinner(cli, "working")
    else:
        cli.log.debug("got spinner as function param")
    spinner.text = f"Getting {cli.args.resource_type}"
    if not echo:
        spinner.enabled = False
    with spinner:
        organization, networks = use_organization(cli, spinner)
        if cli.args.resource_type == "organization":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                match = organization.get_organization(id=cli.args.query['id'])
            else:
                matches = organization.find_organizations(**cli.args.query)
                if len(matches) == 1:
                    match = organization.get_organization(id=matches[0]['id'])
        elif cli.args.resource_type in ["network-version"]:
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                match = networks.get_network_domain_resource(resource_type=cli.args.resource_type, id=cli.args.query['id'])
            else:
                matches = networks.find_network_domain_resources(resource_type=cli.args.resource_type, **cli.args.query)
                if len(matches) == 1:
                    match = matches[0]
        elif cli.args.resource_type == "network-group":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                match = organization.get_network_group(network_group_id=cli.args.query['id'])
            else:
                matches = organization.find_network_groups_by_organization(**cli.args.query)
                if len(matches) == 1:
                    match = organization.get_network_group(network_group_id=matches[0]['id'])
        elif cli.args.resource_type == "identity":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                match = organization.get_identity(identity_id=cli.args.query['id'])
            elif not query_keys:  # return caller identity if not filtering
                match = organization.caller
            else:
                matches = organization.find_identities(**cli.args.query)
                if len(matches) == 1:
                    match = matches[0]
        elif cli.args.resource_type == "role":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                match = organization.get_role(role_id=cli.args.query['id'])
            else:
                matches = organization.find_roles(**cli.args.query)
                if len(matches) == 1:
                    match = matches[0]
        elif cli.args.resource_type == "network":
            if 'id' in query_keys:
                if len(query_keys) > 1:
                    query_keys.remove('id')
                    cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                match = organization.get_network(network_id=cli.args.query['id'], embed=cli.args.embed, accept=cli.args.accept)
            else:
                if cli.config.general.network_group and not cli.config.general.network:
                    network_group = use_network_group(
                        cli,
                        organization,
                        group=cli.config.general.network_group)
                    matches = organization.find_networks_by_group(network_group.id, **cli.args.query)
                elif cli.config.general.network:
                    network, network_group = use_network(
                        cli,
                        organization=organization,
                        network_name=cli.config.general.network)
                    match = organization.get_network(network_id=network.id, embed=cli.args.embed, accept=cli.args.accept)
                else:
                    matches = organization.find_networks_by_organization(**cli.args.query)
                if len(matches) == 1:
                    network, network_group = use_network(
                        cli,
                        organization=organization,
                        network_name=matches[0]['name'])
                    match = organization.get_network(network_id=network.id, embed=cli.args.embed, accept=cli.args.accept)
        else:                                                 # is a resource in the network domain
            if cli.config.general.network:
                network, network_group = use_network(
                    cli,
                    organization=organization,
                    group=cli.config.general.network_group,   # None unless configured
                    network_name=cli.config.general.network)
            else:
                cli.log.error("need --network=ACMENet")
                sysexit(1)
            if cli.args.resource_type == "data-center":
                if 'id' in query_keys:
                    cli.log.warn("data centers fetched by ID may not support this network's product version, try provider or locationCode params for safety")
                    if len(query_keys) > 1:
                        query_keys.remove('id')
                        cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                    match = network.get_data_center_by_id(id=cli.args.query['id'])
                else:
                    matches = network.find_edge_router_data_centers(**cli.args.query)
                    if len(matches) == 1:
                        match = network.get_data_center_by_id(id=matches[0]['id'])
            else:
                if 'id' in query_keys:
                    if len(query_keys) > 1:
                        query_keys.remove('id')
                        cli.log.warn(f"using 'id' only, ignoring params: '{', '.join(query_keys)}'")
                    match = network.get_resource_by_id(type=cli.args.resource_type, id=cli.args.query['id'], accept=cli.args.accept)
                else:
                    matches = network.find_resources(type=cli.args.resource_type, accept=cli.args.accept, params=cli.args.query)
                    if len(matches) == 1:
                        match = matches[0]

    if match:
        cli.log.debug(f"found exactly one {cli.args.resource_type} by '{', '.join(query_keys)}'")
        if not echo:                           # edit() uses echo=False to get a match for updating
            return match, network, network_group, organization
        else:
            if cli.args.keys:
                # intersection of the set of observed, present keys in the
                # match and the set of desired keys
                valid_keys = set(match.keys()) & set(cli.args.keys)
                if valid_keys:                 # if at least one element in intersection set
                    cli.log.debug(f"valid keys: {str(valid_keys)}")
                    filtered_match = {key: match[key] for key in match.keys() if key in valid_keys}
                else:
                    cli.log.error(f"no valid keys requested in list: {', '.join(cli.args.keys)}, need at least one of {', '.join(match.keys())}")
                    sysexit(1)
            else:
                cli.log.debug("not filtering output keys")
                filtered_match = match
            if cli.args.output in ["yaml", "text"]:
                if cli.config.general.color:
                    highlighted = highlight(yaml_dumps(filtered_match, indent=4), yaml_lexer, Terminal256Formatter(style=cli.config.general.style))
                    try:
                        cli.echo(highlighted)
                    except ValueError:
                        print(highlighted)
                else:
                    try:
                        cli.echo(yaml_dumps(filtered_match, indent=4))
                    except ValueError:
                        print(yaml_dumps(filtered_match, indent=4))
            elif cli.args.output == "json":
                if cli.config.general.color:
                    highlighted = highlight(json_dumps(filtered_match, indent=4), json_lexer, Terminal256Formatter(style=cli.config.general.style))
                    try:
                        cli.echo(highlighted)
                    except ValueError:
                        print(highlighted)
                else:
                    try:
                        cli.echo(json_dumps(filtered_match, indent=4))
                    except ValueError:
                        print(json_dumps(filtered_match, indent=4))
    elif len(matches) == 0:
        cli.log.warn(f"found no {cli.args.resource_type} by '{', '.join(query_keys)}'")
        sysexit(1)
    else:                   # len(matches) > 1:
        if cli.args.query:
            cli.log.error(f"found more than one {cli.args.resource_type} by param(s): '{', '.join(query_keys)}', try a more specific query")
        else:
            cli.log.error(f"found more than one {cli.args.resource_type}, try using a query like 'name=AcmeThing%' (% is wildcard)")
        sysexit(len(matches))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('-k', '--keys', arg_only=True, action=StoreListKeys, help="list of keys as a,b,c to print only selected keys (columns)")
@cli.argument('-m', '--my-roles', arg_only=True, action='store_true', help="filter roles by caller identity")
@cli.argument('-a', '--as', dest='accept', arg_only=True, choices=['create'], help="request the as=create alternative form of the resources")
@cli.argument('resource_type', arg_only=True, help='type of resource', metavar="RESOURCE_TYPE",
              choices=[choice for group in [[type, RESOURCES[type].abbreviation] for type in RESOURCES.keys()] for choice in group])
@cli.subcommand(description='find a collection of resources by type and query')
def list(cli, spinner: object = None):
    """Find resources as lists."""
    if not spinner:
        spinner = get_spinner(cli, "working")
    else:
        cli.log.debug("got spinner as function param")
    if RESOURCE_ABBREV.get(cli.args.resource_type):
        cli.args.resource_type = RESOURCE_ABBREV[cli.args.resource_type].name
    if cli.args.accept and not MUTABLE_NET_RESOURCES.get(cli.args.resource_type):  # mutable excludes data-centers
        cli.log.warn("the --as=ACCEPT param is not applicable to resources outside the network domain")
    if cli.args.query and cli.args.query.get('id'):
        cli.log.warn("try 'get' command to get by id")
    if cli.args.output == "text":
        if not stdout.isatty():
            cli.log.warn(f"use --output=yaml or json for scripting {cli.prog_name}")
    else:             # output is YAML or JSON
        # don't emit INFO messages to stdout because they will break deserialization
        cli.log.setLevel(logging.WARN)
    query_keys = [*cli.args.query]
    if cli.args.query:
        spinner.text = f"Finding {cli.args.resource_type} {'by' if query_keys else '...'} {', '.join(query_keys)}"
    else:
        spinner.text = f"Finding all {cli.args.resource_type}"
    with spinner:
        organization, networks = use_organization(cli, spinner)
        if cli.args.resource_type == "organizations":
            matches = organization.find_organizations(**cli.args.query)
        elif cli.args.resource_type in ["network-versions"]:
            matches = networks.find_network_domain_resources(resource_type=cli.args.resource_type, **cli.args.query)
        elif cli.args.resource_type == "network-groups":
            matches = organization.find_network_groups_by_organization(**cli.args.query)
        elif cli.args.resource_type in ["identities", "user-identities", "api-account-identities"]:
            matches = organization.find_identities(type=cli.args.resource_type, **cli.args.query)
        elif cli.args.resource_type == "roles":
            if cli.args.my_roles:
                if cli.args.query.get('identityId'):
                    cli.log.warn("got --my-roles, ignoring param 'identityId'")
                cli.args.query['identityId'] = organization.caller['id']
                matches = organization.find_roles(**cli.args.query)
            else:
                matches = organization.find_roles(**cli.args.query)
        elif cli.args.resource_type == "networks":
            if cli.config.general.network_group:
                network_group = use_network_group(
                    cli,
                    organization=organization,
                    group=cli.config.general.network_group,
                    spinner=spinner)
                matches = organization.find_networks_by_group(network_group.id, accept=cli.args.accept, **cli.args.query)
            else:
                matches = organization.find_networks_by_organization(accept=cli.args.accept, **cli.args.query)
        else:
            if cli.config.general.network:
                network, network_group = use_network(
                    cli,
                    organization=organization,
                    group=cli.config.general.network_group,       # None unless configured
                    network_name=cli.config.general.network,
                    spinner=spinner)
            else:
                cli.log.error("first configure a network: '--network=ACMENet'")
                sysexit(1)
            if cli.args.resource_type == "data-centers":
                matches = network.find_edge_router_data_centers(**cli.args.query)
            else:
                matches = network.find_resources(type=cli.args.resource_type, accept=cli.args.accept, params=cli.args.query)

    if len(matches) == 0:
        spinner.fail(f"Found no {cli.args.resource_type} by '{', '.join(query_keys)}'")
        sysexit(0)
    else:
        cli.log.debug(f"found at least one {cli.args.resource_type} by '{', '.join(query_keys)}'")

    valid_keys = set()
    if cli.args.keys:
        # intersection of the set of valid, observed keys in the first match
        # and the set of configured, desired keys
        valid_keys = set(matches[0].keys()) & set(cli.args.keys)
    elif cli.args.output == "text":
        default_columns = ['name', 'label', 'organizationShortName', 'type', 'description',
                           'edgeRouterAttributes', 'serviceAttributes', 'endpointAttributes',
                           'status', 'zitiId', 'provider', 'locationCode', 'ipAddress', 'networkVersion',
                           'active', 'default', 'region', 'size', 'attributes', 'email', 'productVersion',
                           'address', 'binding', 'component']
        valid_keys = set(matches[0].keys()) & set(default_columns)

    if valid_keys:
        cli.log.debug(f"valid keys: {str(valid_keys)}")
        filtered_matches = []
        for match in matches:
            filtered_match = {key: match[key] for key in match.keys() if key in valid_keys}
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
        table = tabulate(tabular_data=[match.values() for match in filtered_matches], headers=table_headers, tablefmt=table_borders, showindex=True)
        if cli.config.general.color:
            highlighted = highlight(table, text_lexer, Terminal256Formatter(style=cli.config.general.style))
            try:
                cli.echo(highlighted)
            except ValueError:
                print(highlighted)
        else:
            try:
                cli.echo(table)
            except ValueError:
                print(table)
    elif cli.args.output == "yaml":
        if cli.config.general.color:
            highlighted = highlight(yaml_dumps(filtered_matches, indent=4), yaml_lexer, Terminal256Formatter(style=cli.config.general.style))
            try:
                cli.echo(highlighted)
            except ValueError:
                print(highlighted)
        else:
            try:
                cli.echo(yaml_dumps(filtered_matches, indent=4))
            except ValueError:
                print(yaml_dumps(filtered_matches, indent=4))
    elif cli.args.output == "json":
        if cli.config.general.color:
            highlighted = highlight(json_dumps(filtered_matches, indent=4), json_lexer, Terminal256Formatter(style=cli.config.general.style))
            try:
                cli.echo(highlighted)
            except ValueError:
                print(highlighted)
        else:
            try:
                cli.echo(json_dumps(filtered_matches, indent=4))
            except ValueError:
                print(json_dumps(filtered_matches, indent=4))


@cli.argument('query', arg_only=True, action=StoreDictKeyPair, nargs='?', help="query params as k=v,k=v comma-separated pairs")
@cli.argument('resource_type', arg_only=True, help='type of resource',
              choices=[choice for group in [[singular(type), RESOURCES[type].abbreviation] for type in RESOURCES.keys()] for choice in group])
@cli.subcommand('delete a single resource by type and query')
def delete(cli):
    """Delete a resource in the network domain."""
    spinner = get_spinner(cli, "working")
    query_keys = [*cli.args.query]
    if MUTABLE_RESOURCE_ABBREV.get(cli.args.resource_type):
        cli.args['resource_type'] = singular(MUTABLE_RESOURCE_ABBREV[cli.args.resource_type].name)
    cli.args['accept'] = None
    cli.args['embed'] = None
    cli.config.general['wait'] = 0
    spinner.text = f"Finding {cli.args.resource_type} {'by' if query_keys else '...'} {', '.join(query_keys)}"
    with spinner:
        match, network, network_group, organization = get(cli, echo=False, spinner=spinner)
    if cli.args.resource_type == 'network':
        try:
            delete_confirmed = False
            if cli.config.general.yes:
                delete_confirmed = True
            else:
                scrambled = []
                for i in range(4):
                    scrambled.extend([''.join(sample(network.name, len(match['name'])))])
                scrambled.extend([match['name']])
                shuffle(scrambled)
                spinner.stop()
                if not stdin.isatty():
                    raise InputSource
                descrambled = questions.choice(
                    "{style_bright}Enter the number of the unscrambled {fg_yellow}network{fg_reset} name to {fg_red}IRREVERSIBLY DELETE",
                    scrambled, default=None, confirm=True, prompt='{style_bright}{fg_red}DELETE{fg_reset} which {fg_yellow}network? ')
                if match['name'] == descrambled:
                    delete_confirmed = True

            if delete_confirmed:
                spinner.text = f"Deleting network '{match['name']}'"
                try:
                    with spinner:
                        network.delete_network(progress=False, wait=cli.config.general.wait)
                except Exception as e:
                    cli.log.error(f"unknown error deleting network, got {e}")
                    sysexit(1)
                else:
                    spinner.succeed(sub('Deleting', 'Deleted', spinner.text))
            else:
                spinner.fail(f"Not deleting network '{match['name']}'.")
        except KeyboardInterrupt:
            spinner.fail("Cancelled")
            sysexit(1)
        except Exception as e:
            cli.log.error(f"unknown error in {e}")
            sysexit(1)
    else:   # network child resource, not the network itself
        try:
            spinner.stop()
            delete_confirmed = False
            if cli.config.general.yes:
                delete_confirmed = True
            elif stdin.isatty():
                delete_confirmed = questions.yesno("{style_bright}{fg_red}IRREVERSIBLY DELETE{fg_yellow} "+cli.args.resource_type+" {fg_cyan}"+match['name']+" {fg_reset}", default=False)
            else:
                raise NeedUserInput("Need --yes or user input to confirm delete")

            if delete_confirmed:
                spinner.text = f"Deleting {cli.args.resource_type} '{match['name'] or match['id']}'"
                try:
                    with spinner:
                        network.delete_resource(type=cli.args.resource_type, id=match['id'])
                except KeyboardInterrupt:
                    spinner.fail("Cancelled")
                    sysexit(1)
                except Exception as e:
                    cli.log.error(f"unknown error in {e}")
                    sysexit(1)
                else:
                    spinner.succeed(sub('Deleting', 'Deleted', spinner.text))
            else:
                spinner.fail(f"Not deleting {cli.args.resource_type} '{match['name']}'")
        except KeyboardInterrupt:
            spinner.fail("Cancelled")
            sysexit(1)
        except Exception as e:
            cli.log.error(f"unknown error in {e}")
            sysexit(1)


@cli.argument("-p", "--prefix", default=f"{cli.prog_name}-demo", help="choose a network name prefix to identify all of your demos")
@cli.argument("-j", "--jwt", action="store_boolean", default=True, help="save the one-time enroll token for each demo identity in the current directory")
@cli.argument("-e", "--echo-name", arg_only=True, action="store_true", default=False, help="only echo a friendly network name then exit")
@cli.argument("-s", "--size", default="medium", help=argparse.SUPPRESS)   # troubleshoot scale-up instance size factor
@cli.argument("-v", "--product-version", default="default", help="network product version: 'default', 'latest', or any active semver")
@cli.argument("--provider", default="AWS", help="cloud provider for hosted edge routers", choices=DC_PROVIDERS)
@cli.argument("--regions", dest="regions", default=["us-west-1"], nargs="+", help="provider regions for hosted edge routers")
@cli.subcommand('create a functioning demo network')
def demo(cli):
    """Create a demo network or add demo resources to existing network."""
    spinner = get_spinner(cli, "working")
    with spinner:
        organization, networks = use_organization(cli, spinner)
    if cli.config.general.network:
        network_name = cli.config.general.network
    else:
        friendly_words_dir = path.join(path.dirname(__file__), 'friendly-words')
        friendly_words_filename = path.join(friendly_words_dir, "generated/words.json")
        with open(friendly_words_filename, 'r') as friendly_words_path:
            friendly_words = json_load(friendly_words_path)
        network_name = f"{cli.config.demo.prefix}-{choice(friendly_words['predicates'])}-{choice(friendly_words['objects'])}"
        if cli.args.echo_name:
            cli.echo(network_name)
            sysexit(0)
    demo_confirmed = False
    if cli.config.general.yes:
        demo_confirmed = True
    elif stdin.isatty():
        spinner.stop()  # always stop for questions
        demo_confirmed = questions.yesno(f"Run demo in network {network_name} ({organization.label}) now?")
    else:
        raise NeedUserInput("Need --yes or user input to confirm delete")

    if demo_confirmed:
        spinner.text = f"Finding network '{network_name}'"
    else:
        spinner.fail("Demo cancelled")
        cli.run(command=["nfctl", "demo", "--help"], capture_output=False)
        sysexit(1)

    with spinner:
        # create network unless exists
        cli.log.setLevel(logging.WARN)   # FIXME: hack to silence redundant spinners
        network_group = use_network_group(
            cli,
            organization,
            cli.config.general.network_group)
        cli.log.setLevel(logging.INFO)   # FIXME: hack to silence redundant spinners
        if network_group.network_exists(network_name):
            network, network_group = use_network(
                cli,
                organization=organization,
                group=network_group.id,
                network_name=network_name,
                spinner=spinner)
            spinner.succeed(f"Found network '{network_name}'")
        else:
            cli.log.debug(f"creating network named '{network_name}'")
            spinner.text = f"Creating network '{network_name}'"
            network_created = network_group.create_network(
                name=network_name,
                size=cli.config.demo.size,
                version=cli.config.demo.product_version,
                wait=0)  # FIXME: don't use wait > 0 until process-executions beta is launched, until then poll for status
            network, network_group = use_network(
                cli,
                organization=organization,
                group=cli.config.general.network_group,
                network_name=network_created['name'],
                spinner=spinner)
            spinner.succeed(sub('Creating', 'Created', spinner.text))
    # existing hosted routers
    spinner.text = "Finding hosted routers"
    with spinner:
        hosted_edge_routers = network.edge_routers(only_hosted=True)
    # a list of locations to place a hosted router
    fabric_placements = []
    for region in cli.config.demo.regions:
        dc_matches = network.find_edge_router_data_centers(provider=cli.config.demo.provider, location_code=region)
        if not len(dc_matches) == 1:
            raise RuntimeError(f"invalid region '{region}'")
        else:
            existing_count = len([er for er in hosted_edge_routers if er['provider'] == cli.config.demo.provider and er['region'] == region])
        if existing_count < 1:             # allow any existing hosted router matching region and provider to satisfy placement
            fabric_placements += [region]  # otherwise queue for placement
        else:
            spinner.succeed(f"Found a hosted router in {region}")

    spinner.text = f"Creating {len(fabric_placements)} hosted router(s)"
    with spinner:
        for region in fabric_placements:
            er_name = f"Hosted Router {region} [{cli.config.demo.provider}]"
            if not network.edge_router_exists(er_name):
                er = network.create_edge_router(
                    name=er_name,
                    attributes=[
                        "#hosted_routers",
                        "#demo_exits",
                        f"#{cli.config.demo.provider}",
                    ],
                    provider=cli.config.demo.provider,
                    location_code=region,
                    tunneler_enabled=False,  # workaround for MOP-18098 (missing tunneler binding in ziti-router config)
                )
                hosted_edge_routers.extend([er])
                spinner.succeed(f"Created {cli.config.demo.provider} router in {region}")
            else:
                er_matches = network.edge_routers(name=er_name, only_hosted=True)
                if len(er_matches) == 1:
                    er = er_matches[0]
                else:
                    raise RuntimeError(f"unexpectedly found more than one matching router for name '{er_name}'")
                if er['status'] in RESOURCES["edge-routers"].status_symbols["error"] + RESOURCES["edge-routers"].status_symbols["deleting"] + RESOURCES["edge-routers"].status_symbols["deleted"]:
                    raise RuntimeError(f"hosted router '{er_name}' has unexpected status '{er['status']}'")

    if not len(hosted_edge_routers) > 0:
        raise RuntimeError("unexpected problem with router placements, found zero hosted routers")

    spinner.text = f"Waiting for {len(hosted_edge_routers)} hosted router(s) to provision"
    with spinner:
        for router in hosted_edge_routers:
            network.wait_for_statuses(expected_statuses=RESOURCES["edge-routers"].status_symbols["complete"], id=router['id'], type="edge-router", wait=2222, progress=False)
            # ensure the router tunneler is available
            # network.wait_for_entity_name_exists(entity_name=router['name'], entity_type='endpoint')
            # router_tunneler = network.find_resources(type='endpoint', name=router['name'])[0]
            # router_tunneler['attributes'] = ['#demo_exits']
            # network.patch_resource(router_tunneler)
    spinner.succeed("All hosted routers online")

    # create a simple global router policy unless one exists with the same name
    blanket_policy_name = "Default Edge Router Policy"
    spinner.text = "Finding router policy"
    with spinner:
        if not network.edge_router_policy_exists(name=blanket_policy_name):
            try:
                spinner.text = f"Creating router policy '{blanket_policy_name}'"
                with spinner:
                    network.create_edge_router_policy(
                        name=blanket_policy_name,
                        edge_router_attributes=["#hosted_routers"],
                        endpoint_attributes=["#all"])
            except Exception as e:
                raise RuntimeError(f"error creating edge router policy, got {e}")
            else:
                spinner.succeed(sub('Creating', 'Created', spinner.text))
        else:
            spinner.succeed(f"Found router policy '{blanket_policy_name}'")

    endpoints = dict()
    clients = ['Desktop', 'Mobile', 'Laptop']
    for client in clients:
        endpoints[client] = {
            "attributes": ["#work_from_anywhere"]
        }
    exits = ['Exit Tunneler']
    for exit in exits:
        endpoints[exit] = {
            "attributes": ["#demo_exits"]
        }
    for end, spec in endpoints.items():
        spinner.text = f"Finding endpoint '{end}'"
        with spinner:
            if not network.endpoint_exists(name=end):
                # create an endpoint for the dialing device that will access services
                spinner.text = f"Creating endpoint '{end}'"
                endpoints[end]['properties'] = network.create_endpoint(name=end, attributes=spec['attributes'])
                spinner.succeed(sub('Creating', 'Created', spinner.text))
            else:
                spec['properties'] = network.endpoints(name=end)[0]
                spinner.succeed(sub('Finding', 'Found', spinner.text))
            if cli.args.jwt and spec['properties'].get('jwt'):  # save if --jwt, token is absent if already enrolled
                jwt = spec['properties']['jwt']
                with open(end+'.jwt', 'wt') as tf:
                    tf.write(jwt)
                    cli.log.info(f"Saved enrollment token in {tf.name}")

    services = {
        "Fireworks Service": {
            "client_attributes": ["#welcome_wagon"],
            "tcp_port": "80",
            "client_domain": "fireworks.netfoundry",
            "exit_attributes": choice(hosted_edge_routers)['id'],
            "exit_domain": "fireworks-load-balancer-1246256380.us-east-1.elb.amazonaws.com",
        },
        # "Weather Service": {
        #     "client_attributes": ["#welcome_wagon"],
        #     "tcp_port": "80",
        #     "client_domain": "weather.netfoundry",
        #     "exit_attributes": ["#demo_exits"],
        #     "exit_domain": "wttr.in",
        # },
        "Echo Service": {
            "client_attributes": ["#welcome_wagon"],
            "tcp_port": "80",
            "client_domain": "echo.netfoundry",
            "exit_attributes": choice(hosted_edge_routers)['id'],
            "exit_domain": "eth0.me",
        },
    }
    for svc in services.keys():
        spinner.text = f"Finding service '{svc}'"
        with spinner:
            if not network.service_exists(name=svc):
                spinner.text = f"Creating service '{svc}'"
                services[svc]['properties'] = network.create_service(
                    name=svc,
                    attributes=services[svc]['client_attributes'],
                    egress_router_id=services[svc]['exit_attributes'],
                    client_host_name=services[svc]['client_domain'],
                    server_host_name=services[svc]['exit_domain'],
                    client_port=services[svc]['tcp_port'],
                    server_port=services[svc]['tcp_port'],
                )
                spinner.succeed(sub('Creating', 'Created', spinner.text))
            else:
                services[svc]['properties'] = network.services(name=svc)[0]
                spinner.succeed(sub("Finding", "Found", spinner.text))

    # create a customer-hosted ER unless exists
    customer_router_name = "Branch Exit Router"
    spinner.text = f"Finding customer router '{customer_router_name}'"
    with spinner:
        if not network.edge_router_exists(name=customer_router_name):
            spinner.text = sub("Finding", "Creating", spinner.text)
            customer_router = network.create_edge_router(
                name=customer_router_name,
                attributes=["#branch_exit_routers"],
                tunneler_enabled=True)
        else:
            customer_router = network.edge_routers(name=customer_router_name)[0]
            spinner.succeed(sub("Finding", "Found", spinner.text))

    spinner.text = f"Waiting for customer router {customer_router_name} to be ready for registration"
    # wait for customer router to be PROVISIONED so that registration will be available
    with spinner:
        try:
            network.wait_for_statuses(expected_statuses=RESOURCES["edge-routers"].status_symbols["complete"], id=customer_router['id'], type="edge-router", wait=222, progress=False)
            customer_router_registration = network.rotate_edge_router_registration(id=customer_router['id'])
        except Exception as e:
            raise RuntimeError(f"error getting router registration, got {e}")
        else:
            spinner.succeed(f"Customer router ready to register with key '{customer_router_registration['registrationKey']}'")

    # create unless exists
    app_wan_name = "Default Service Policy"
    spinner.text = "Finding service policy"
    with spinner:
        if not network.app_wan_exists(name=app_wan_name):
            # work_from_anywhere may connect to welcome_wagon
            spinner.text = sub("Finding", "Creating", spinner.text)
            network.create_app_wan(
                name=app_wan_name,
                endpoint_attributes=["#work_from_anywhere"],
                service_attributes=["#welcome_wagon"])
            spinner.succeed(sub("Creating", "Created", spinner.text))
        else:
            # app_wan = network.app_wans(name=app_wan_name)[0]
            spinner.text = sub("Finding", "Found", spinner.text)

    spinner.succeed("Demo network is ready")

    for svc in services:
        cli.log.info(f"{svc}:\thttp://{services[svc]['properties']['model']['clientIngress']['host']}/")
    cli.log.info("Demo Guide: https://developer.netfoundry.io/guides/demo/")


def use_organization(cli, spinner: object = None, prompt: bool = True):
    """Cache an expiring token for an identity and configure access to the network domain."""
    if not spinner:
        spinner = get_spinner(cli, "working")
    else:
        cli.log.debug("got spinner as function param")
    spinner.text = f"Loading profile '{cli.config.general.profile}'"
    # use the session with some organization, default is to use the first and there's typically only one
    try:
        with spinner:
            organization = Organization(
                credentials=cli.config.general.credentials if cli.config.general.credentials else None,
                organization=cli.config.general.organization if cli.config.general.organization else None,
                profile=cli.config.general.profile,
                expiry_minimum=0,
                proxy=cli.config.general.proxy,
                logger=cli.log,
            )
    except NFAPINoCredentials:
        if prompt:
            cli.log.debug("caught no credentials exception from organization, prompting for token")
            try:
                spinner.stop()
                token_from_prompt = questions.password(prompt='Enter Bearer Token:', confirm=False, validate=is_jwt)
            except KeyboardInterrupt:
                spinner.fail("Cancelled")
                sysexit(1)
            except Exception as e:
                cli.log.error(f"unknown error in {e}")
                sysexit(1)

            try:
                spinner.text = f"Trying token for profile '{cli.config.general.profile}'"
                with spinner:
                    organization = Organization(
                        token=token_from_prompt,
                        organization=cli.config.general.organization if cli.config.general.organization else None,
                        profile=cli.config.general.profile,
                        expiry_minimum=0,
                        proxy=cli.config.general.proxy,
                        logger=cli.log,
                    )
            except PyJWTError:
                spinner.fail("Not a valid token")
                sysexit(1)
            except Exception as e:
                raise RuntimeError(f"unknown error in {e}")
        else:
            spinner.fail("Not logged in")
            raise NFAPINoCredentials()
    spinner.succeed(f"Logged in profile '{cli.config.general.profile}'")
    cli.log.debug(f"logged-in organization label is {organization.label}.")
    networks = Networks(Organization=organization)
    return organization, networks


def use_network_group(cli, organization: object, group: str = None, spinner: object = None):
    """
    Use a network group.

    :param spinner: the spinner object from parent flow is used and returned
    :param organization: the netfoundry.Organization object representing the current session
    :param str group: name or UUIDv4 of group to use
    """
    if not spinner:
        spinner = get_spinner(cli, "working")
    else:
        cli.log.debug("got spinner as function param")
    # module will use first available group if not specified, and typically there is only one
    spinner.text = f"Configuring network group '{group}'"
    with spinner:
        network_group = NetworkGroup(
            organization,
            group=group,
        )
    spinner.succeed(f"Configured network group '{network_group.name}'")
    cli.log.debug(f"network group is {network_group.name}")
    return network_group


def use_network(cli, organization: object, network_name: str = None, group: str = None, spinner: object = None):
    """
    Use a network.

    :param spinner: the spinner object from parent flow is used and returned
    :param organization: the netfoundry.Organization object representing the current session
    :param network_name: name of the network to use, optional if there's only one
    :param group: a network group name or UUID, optional if network name is unique across all available groups
    """
    if not spinner:
        spinner = get_spinner(cli, "working")
    else:
        cli.log.debug("got spinner as function param")
    if not network_name:
        spinner.text = "Finding networks"
        if group:
            network_group = use_network_group(
                cli,
                organization=organization,
                group=group,
                spinner=spinner)
            existing_networks = network_group.networks_by_name()
        else:
            existing_networks = organization.find_networks_by_organization()
        if len(existing_networks) == 1:
            network_name = existing_networks[0]['name']

            cli.log.debug(f"using the only available network: '{network_name}'")
        else:
            cli.log.error("You have multiple networks, which one would you like to use? Need 'nfctl --network=NETWORK' or 'nfctl config.general.network=NETWORK'.")
            sysexit(1)
    elif group:
        network_group = use_network_group(
            cli,
            organization=organization,
            group=group,
            spinner=spinner)
        existing_networks = network_group.network_ids_by_normal_name
        if not existing_networks.get(normalize_caseless(network_name)):
            cli.log.error(f"failed to find a network named '{network_name}' in network group '{network_group['name']}'.")
            sysexit(1)
    else:
        existing_count = organization.count_networks_with_name(network_name)
        if existing_count == 1:
            existing_networks = organization.find_networks_by_organization(name=network_name)
            existing_network = existing_networks[0]
            network_group = use_network_group(
                cli,
                organization,
                group=existing_network['networkGroupId'],
                spinner=spinner)
        elif existing_count > 1:
            cli.log.error(f"there were {existing_count} networks named '{network_name}' visible to your identity. Try narrowing the search with '--network-group=NETWORK_GROUP'.")
            sysexit(1)
        else:
            cli.log.error(f"failed to find a network named '{network_name}'.")
            sysexit(1)

    # use the network
    spinner.text = f"Configuring network '{network_name}'"
    with spinner:
        network = Network(network_group, network_name=network_name)
        if network.status in RESOURCES['networks'].status_symbols['deleting'] + RESOURCES['networks'].status_symbols['deleted'] + RESOURCES['networks'].status_symbols['error']:
            cli.log.error(f"network {network.name} has status {network.status}")
        elif not cli.config.general.wait:
            cli.log.debug("wait seconds is 0, not waiting for network to provision")
        elif not network.status == 'PROVISIONED':
            try:
                spinner.text = f"Waiting for network {network.name} to provision"
                network.wait_for_statuses(expected_statuses=RESOURCES["networks"].status_symbols["complete"], wait=600, progress=False)
            except KeyboardInterrupt:
                spinner.fail("Cancelled")
                sysexit(1)
            except Exception as e:
                raise RuntimeError(f"unknown error in {e}")
    spinner.succeed(sub("Configuring", "Configured", spinner.text))
    return network, network_group


def edit_object_as_yaml(cli, edit: object):
    """Edit a resource object as YAML and return as object upon exit.

    :param obj input: a deserialized (object) to edit and return as yaml
    """
    # unless --yes (config general.yes), if stdout is connected to a terminal
    # then open input for editing and send on exit
    if cli.config.general.yes or not stdout.isatty():
        return edit
    save_error = False
    editor = environ.get('NETFOUNDRY_EDITOR', environ.get('EDITOR', 'vim'))
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
            edited_no_comments += re.sub(r'^(\s+)?#.*', '', line)
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
        cli.log.error(f"your buffer was saved in {temp_file}")
        sysexit(1)


def get_spinner(cli, text):
    """
    Get a spinner.

    Enabled if stdout is a tty and log level is >= INFO, else disabled to not
    corrupt structured output.
    """
    inner_spinner = cli.spinner(text=text, spinner='dots12', placement='left', color='green', stream=stdout)
    if not stdout.isatty():
        inner_spinner.enabled = False
        cli.log.debug("spinner disabled because stdout is not a tty")
    elif ('eval' in dir(cli.args) and cli.args.eval):
        inner_spinner.enabled = False
        cli.log.debug("spinner disabled because output evaluation mode is enabled")
    elif cli.config.general.verbose:
        inner_spinner.enabled = False
        cli.log.debug("spinner disabled because DEBUG is enabled")
    elif cli.log.getEffectiveLevel() > logging.INFO:
        inner_spinner.enabled = False
        cli.log.debug("spinner disabled because logging level is higher than INFO")
    else:
        inner_spinner.enabled = True
    return inner_spinner


yaml_lexer = get_lexer_by_name("yaml", stripall=True)
json_lexer = get_lexer_by_name("json", stripall=True)
bash_lexer = get_lexer_by_name("bash", stripall=True)
cwd = path.dirname(__file__)
text_lexer_filename = path.join(cwd, "table_lexer.py")
text_lexer = load_lexer_from_file(text_lexer_filename, "NetFoundryTableLexer")

if __name__ == '__main__':
    cli()
