#!/usr/bin/env python3
r"""Command-line interface for the NetFoundry Management API.

Usage:
    $ python3 -m netfoundry.mgmt --network BibbidiBobbidiBoo
"""
import argparse
import os
import sys
import platform
import tempfile

from .network import Network
from .network_group import NetworkGroup
from .organization import Organization
from .utility import Utility

utility = Utility()

def main():
    """Use the Management API."""
    #print("DEBUG: running script in \"{:s}\"".format(sys.argv[0]))

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        nargs='?',
        default="download",
        help="the command to run",
        choices=["download","login"]
    )
    parser.add_argument(
        "-n", "--network",
        required=True,
        help="The name of the network"
    )
    parser.add_argument(
        "-o", "--organization",
        help="The label of an alternative organization (default is Org of caller)"
    )
    parser.add_argument(
        "-g", "--network-group",
        default=None,
        dest="network_group",
        help="The shortname of a Network Group (default is the first, typically singular, Group known to this Org)"
    )
    parser.add_argument("--credentials",
        default=None,
        help="path to API account credentials JSON file overrides NETFOUNDRY_API_ACCOUNT"
    )
    parser.add_argument("--proxy",
        default=None,
        help="'http://localhost:8080'"+
        " 'socks5://localhost:9046'"
    )
    args = parser.parse_args()

    if not 'NETFOUNDRY_API_TOKEN' in os.environ and not 'NETFOUNDRY_API_ACCOUNT' in os.environ and not args.credentials:
        os.environ['NETFOUNDRY_API_TOKEN'] = query_bearer_token("Paste bearer token (JWT) for an identity with resource action grant \"read-platform-protected\".")
    elif 'NETFOUNDRY_API_TOKEN' in os.environ:
        print("INFO: using NETFOUNDRY_API_TOKEN from environment")
    elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
        print("INFO: using NETFOUNDRY_API_ACCOUNT from environment")
    elif 'credentials' in args:
        print("INFO: using credentials file {} from args".format(args.credentials))
    else:
        print("ERROR: missing token or credentials file")
        sys.exit(1)

    network_name = args.network
    
    # use the session with some organization, default is to use the first and there's typically only one
    organization = Organization(
        credentials=args.credentials if 'credentials' in args else None,
        organization_label=args.organization if 'organization' in args else None,
        proxy=args.proxy
    )
    print("DEBUG: organization label is {label}.".format(label=organization.label))

    if args.network_group:
        network_group = NetworkGroup(
            organization,
            network_group_name=args.network_group
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

    if args.command == "login":
        if platform.system() == 'Windows':
            ziti_cli = 'ziti.exe'
        else:
            ziti_cli = 'ziti'
        tempdir = tempfile.mkdtemp()

        network_controller = network.get_resource_by_id(type="network-controller", id=network.network_controller_id)

        ziti_ctrl_ip = network_controller['_embedded']['host']['ipAddress']

        try:
            secrets = network.get_controller_secrets(network.network_controller_id)
            os.system('curl -sSfk https://'+ziti_ctrl_ip+'/.well-known/est/cacerts | openssl base64 -d | openssl pkcs7 -inform DER -outform PEM -print_certs -out '+tempdir+'/well-known-certs.pem')
            os.system(ziti_cli+' edge login '+ziti_ctrl_ip+' -u '+secrets['zitiUserId']+' -p '+secrets['zitiPassword']+' -c '+tempdir+'/well-known-certs.pem')
            os.system(ziti_cli+' edge --help')
        except:
            raise

def query_bearer_token(question: str):
    """Obtain a bearer token via input() and return the answer.

    :param question: a string that is presented to the user.
    """
    prompt = ' > '
    while True:
        sys.stdout.write(question + prompt)
        bearer_token = input()
        return bearer_token

if __name__ == '__main__':
    main()


# else:
#     get identities self id
#     check grants for read-platform-protected 
#         ❯ http GET "https://gateway.$MOPENV.netfoundry.io/auth/v1/grants?resourceActionId=${RESOURCE_ACTION_ID}&identityId=${SELF_ID}" \
#         "Authorization: Bearer ${NETFOUNDRY_API_TOKEN}" | jq
