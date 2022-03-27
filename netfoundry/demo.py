#!/usr/bin/env python3
r"""This script demonstrates the NetFoundry Python module.

Usage:
    $ python3 -m netfoundry.demo --network BibbidiBobbidiBoo
"""
import argparse
import logging
import os
import random
import sys
from pathlib import Path

from .network import Network
from .network_group import NetworkGroup
from .organization import Organization
from .utility import DC_PROVIDERS


def main(raw_args=None):
    """Run the demo script."""
    print("DEBUG: running demo script in \"{:s}\"".format(sys.argv[0]))

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--verbose", "--debug",
        dest="verbose",
        default=False,
        action="store_true",
        help="emit debug messages"
    )
    parser.add_argument(
        "-y", "--yes",
        dest="yes",
        default=False,
        action="store_true",
        help="Skip interactive prompt to confirm destructive actions."
    )
    parser.add_argument(
        "-n", "--network",
        required=True,
        help="The name of your demo network"
    )
    parser.add_argument(
        "-o", "--organization",
        help="The label of an alternative organization (default is org of caller)"
    )
    parser.add_argument(
        "-g", "--network-group",
        dest="network_group",
        help="The shortname of a Network Group (default is the first, typically singular, Group known to this Org)"
    )
    parser.add_argument(
        "-s", "--network-size",
        dest="size",
        default="small",
        help="Network size to create",
        choices=["small","medium","large"]
    )
    parser.add_argument(
        "-v", "--network-version",
        dest="version",
        default="default",
        help="Network product version: \"default\", \"latest\", or semver"
    )
    parser.add_argument(
        "-p", "--create-private",
        dest="private",
        default=False,
        action="store_true",
        help="Also create private Endpoint-hosted Services for the optional Docker Compose portion of the quickstart"
    )
    parser.add_argument(
        "-c", "--create-client",
        dest="client",
        default=False,
        action="store_true",
        help="Also create a client Endpoint for the optional Linux portion of the quickstart"
    )
    parser.add_argument("--credentials",
        default=None,
        help="path to API account credentials JSON file overrides NETFOUNDRY_API_ACCOUNT"
    )
    parser.add_argument("--provider",
        default="AWS",
        required=False,
        help="cloud provider to host Edge Routers",
        choices=DC_PROVIDERS
    )
    parser.add_argument("--regions",
        dest="regions",
        default=["us-west-1"],
        nargs="+",
        help="cloud location codes in which to host Edge Routers"
    )
    parser.add_argument("--proxy",
        default=None,
        help="'http://localhost:8080'"+
        " 'socks5://localhost:9046'"
    )
    args = parser.parse_args(raw_args)

    if args.verbose:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging_level)

    network_name = args.network
    
    # use the session with some organization, default is to use the first and there's typically only one
    organization = Organization(
        credentials=args.credentials if 'credentials' in args else None,
        organization_label=args.organization if 'organization' in args else None,
        proxy=args.proxy
    )

    # use some Network Group, default is to use the first and there's typically only one
    network_group = NetworkGroup(
        organization,
        network_group_name=args.network_group if 'network_group' in args else None
    )

    # create a Network
    if network_group.network_exists(network_name):
        # use the Network
        network = Network(network_group, network_name=network_name)
        network.wait_for_status("PROVISIONED",wait=999,progress=True)
    else:
        logging.debug(f"creating network named {network_name}")
        network_id = network_group.create_network(name=network_name,size=args.size,version=args.version)['id']
        network = Network(network_group, network_id=network_id)
        network.wait_for_status("PROVISIONED",wait=999,progress=True)

    # existing hosted routers
    hosted_edge_routers = network.edge_routers(only_hosted=True)
    # a list of places where endpoints are dialing from

    # a list of locations to place a hosted router
    fabric_placements = list()
    if args.regions:
        for region in args.regions:
            existing_count = len([er for er in hosted_edge_routers if er['provider'] == args.provider and er['region'] == region])
            if existing_count < 1:
                fabric_placements += [region]
            else:
                logging.info(f"found a hosted router in {region}")

        for region in fabric_placements:
            er = network.create_edge_router(
                name=f"Hosted Router {region} [{args.provider}]",
                attributes=[
                    "#defaultRouters",
                    f"#{region}",
                    f"#{args.provider}",
                ],
                provider=args.provider,
                location_code=region
            )
            hosted_edge_routers.extend(er)
            logging.info(f"placed router in {args.provider} ({region})")

    try:
        assert(len(hosted_edge_routers) > 0)
    except Exception as e:
        raise RuntimeError("unexpected error with router placements, found zero hosted router")

    for router_id in [r['id'] for r in hosted_edge_routers]:
        try:
            network.wait_for_status("PROVISIONED",id=router_id,type="edge-router",wait=999,progress=True)
        except Exception as e:
            raise RuntimeError(f"error while waiting for router status, got {e}")

    # create a simple global Edge Router Policy unless one exists with the same name
    blanket_policy_name = "defaultRouters"
    if not network.edge_router_policy_exists(name=blanket_policy_name):
        try: 
            network.create_edge_router_policy(name=blanket_policy_name,edge_router_attributes=["#defaultRouters"],endpoint_attributes=["#all"])
        except Exception as e: 
            raise RuntimeError(f"error creating edge router policy, got {e}")

    clients = list()
    client1_name = "Desktop1"
    if not network.endpoint_exists(name=client1_name):
        # create an Endpoint for the dialing device that will access Services
        client1 = network.create_endpoint(name=client1_name,attributes=["#workFromAnywhere"])
        print("INFO: created Endpoint \"{:s}\"".format(client1['name']))
    else:
        client1 = network.endpoints(name=client1_name)[0]
        print("INFO: found Endpoint \"{:s}\"".format(client1['name']))
    clients += [client1]

    client2_name = "Mobile1"
    if not network.endpoint_exists(name=client2_name):
        # create an Endpoint for the dialing device that will access Services
        client2 = network.create_endpoint(name=client2_name,attributes=["#workFromAnywhere"])
        print("INFO: created Endpoint \"{:s}\"".format(client2['name']))
    else:
        client2 = network.endpoints(name=client2_name)[0]
        print("INFO: found Endpoint \"{:s}\"".format(client2['name']))
    clients += [client2]

    if args.client:
        client3_name = "Linux1"
        if not network.endpoint_exists(name=client3_name):
            # create an Endpoint for the dialing device that will access Services
            client3 = network.create_endpoint(name=client3_name,attributes=["#workFromAnywhere"])
            print("INFO: created Endpoint \"{:s}\"".format(client3['name']))
        else:
            client3 = network.endpoints(name=client3_name)[0]
            print("INFO: found Endpoint \"{:s}\"".format(client3['name']))
        clients += [client3]

    exits = list()
    if args.private:
        exit1_name = "Exit1"
        if not network.endpoint_exists(name=exit1_name):
            # create an Endpoint for the hosting device that will provide access to the server
            exit1 = network.create_endpoint(name=exit1_name,attributes=["#exits"])
            print("INFO: created Endpoint \"{:s}\"".format(exit1['name']))
        else:
            exit1 = network.endpoints(name=client3_name)[0]
            print("INFO: found Endpoint \"{:s}\"".format(exit1['name']))
        exits += [exit1]

    # the demo containers have the demo working dir mounted on /netfoundry
    if os.access('/netfoundry', os.W_OK):
        token_path = '/netfoundry' # nosec
    else:
        token_path = str(Path.cwd())
    for end in clients+exits:
        token_file = token_path+'/'+end['name']+'.jwt'
        if end['jwt']:
            text = open(token_file, "wt")
            text.write(end['jwt'])
            text.close()
        else:
            if os.path.exists(token_file):
                print("DEBUG: cleaning up used OTT for enrolled Endpoint {end} from {path}".format(end=end['name'],path=token_file))
                os.remove(token_file)

    demo_services = dict()

    if args.private:
        # create Endpoint-hosted Services unless name exists
        demo_services['hello_service'] = dict()
        demo_services['hello_service']['display_name'] = "Hello Service"
        if not network.service_exists(name=demo_services['hello_service']['display_name']):
            # traffic sent to hello.netfoundry:80 leaves Endpoint exit1 to server hello:3000
            demo_services['hello_service']['entity'] = network.create_service(
                name=demo_services['hello_service']['display_name'],
                attributes=["#welcomeWagon"],
                client_host_name="hello.netfoundry",
                client_port="80",
                endpoints=[exit1['id']],
                server_host_name="hello",
                server_port="3000",
                server_protocol="TCP"
            )
            print("INFO: created Service \"{:s}\"".format(demo_services['hello_service']['entity']['name']))
        else:
            demo_services['hello_service']['entity'] = network.services(name=demo_services['hello_service']['display_name'])[0]
            print("INFO: found Service \"{:s}\"".format(demo_services['hello_service']['entity']['name']))

        demo_services['rest_service'] = dict()
        demo_services['rest_service']['display_name'] = "REST Service"
        if not network.service_exists(name=demo_services['rest_service']['display_name']):
            # traffic sent to httpbin.netfoundry:80 leaves Endpoint exit1 to server httpbin:80
            demo_services['rest_service']['entity'] = network.create_service(
                name=demo_services['rest_service']['display_name'],
                attributes=["#welcomeWagon"],
                client_host_name="httpbin.netfoundry",
                client_port="80",
                endpoints=[exit1['id']],
                server_host_name="httpbin",
                server_port="80",
                server_protocol="TCP"
            )
            print("INFO: created Service \"{:s}\"".format(demo_services['rest_service']['entity']['name']))
        else:
            demo_services['rest_service']['entity'] = network.services(name=demo_services['rest_service']['display_name'])[0]
            print("INFO: found Service \"{:s}\"".format(demo_services['rest_service']['entity']['name']))

    # Create router-hosted Services unless exists
    hosting_router = random.choice(hosted_edge_routers) # nosec

    demo_services['fireworks_service'] = dict()
    demo_services['fireworks_service']['display_name'] = "Fireworks Service"
    if not network.service_exists(name=demo_services['fireworks_service']['display_name']):
        # traffic sent to fireworks.netfoundry:80 leaves Routers to 34.204.78.203:80
        demo_services['fireworks_service']['entity'] = network.create_service(
            name=demo_services['fireworks_service']['display_name'],
            attributes=["#welcomeWagon"],
            client_host_name="fireworks.netfoundry",
            client_port="80",
            egress_router_id=hosting_router['id'],
            server_host_name="fireworks-load-balancer-1246256380.us-east-1.elb.amazonaws.com",
            server_port="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(demo_services['fireworks_service']['entity']['name']))
    else:
        demo_services['fireworks_service']['entity'] = network.services(name=demo_services['fireworks_service']['display_name'])[0]
        print("INFO: found Service \"{:s}\"".format(demo_services['fireworks_service']['entity']['name']))

    demo_services['weather_service'] = dict()
    demo_services['weather_service']['display_name'] = "Weather Service"
    if not network.service_exists(name=demo_services['weather_service']['display_name']):
        # traffic sent to weather.netfoundry:80 leaves Routers to wttr.in:80
        demo_services['weather_service']['entity'] = network.create_service(
            name=demo_services['weather_service']['display_name'],
            attributes=["#welcomeWagon"],
            client_host_name="weather.netfoundry",
            client_port="80",
            egress_router_id=hosting_router['id'],
            server_host_name="wttr.in",
            server_port="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(demo_services['weather_service']['entity']['name']))
    else:
        demo_services['weather_service']['entity'] = network.services(name=demo_services['weather_service']['display_name'])[0]
        print("INFO: found Service \"{:s}\"".format(demo_services['weather_service']['entity']['name']))

    # fireworks
    # heartbeat
    
    demo_services['echo_service'] = dict()
    demo_services['echo_service']['display_name'] = "Echo Service"
    if not network.service_exists(name=demo_services['echo_service']['display_name']):
        # traffic sent to echo.netfoundry:80 leaves Routers to eth0.me:80
        demo_services['echo_service']['entity'] = network.create_service(
            name=demo_services['echo_service']['display_name'],
            attributes=["#welcomeWagon"],
            client_host_name="echo.netfoundry",
            client_port="80",
            egress_router_id=hosting_router['id'],
            server_host_name="eth0.me",
            server_port="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(demo_services['echo_service']['entity']['name']))
    else:
        demo_services['echo_service']['entity'] = network.services(name=demo_services['echo_service']['display_name'])[0]
        print("INFO: found Service \"{:s}\"".format(demo_services['echo_service']['entity']['name']))

    # create a customer-hosted ER unless exists
    customer_router_name="Branch Exit Router 1"
    if not network.edge_router_exists(name=customer_router_name):
        customer_router = network.create_edge_router(
            name=customer_router_name,
            attributes=["#vmWareExitRouters"],
            tunneler_enabled=True
        )
    else:
        customer_router = network.edge_routers(name=customer_router_name)[0]

    # wait for customer router to be PROVISIONED so that registration will be available 
    try:
        network.wait_for_status("PROVISIONED",id=customer_router['id'],type="edge-router",wait=999,progress=True)
        customer_router_registration = network.rotate_edge_router_registration(id=customer_router['id'])
    except Exception as e:
        raise RuntimeError(f"error getting router registration, got {e}")
    print("INFO: Ready to register branch exit Edge Router {name} with key {key} (expires {expiry})".format(
        name=customer_router_name,
        key=customer_router_registration['registrationKey'],
        expiry=customer_router_registration['expiresAt'],
    ))

    # create unless exists
    app_wan1_name = "Welcome"
    if not network.app_wan_exists(name=app_wan1_name):
        # workFromAnywhere may connect to welcomeWagon
        app_wan1 = network.create_app_wan(name=app_wan1_name,endpoint_attributes=["#workFromAnywhere"],service_attributes=["#welcomeWagon"])
        print("INFO: created AppWAN \"{:s}\"".format(app_wan1['name']))
    else:
        app_wan1 = network.app_wans(name=app_wan1_name)[0]
        print("INFO: found AppWAN \"{:s}\"".format(app_wan1['name']))

    print("SUCCESS! The next step is to enroll one or more of your client endpoints on some device(s) and visit one of the demo Service URLs described in the demo document ({doc})."
            "You may also log in to the web console ({nfconsole}) to play with your Network".format(doc="https://developer.netfoundry.io/v2/tools/#demos",nfconsole=network_group.nfconsole))
    for svc in demo_services:
        print("* {name}:\thttp://{url}/".format(name=demo_services[svc]['entity']['name'],url=demo_services[svc]['entity']['model']['clientIngress']['host']))

def query_yes_no(question: str, default: str="no"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
            "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError(f"invalid default answer: '{default}'")

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                            "(or 'y' or 'n').\n")

if __name__ == '__main__':
    main()
