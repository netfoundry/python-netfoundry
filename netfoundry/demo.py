#!/usr/bin/env python3
r"""Example script to create a NetFoundry Network
Usage::
    $ python3 -m netfoundry.demo BibbidiBobbidiBoo
"""

import netfoundry
import sys
import random
import os
from pathlib import Path
import argparse

def main():

    print("DEBUG: running demo script in \"{:s}\"".format(sys.argv[0]))

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        nargs='?',
        default="create",
        help="the command to run",
        choices=["create","delete"]
    )
    parser.add_argument(
        "-n", "--network",
        help="The name of your demo network"
    )
    parser.add_argument(
        "-o", "--organization",
        help="The label of an alternative Organization (default is Org of caller)"
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
        help="Billable Network size to create",
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
        choices=["AWS", "AZURE", "GCP", "ALICLOUD", "NETFOUNDRY", "OCP"]
    )
    regions_group = parser.add_mutually_exclusive_group(required=False)
    regions_group.add_argument("--regions",
        default=["Americas"],
        nargs="+",
        help="space-separated one or more major geographic regions in which to place Edge Routers for overlay fabric",
        choices=["Americas", "EuropeMiddleEastAfrica", "AsiaPacific"]
    )
    regions_group.add_argument("--location-codes",
        dest="location_codes",
        nargs="+",
        help="cloud location codes in which to host Edge Routers"
    )
    parser.add_argument("--proxy",
        default=None,
        help="'http://localhost:8080'"+
        " 'socks5://localhost:9046'"
    )
    args = parser.parse_args()

    network_name = args.network
    
    # use the session with some Organization, default is to use the first and there's typically only one
    Organization = netfoundry.Organization(
        credentials=args.credentials if 'credentials' in args else None,
        organization_label=args.organization if 'organization' in args else None,
        proxy=args.proxy
    )

    # use some Network Group, default is to use the first and there's typically only one
    network_group = netfoundry.NetworkGroup(
        Organization,
        network_group_name=args.network_group if 'network_group' in args else None
    )

    # create a Network
    if network_name in network_group.networks_by_name.keys():
        # use the Network
        network = netfoundry.Network(network_group, network_name=network_name)
        if args.command == "create":
            network.wait_for_status("PROVISIONED",wait=999,progress=True)
        elif args.command == "delete":
            if query_yes_no("Permanently destroy Network \"{network_name}\" now?".format(network_name=network_name)):
                network.delete_network(progress=True)
            else:
                print("Not deleting Network \"{network_name}\".".format(network_name=network_name))
            sys.exit()
    elif args.command == "create":
        network_id = network_group.create_network(name=network_name,size=args.size,version=args.version)['id']
        network = netfoundry.Network(network_group, network_id=network_id)
        network.wait_for_status("PROVISIONED",wait=999,progress=True)

    # existing hosted ERs
    hosted_edge_routers = network.edge_routers(only_hosted=True)
    # a list of places where Endpoints are dialing from

    # a list of locations to place one hosted ER
    fabric_placements = list()
    if args.location_codes:
        for location in args.location_codes:
            data_centers = [dc for dc in network.get_edge_router_data_centers(provider=args.provider,location_code=location)]
            data_center = data_centers[0]
            existing_count = len([er for er in hosted_edge_routers if er['dataCenterId'] == data_center['id']])
            if existing_count < 1:
                fabric_placements += [data_center]
            else:
                print("INFO: found a hosted Edge Router(s) in {location}".format(location=location))

        for location in fabric_placements:
            er = network.create_edge_router(
                name=location['locationName']+" ["+location['provider']+"]",
                attributes=[
                    "#defaultRouters",
                    "#"+location['locationCode'],
                    "#"+location['provider']
                ],
                data_center_id=location['id']
            )
            hosted_edge_routers += [er]
            print("INFO: Placed Edge Router in {provider} ({location_name})".format(
                provider=location['provider'],
                location_name=location['locationName']
            ))
    elif args.regions:
        geo_regions = args.regions
        for region in geo_regions:
            data_center_ids = [dc['id'] for dc in network.aws_geo_regions[region]]
            existing_count = len([er for er in hosted_edge_routers if er['dataCenterId'] in data_center_ids])
            if existing_count < 1:
                choice = random.choice(network.aws_geo_regions[region])
                # append the current major region to the randomly-chosen data center object
                #   so we can use it as a role attribute when we create the hosted Edge Router
                choice['geoRegion'] = region
                fabric_placements += [choice]
            else:
                print("INFO: found a hosted Edge Router(s) in {major}".format(major=region))

        for location in fabric_placements:
            er = network.create_edge_router(
                name=location['locationName']+" ["+location['geoRegion']+"]",
                attributes=[
                    "#defaultRouters",
                    "#"+location['locationCode'],
                    "#"+location['geoRegion']
                ],
                data_center_id=location['id']
            )
            hosted_edge_routers += [er]
            print("INFO: Placed Edge Router in {major} ({location_name})".format(
                major=location['geoRegion'],
                location_name=location['locationName']
            ))

    for router_id in [r['id'] for r in hosted_edge_routers]:
        try:
            network.wait_for_status("PROVISIONED",id=router_id,type="edge-router",wait=999,progress=True)
        except:
            raise

    # create a simple global Edge Router Policy unless one exists with the same name
    ERPs = network.edge_router_policies()
    blanket_policy_name = "defaultRouters"
    if not blanket_policy_name in [erp['name'] for erp in ERPs]:
        try: network.create_edge_router_policy(name=blanket_policy_name,edge_router_attributes=["#defaultRouters"],endpoint_attributes=["#all"])
        except: raise

    endpoints = network.endpoints()
    clients = list()
    client1_name = "Desktop1"
    if not client1_name in [end['name'] for end in endpoints]:
        # create an Endpoint for the dialing device that will access Services
        client1 = network.create_endpoint(name=client1_name,attributes=["#workFromAnywhere"])
        print("INFO: created Endpoint \"{:s}\"".format(client1['name']))
    else:
        client1 = [end for end in endpoints if end['name'] == client1_name][0]
        print("INFO: found Endpoint \"{:s}\"".format(client1['name']))
    clients += [client1]

    client2_name = "Mobile1"
    if not client2_name in [end['name'] for end in endpoints]:
        # create an Endpoint for the dialing device that will access Services
        client2 = network.create_endpoint(name=client2_name,attributes=["#workFromAnywhere"])
        print("INFO: created Endpoint \"{:s}\"".format(client2['name']))
    else:
        client2 = [end for end in endpoints if end['name'] == client2_name][0]
        print("INFO: found Endpoint \"{:s}\"".format(client2['name']))
    clients += [client2]

    if args.client:
        client3_name = "Linux1"
        if not client3_name in [end['name'] for end in endpoints]:
            # create an Endpoint for the dialing device that will access Services
            client3 = network.create_endpoint(name=client3_name,attributes=["#workFromAnywhere"])
            print("INFO: created Endpoint \"{:s}\"".format(client3['name']))
        else:
            client3 = [end for end in endpoints if end['name'] == client3_name][0]
            print("INFO: found Endpoint \"{:s}\"".format(client3['name']))
        clients += [client3]

    exits = list()
    if args.private:
        exit1_name = "Exit1"
        if not exit1_name in [end['name'] for end in endpoints]:
            # create an Endpoint for the hosting device that will provide access to the server
            exit1 = network.create_endpoint(name=exit1_name,attributes=["#exits"])
            print("INFO: created Endpoint \"{:s}\"".format(exit1['name']))
        else:
            exit1 = [end for end in endpoints if end['name'] == exit1_name][0]
            print("INFO: found Endpoint \"{:s}\"".format(exit1['name']))
        exits += [exit1]

    # the demo containers have the demo working dir mounted on /netfoundry
    if os.access('/netfoundry', os.W_OK):
        token_path = '/netfoundry'
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

    services = network.services()

    if args.private:
        # create Endpoint-hosted Services unless name exists
        service1_name = "Hello Service"
        if not service1_name in [svc['name'] for svc in services]:
            # traffic sent to hello.netfoundry:80 leaves Endpoint exit1 to server hello:3000
            service1 = network.create_service(
                name=service1_name,
                attributes=["#welcomeWagon"],
                client_host_name="hello.netfoundry",
                client_port="80",
                endpoints=[exit1['id']],
                server_host_name="hello",
                server_port="3000",
                server_protocol="TCP"
            )
            print("INFO: created Service \"{:s}\"".format(service1['name']))
        else:
            service1 = [svc for svc in services if svc['name'] == service1_name][0]
            print("INFO: found Service \"{:s}\"".format(service1['name']))

        service2_name = "REST Service"
        if not service2_name in [svc['name'] for svc in services]:
            # traffic sent to httpbin.netfoundry:80 leaves Endpoint exit1 to server httpbin:80
            service2 = network.create_service(
                name=service2_name,
                attributes=["#welcomeWagon"],
                client_host_name="httpbin.netfoundry",
                client_port="80",
                endpoints=[exit1['id']],
                server_host_name="httpbin",
                server_port="80",
                server_protocol="TCP"
            )
            print("INFO: created Service \"{:s}\"".format(service2['name']))
        else:
            service2 = [svc for svc in services if svc['name'] == service2_name][0]
            print("INFO: found Service \"{:s}\"".format(service2['name']))

    # Create router-hosted Services unless exists
    hosting_router = random.choice(hosted_edge_routers)

    service3_name = "Fireworks Service"
    if not service3_name in [svc['name'] for svc in services]:
        # traffic sent to fireworks.netfoundry:80 leaves Routers to 34.204.78.203:80
        service3 = network.create_service(
            name=service3_name,
            attributes=["#welcomeWagon"],
            client_host_name="fireworks.netfoundry",
            client_port="80",
            egress_router_id=hosting_router['id'],
            server_host_name="fireworks-load-balancer-1246256380.us-east-1.elb.amazonaws.com",
            server_port="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(service3['name']))
    else:
        service3 = [svc for svc in services if svc['name'] == service3_name][0]
        print("INFO: found Service \"{:s}\"".format(service3['name']))

    service4_name = "Weather Service"
    if not service4_name in [svc['name'] for svc in services]:
        # traffic sent to weather.netfoundry:80 leaves Routers to wttr.in:80
        service4 = network.create_service(
            name=service4_name,
            attributes=["#welcomeWagon"],
            client_host_name="weather.netfoundry",
            client_port="80",
            egress_router_id=hosting_router['id'],
            server_host_name="wttr.in",
            server_port="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(service4['name']))
    else:
        service4 = [svc for svc in services if svc['name'] == service4_name][0]
        print("INFO: found Service \"{:s}\"".format(service4['name']))

    # fireworks
    # heartbeat
    
    service5_name = "Echo Service"
    if not service5_name in [svc['name'] for svc in services]:
        # traffic sent to echo.netfoundry:80 leaves Routers to eth0.me:80
        service5 = network.create_service(
            name=service5_name,
            attributes=["#welcomeWagon"],
            client_host_name="echo.netfoundry",
            client_port="80",
            egress_router_id=hosting_router['id'],
            server_host_name="eth0.me",
            server_port="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(service5['name']))
    else:
        service5 = [svc for svc in services if svc['name'] == service5_name][0]
        print("INFO: found Service \"{:s}\"".format(service5['name']))

    # create a customer-hosted ER unless exists
    customer_routers = network.edge_routers(only_customer=True)
    customer_router_name="Branch Exit Router 1"
    if not customer_router_name in [er['name'] for er in customer_routers]:
        customer_router = network.create_edge_router(
            name=customer_router_name,
            attributes=["#vmWareExitRouters"],
        )
    else:
        customer_router = [er for er in customer_routers if er['name'] == customer_router_name][0]
    # wait for customer router to be PROVISIONED so that registration will be available 
    try:
        network.wait_for_status("PROVISIONED",id=customer_router['id'],type="edge-router",wait=999,progress=True)
        customer_router_registration = network.get_edge_router_registration(id=customer_router['id'])
    except:
        raise
    print("INFO: Ready to register branch exit Edge Router {name} with key {key} (expires {expiry})".format(
        name=customer_router_name,
        key=customer_router_registration['registrationKey'],
        expiry=customer_router_registration['expiresAt'],
    ))


    # create unless exists
    app_wan1_name = "Welcome"
    app_wans = network.app_wans()
    if not app_wan1_name in [aw['name'] for aw in app_wans]:
        # workFromAnywhere may connect to welcomeWagon
        app_wan1 = network.create_app_wan(name=app_wan1_name,endpoint_attributes=["#workFromAnywhere"],service_attributes=["#welcomeWagon"])
        print("INFO: created AppWAN \"{:s}\"".format(app_wan1['name']))
    else:
        app_wan1 = [aw for aw in app_wans if aw['name'] == app_wan1_name][0]
        print("INFO: found AppWAN \"{:s}\"".format(app_wan1['name']))

    print("SUCCESS! The next step is to enroll one or more of your client Endpoints on some device(s) and visit one of the demo Service URLs described in the demo document ({doc})."
            "You may also log in to the web console ({nfconsole}) to play with your Network".format(doc="https://developer.netfoundry.io/v2/tools/#demos",nfconsole=network_group.nfconsole))
    for svc in network.services():
        print("* {name}:\thttp://{url}/".format(name=svc['name'],url=svc['model']['clientIngress']['host']))

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
        raise ValueError("invalid default answer: '%s'" % default)

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