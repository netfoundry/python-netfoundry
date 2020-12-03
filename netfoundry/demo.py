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

    PARSER = argparse.ArgumentParser()
    PARSER.add_argument(
        "-n", "--network",
        help="The name of your demo network"
    )
    PARSER.add_argument(
        "-p", "--create-private",
        dest="private",
        default=False,
        action="store_true",
        help="Also create private Services for the Docker Compose Demo"
    )
    PARSER.add_argument(
        "-d", "--create-dialer",
        dest="dialer",
        default=False,
        action="store_true",
        help="Also create a Linux dialer for the Docker Compose Demo"
    )
    PARSER.add_argument("--credentials",
        default=None,
        help="path to API account credentials JSON file overrides NETFOUNDRY_API_ACCOUNT"
    )
    PARSER.add_argument("--regions",
        default=["Americas"],
        nargs="+",
        required=False,
        help="space-separated one or more major geographic regions in which to place Edge Routers for overlay fabric: "
                +' '.join(["Americas", "EuropeMiddleEastAfrica", "AsiaPacific"])
    )
    PARSER.add_argument("--proxy",
        default=None,
        help="'http://localhost:8080'"+
        " (implies certificate verification is disabled); or"+
        " 'socks5://localhost:9046'"
    )
    ARGS = PARSER.parse_args()

    network_name = ARGS.network
    
    Session = netfoundry.Session(
        credentials=ARGS.credentials if ARGS.credentials is not None else None,
        proxy=ARGS.proxy,
    )

    # yields a list of Network Groups in Organization.network_groups[], but there's typically only one group
    Organization = netfoundry.Organization(Session)

    # use the default Network Group (the first Network Group ID known to the Organization)
    NetworkGroup = netfoundry.NetworkGroup(Organization)

    # create a Network
    if network_name in NetworkGroup.networks_by_name.keys():
        # use the Network
        Network = netfoundry.Network(Session, network_name=network_name)
        Network.wait_for_status("PROVISIONED",wait=999,progress=True)
    else:
        network_id = NetworkGroup.create_network(network_name)
        Network = netfoundry.Network(Session, network_id=network_id)
        Network.wait_for_status("PROVISIONED",wait=999,progress=True)
        Network = netfoundry.Network(Session, network_id=network_id)

    # delete the Network and wait for confirmation
    #Network.delete_network()

    #print('{} is {}\n'.format(Network.name, Network.status))

    # existing ERs
    EDGE_ROUTERS = Network.edge_routers()
    # a list of places where Endpoints are dialing from
    MAJOR_REGIONS = ARGS.regions
    # a list of locations to place one hosted ER
    FABRIC_PLACEMENTS = list()
    DESIRED_COUNT = 1
    for region in MAJOR_REGIONS:
        datacenter_ids = [dc['id'] for dc in Network.aws_geo_regions[region]]
        existing_count = len([er for er in EDGE_ROUTERS if er['dataCenterId'] in datacenter_ids])
        if existing_count < DESIRED_COUNT:
            choice = random.choice(Network.aws_geo_regions[region])
            # append the current major region to the randomly-chosen datacenter object
            #   so we can use it as a role attribute when we create the hosted Edge Router
            choice['majorRegion'] = region
            FABRIC_PLACEMENTS += [choice]
        else:
            print("INFO: found at least {count} Edge Router(s) in {major}".format(count=DESIRED_COUNT, major=region))

    for location in FABRIC_PLACEMENTS:
        er = Network.create_edge_router(
            name=location['locationName'],
            attributes=[
                "#defaultRouters",
                "#"+location['locationCode'],
                "#"+location['majorRegion']
            ],
            datacenter_id=location['id']
        )
        print("INFO: Placed Edge Router in {major} ({location_name})".format(
            major=location['majorRegion'],
            location_name=location['locationName']
        ))

    HOSTED_ROUTERS = [er for er in Network.edge_routers() if er['dataCenterId']]
    for router_id in [r['id'] for r in HOSTED_ROUTERS]:
        try:
            Network.wait_for_status("PROVISIONED",id=router_id,type="edge-router",wait=999,progress=True)
        except:
            raise

    # create a simple global Edge Router Policy unless one exists with the same name
    ERPs = Network.edge_router_policies()
    DEFAULT_ERP_NAME = "defaultRouters"
    if not DEFAULT_ERP_NAME in [erp['name'] for erp in ERPs]:
        DEFAULT_ERP = Network.create_edge_router_policy(name=DEFAULT_ERP_NAME,edge_router_attributes=["#defaultRouters"],endpoint_attributes=["#all"])

    ENDPOINTS = Network.endpoints()
    DIALERS = list()
    DIALER1_NAME = "Desktop1"
    if not DIALER1_NAME in [end['name'] for end in ENDPOINTS]:
        # create an Endpoint for the dialing device that will access Services
        DIALER1 = Network.create_endpoint(name=DIALER1_NAME,attributes=["#dialers"])
        print("INFO: created Endpoint \"{:s}\"".format(DIALER1['name']))
    else:
        DIALER1 = [end for end in ENDPOINTS if end['name'] == DIALER1_NAME][0]
        print("INFO: found Endpoint \"{:s}\"".format(DIALER1['name']))
    DIALERS += [DIALER1]

    DIALER2_NAME = "Mobile1"
    if not DIALER2_NAME in [end['name'] for end in ENDPOINTS]:
        # create an Endpoint for the dialing device that will access Services
        DIALER2 = Network.create_endpoint(name=DIALER2_NAME,attributes=["#dialers"])
        print("INFO: created Endpoint \"{:s}\"".format(DIALER2['name']))
    else:
        DIALER2 = [end for end in ENDPOINTS if end['name'] == DIALER2_NAME][0]
        print("INFO: found Endpoint \"{:s}\"".format(DIALER2['name']))
    DIALERS += [DIALER2]

    if ARGS.dialer:
        DIALER3_NAME = "Linux1"
        if not DIALER3_NAME in [end['name'] for end in ENDPOINTS]:
            # create an Endpoint for the dialing device that will access Services
            DIALER3 = Network.create_endpoint(name=DIALER3_NAME,attributes=["#dialers"])
            print("INFO: created Endpoint \"{:s}\"".format(DIALER3['name']))
        else:
            DIALER3 = [end for end in ENDPOINTS if end['name'] == DIALER3_NAME][0]
            print("INFO: found Endpoint \"{:s}\"".format(DIALER3['name']))
        DIALERS += [DIALER3]

    EXITS = list()
    if ARGS.private:
        EXIT1_NAME = "Exit1"
        if not EXIT1_NAME in [end['name'] for end in ENDPOINTS]:
            # create an Endpoint for the hosting device that will provide access to the server
            EXIT1 = Network.create_endpoint(name=EXIT1_NAME,attributes=["#exits"])
            print("INFO: created Endpoint \"{:s}\"".format(EXIT1['name']))
        else:
            EXIT1 = [end for end in ENDPOINTS if end['name'] == EXIT1_NAME][0]
            print("INFO: found Endpoint \"{:s}\"".format(EXIT1['name']))
        EXITS += [EXIT1]

    # the demo containers have the demo working dir mounted on /netfoundry
    if os.access('/netfoundry', os.W_OK):
        JWT_PATH = '/netfoundry'
    else:
        JWT_PATH = str(Path.cwd())
    for end in DIALERS+EXITS:
        jwt_file = JWT_PATH+'/'+end['name']+'.jwt'
        try:
            end['jwt']
        except KeyError:
            if os.path.exists(jwt_file):
                print("DEBUG: cleaning up used OTT for enrolled Endpoint {end} from {path}".format(end=end['name'],path=jwt_file))
                os.remove(jwt_file)
        else:
            text = open(jwt_file, "wt")
            text.write(end['jwt'])
            text.close()

    SERVICES = Network.services()

    if ARGS.private:
        # create Endpoint-hosted Services unless name exists
        HELLO1_NAME = "hello Service"
        if not HELLO1_NAME in [svc['name'] for svc in SERVICES]:
            # traffic sent to hello.netfoundry:80 leaves Endpoint exit1 to server hello:3000
            HELLO1 = Network.create_service(
                name=HELLO1_NAME,
                attributes=["#welcomeWagon"],
                client_host_name="hello.netfoundry",
                client_port_range="80",
                endpoints=[EXIT1['id']],
                server_hostname="hello",
                server_port_range="3000",
                server_protocol="TCP"
            )
            print("INFO: created Service \"{:s}\"".format(HELLO1['name']))
        else:
            HELLO1 = [svc for svc in SERVICES if svc['name'] == HELLO1_NAME][0]
            print("INFO: found Service \"{:s}\"".format(HELLO1['name']))

        HTTPBIN1_NAME = "httpbin Service"
        if not HTTPBIN1_NAME in [svc['name'] for svc in SERVICES]:
            # traffic sent to httpbin.netfoundry:80 leaves Endpoint exit1 to server httpbin:80
            HTTPBIN1 = Network.create_service(
                name=HTTPBIN1_NAME,
                attributes=["#welcomeWagon"],
                client_hostname="httpbin.netfoundry",
                client_port_range="80",
                endpoints=[EXIT1['id']],
                server_hostname="httpbin",
                server_port_range="80",
                server_protocol="TCP"
            )
            print("INFO: created Service \"{:s}\"".format(HTTPBIN1['name']))
        else:
            HTTPBIN1 = [svc for svc in SERVICES if svc['name'] == HTTPBIN1_NAME][0]
            print("INFO: found Service \"{:s}\"".format(HTTPBIN1['name']))

    # Create router-hosted Services unless exists
    EGRESS_ROUTER = random.choice(HOSTED_ROUTERS)

    FIREWORKS1_NAME = "Fireworks Service"
    if not FIREWORKS1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to fireworks.netfoundry:80 leaves Routers to 34.204.78.203:80
        FIREWORKS1 = Network.create_service(
            name=FIREWORKS1_NAME,
            attributes=["#welcomeWagon"],
            client_hostname="fireworks.netfoundry",
            client_port_range="80",
            egress_router_id=EGRESS_ROUTER['id'],
            server_hostname="34.204.78.203",
            server_port_range="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(FIREWORKS1['name']))
    else:
        FIREWORKS1 = [svc for svc in SERVICES if svc['name'] == FIREWORKS1_NAME][0]
        print("INFO: found Service \"{:s}\"".format(FIREWORKS1['name']))

    WEATHER1_NAME = "Weather Service"
    if not WEATHER1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to weather.netfoundry:80 leaves Routers to wttr.in:80
        WEATHER1 = Network.create_service(
            name=WEATHER1_NAME,
            attributes=["#welcomeWagon"],
            client_hostname="weather.netfoundry",
            client_port_range="80",
            egress_router_id=EGRESS_ROUTER['id'],
            server_hostname="wttr.in",
            server_port_range="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(WEATHER1['name']))
    else:
        WEATHER1 = [svc for svc in SERVICES if svc['name'] == WEATHER1_NAME][0]
        print("INFO: found Service \"{:s}\"".format(WEATHER1['name']))

    # fireworks
    # heartbeat
    
    ECHO1_NAME = "Echo Service"
    if not ECHO1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to echo.netfoundry:80 leaves Routers to eth0.me:80
        ECHO1 = Network.create_service(
            name=ECHO1_NAME,
            attributes=["#welcomeWagon"],
            client_hostname="echo.netfoundry",
            client_port_range="80",
            egress_router_id=EGRESS_ROUTER['id'],
            server_hostname="eth0.me",
            server_port_range="80",
            server_protocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(ECHO1['name']))
    else:
        ECHO1 = [svc for svc in SERVICES if svc['name'] == ECHO1_NAME][0]
        print("INFO: found Service \"{:s}\"".format(ECHO1['name']))

    # create unless exists
    WELCOMEWAN1_NAME = "Welcome"
    APPWANS = Network.appwans()
    if not WELCOMEWAN1_NAME in [aw['name'] for aw in APPWANS]:
        # dialers may connect to welcomeWagon
        WELCOMEWAN1 = Network.create_appwan(name=WELCOMEWAN1_NAME,endpoint_attributes=["#dialers"],service_attributes=["#welcomeWagon"])
        print("INFO: created AppWAN \"{:s}\"".format(WELCOMEWAN1['name']))
    else:
        WELCOMEWAN1 = [aw for aw in APPWANS if aw['name'] == WELCOMEWAN1_NAME][0]
        print("INFO: found AppWAN \"{:s}\"".format(WELCOMEWAN1['name']))

    print("SUCCESS! The next step is to enroll one or more of your dialer Endpoints on some device(s) and visit one of the demo Service URLs described in the demo document ({doc})."
            "You may also log in to the web console ({nfconsole}) to play with your Network".format(doc="https://developer.netfoundry.io/v2/tools/#demos",nfconsole=NetworkGroup.nfconsole))
    for svc in Network.services():
        print("* {name}:\thttp://{url}/".format(name=svc['name'],url=svc['clientHostName']))


if __name__ == '__main__':
    main()