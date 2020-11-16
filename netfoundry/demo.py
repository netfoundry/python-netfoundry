#!/usr/bin/env python3
r"""Example script to create a NetFoundry Network
Usage::
    $ python3 -m netfoundry.demo BibbidiBobbidiBoo
"""

import netfoundry
import sys
import random
import os

def main(netName = "BibbidiBobbidiBoo"):

    Session = netfoundry.Session()

    # yields a list of Network Groups in Organization.networkGroups[], but there's typically only one group
    Organization = netfoundry.Organization(Session)

    # use the default Network Group (the first Network Group ID known to the Organization)
    NetworkGroup = netfoundry.NetworkGroup(Organization)

    # create a Network
    if netName in NetworkGroup.networksByName.keys():
        # use the Network
        Network = netfoundry.Network(Session, networkName=netName)
        Network.waitForStatus("PROVISIONED",wait=999,progress=True)
    else:
        netId = NetworkGroup.createNetwork(netName)
        Network = netfoundry.Network(Session, networkId=netId)
        Network.waitForStatus("PROVISIONED",wait=999,progress=True)
        Network = netfoundry.Network(Session, networkId=netId)

    # delete the Network and wait for confirmation
    #Network.deleteNetwork()

    #print('{} is {}\n'.format(Network.name, Network.status))

    # existing ERs
    EDGE_ROUTERS = Network.edgeRouters()
    # a list of places where Endpoints are dialing from
    MAJOR_REGIONS = ("Americas", "EuropeMiddleEastAfrica")
    # a list of locations to place one hosted ER
    FABRIC_PLACEMENTS = list()
    DESIRED_COUNT = 1
    for region in MAJOR_REGIONS:
        dataCenterIds = [dc['id'] for dc in NetworkGroup.dataCentersByMajorRegion[region]]
        existing_count = len([er for er in EDGE_ROUTERS if er['dataCenterId'] in dataCenterIds])
        if existing_count < DESIRED_COUNT:
            choice = random.choice(NetworkGroup.dataCentersByMajorRegion[region])
            # append the current major region to the randomly-chosen dataCenter object
            #   so we can use it as a role attribute when we create the hosted Edge Router
            choice['majorRegion'] = region
            FABRIC_PLACEMENTS += [choice]
        else:
            print("INFO: found at least {count} Edge Router(s) in {major}".format(count=DESIRED_COUNT, major=region))

    for location in FABRIC_PLACEMENTS:
        er = Network.createEdgeRouter(
            name=location['name'],
            attributes=[
                "#defaultRouters",
                "#"+location['locationCode'],
                "#"+location['majorRegion']
            ],
            dataCenterId=location['id']
        )
        print("INFO: Placed Edge Router in {major} ({locationName})".format(
            major=location['majorRegion'],
            locationName=location['name']
        ))

    # create a simple global Edge Router Policy unless one exists with the same name
    ERPs = Network.edgeRouterPolicies()
    DEFAULT_ERP_NAME = "defaultRouters"
    if not DEFAULT_ERP_NAME in [erp['name'] for erp in ERPs]:
        DEFAULT_ERP = Network.createEdgeRouterPolicy(name=DEFAULT_ERP_NAME,edgeRouterAttributes=["#defaultRouters"],endpointAttributes=["#all"])

    ENDPOINTS = Network.endpoints()
    DIALER1_NAME = "dialer1"
    if not DIALER1_NAME in [end['name'] for end in ENDPOINTS]:
        # create an Endpoint for the dialing device that will access Services
        DIALER1 = Network.createEndpoint(name=DIALER1_NAME,attributes=["#dialers"])
        print("INFO: created Endpoint {:s}".format(DIALER1['name']))
    else:
        DIALER1 = [end for end in ENDPOINTS if end['name'] == DIALER1_NAME][0]
        print("INFO: found Endpoint {:s}".format(DIALER1['name']))

    EXIT1_NAME = "exit1"
    if not EXIT1_NAME in [end['name'] for end in ENDPOINTS]:
        # create an Endpoint for the hosting device that will provide access to the server
        EXIT1 = Network.createEndpoint(name=EXIT1_NAME,attributes=["#exits"])
        print("INFO: created Endpoint {:s}".format(EXIT1['name']))
    else:
        EXIT1 = [end for end in ENDPOINTS if end['name'] == EXIT1_NAME][0]
        print("INFO: found Endpoint {:s}".format(EXIT1['name']))

    for end in [DIALER1, EXIT1]:
        if end['jwt']:
            text = open(os.environ['HOME']+'/.netfoundry/'+end['name']+'.jwt', "wt")
            text.write(end['jwt'])
            text.close()

    # check Endpoint exit1 exists
    ENDPOINTS = Network.endpoints()
    EXIT1_NAME = "exit1"
    if not EXIT1_NAME in [end['name'] for end in ENDPOINTS]:
        raise Exception("ERROR: missing Endpoint {:s}".format(EXIT1_NAME))
    else:
        EXIT1 = [end for end in ENDPOINTS if end['name'] == EXIT1_NAME][0]
    #    print("INFO: found Endpoint {:s}".format(EXIT1['name']))

    # create Services unless name exists
    HELLO1_NAME = "hello Service"
    SERVICES = Network.services()
    if not HELLO1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to hello.netfoundry:80 leaves Endpoint exit1 to server hello:3000
        HELLO1 = Network.createService(
            name=HELLO1_NAME,
            attributes=["#welcomeWagon"],
            clientHostName="hello.netfoundry",
            clientPortRange="80",
            endpoints=[EXIT1['id']],
            serverHostName="hello",
            serverPortRange="3000",
            serverProtocol="TCP"
        )
        print("INFO: created Service {:s}".format(HELLO1['name']))
    else:
        HELLO1 = [svc for svc in SERVICES if svc['name'] == HELLO1_NAME][0]
        print("INFO: found Service {:s}".format(HELLO1['name']))

    SPEED1_NAME = "speedtest Service"
    if not SPEED1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to speedtest.netfoundry:80 leaves Endpoint exit1 to server speedtest:8080
        SPEED1 = Network.createService(
            name=SPEED1_NAME,
            attributes=["#welcomeWagon"],
            clientHostName="speedtest.netfoundry",
            clientPortRange="80",
            endpoints=[EXIT1['id']],
            serverHostName="speedtest",
            serverPortRange="8080",
            serverProtocol="TCP"
        )
        print("INFO: created Service {:s}".format(SPEED1['name']))
    else:
        SPEED1 = [svc for svc in SERVICES if svc['name'] == SPEED1_NAME][0]
        print("INFO: found Service {:s}".format(SPEED1['name']))

    HTTPBIN1_NAME = "httpbin Service"
    if not HTTPBIN1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to speedtest.netfoundry:80 leaves Endpoint exit1 to server speedtest:8080
        HTTPBIN1 = Network.createService(
            name=HTTPBIN1_NAME,
            attributes=["#welcomeWagon"],
            clientHostName="httpbin.netfoundry",
            clientPortRange="80",
            endpoints=[EXIT1['id']],
            serverHostName="httpbin",
            serverPortRange="80",
            serverProtocol="TCP"
        )
        print("INFO: created Service {:s}".format(HTTPBIN1['name']))
    else:
        HTTPBIN1 = [svc for svc in SERVICES if svc['name'] == HTTPBIN1_NAME][0]
        print("INFO: found Service {:s}".format(HTTPBIN1['name']))


    # create unless exists
    WELCOMEWAN1_NAME = "Welcome"
    APPWANS = Network.appWans()
    if not WELCOMEWAN1_NAME in [aw['name'] for aw in APPWANS]:
        # dialers may connect to welcomeWagon
        WELCOMEWAN1 = Network.createAppWan(name=WELCOMEWAN1_NAME,endpointAttributes=["#dialers"],serviceAttributes=["#welcomeWagon"])
        print("INFO: created AppWAN {:s}".format(WELCOMEWAN1['name']))
    else:
        WELCOMEWAN1 = [aw for aw in APPWANS if aw['name'] == WELCOMEWAN1_NAME][0]
        print("INFO: found AppWAN {:s}".format(WELCOMEWAN1['name']))


if __name__ == '__main__':
    if len(sys.argv) == 1:
        main()
    elif len(sys.argv) == 2:
        main(netName=sys.argv[1])
    else:
        raise Exception("ERROR: too many args, only network name expected")

