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

def main(netName, privateServices=False):

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

    HOSTED_ROUTERS = [er for er in Network.edgeRouters() if er['dataCenterId']]
    for routerId in [r['id'] for r in HOSTED_ROUTERS]:
        try:
            Network.waitForStatus("PROVISIONED",id=routerId,type="edge-router",wait=333,progress=True)
        except:
            pass

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
        print("INFO: created Endpoint \"{:s}\"".format(DIALER1['name']))
    else:
        DIALER1 = [end for end in ENDPOINTS if end['name'] == DIALER1_NAME][0]
        print("INFO: found Endpoint \"{:s}\"".format(DIALER1['name']))

    DIALER2_NAME = "dialer2"
    if not DIALER2_NAME in [end['name'] for end in ENDPOINTS]:
        # create an Endpoint for the dialing device that will access Services
        DIALER2 = Network.createEndpoint(name=DIALER2_NAME,attributes=["#dialers"])
        print("INFO: created Endpoint \"{:s}\"".format(DIALER2['name']))
    else:
        DIALER2 = [end for end in ENDPOINTS if end['name'] == DIALER2_NAME][0]
        print("INFO: found Endpoint \"{:s}\"".format(DIALER2['name']))

    DIALER3_NAME = "dialer3"
    if not DIALER3_NAME in [end['name'] for end in ENDPOINTS]:
        # create an Endpoint for the dialing device that will access Services
        DIALER3 = Network.createEndpoint(name=DIALER3_NAME,attributes=["#dialers"])
        print("INFO: created Endpoint \"{:s}\"".format(DIALER3['name']))
    else:
        DIALER3 = [end for end in ENDPOINTS if end['name'] == DIALER3_NAME][0]
        print("INFO: found Endpoint \"{:s}\"".format(DIALER3['name']))

    EXIT1_NAME = "exit1"
    if not EXIT1_NAME in [end['name'] for end in ENDPOINTS]:
        # create an Endpoint for the hosting device that will provide access to the server
        EXIT1 = Network.createEndpoint(name=EXIT1_NAME,attributes=["#exits"])
        print("INFO: created Endpoint \"{:s}\"".format(EXIT1['name']))
    else:
        EXIT1 = [end for end in ENDPOINTS if end['name'] == EXIT1_NAME][0]
        print("INFO: found Endpoint \"{:s}\"".format(EXIT1['name']))

    if os.access('/netfoundry', os.W_OK):
        JWT_PATH = '/netfoundry'
    else:
        JWT_PATH = str(Path.cwd())
    for end in [DIALER1, DIALER2, DIALER3, EXIT1]:
        if end['jwt']:
            jwt_file = JWT_PATH+'/'+end['name']+'.jwt'
            print("DEBUG: saving OTT for {end} in {path}".format(end=end['name'],path=jwt_file))
            text = open(jwt_file, "wt")
            text.write(end['jwt'])
            text.close()

    # check Endpoint exit1 exists
    ENDPOINTS = Network.endpoints()
    EXIT1_NAME = "exit1"
    if not EXIT1_NAME in [end['name'] for end in ENDPOINTS]:
        raise Exception("ERROR: missing Endpoint \"{:s}\"".format(EXIT1_NAME))
    else:
        EXIT1 = [end for end in ENDPOINTS if end['name'] == EXIT1_NAME][0]
    #    print("INFO: found Endpoint \"{:s}\"".format(EXIT1['name']))

    SERVICES = Network.services()

    if privateServices:
        # create Endpoint-hosted Services unless name exists
        HELLO1_NAME = "hello Service"
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
            print("INFO: created Service \"{:s}\"".format(HELLO1['name']))
        else:
            HELLO1 = [svc for svc in SERVICES if svc['name'] == HELLO1_NAME][0]
            print("INFO: found Service \"{:s}\"".format(HELLO1['name']))

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
            print("INFO: created Service \"{:s}\"".format(SPEED1['name']))
        else:
            SPEED1 = [svc for svc in SERVICES if svc['name'] == SPEED1_NAME][0]
            print("INFO: found Service \"{:s}\"".format(SPEED1['name']))

        HTTPBIN1_NAME = "httpbin Service"
        if not HTTPBIN1_NAME in [svc['name'] for svc in SERVICES]:
            # traffic sent to httpbin.netfoundry:80 leaves Endpoint exit1 to server httpbin:80
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
            print("INFO: created Service \"{:s}\"".format(HTTPBIN1['name']))
        else:
            HTTPBIN1 = [svc for svc in SERVICES if svc['name'] == HTTPBIN1_NAME][0]
            print("INFO: found Service \"{:s}\"".format(HTTPBIN1['name']))

    # Create router-hosted Services unless exists
    EGRESS_ROUTER = random.choice(HOSTED_ROUTERS)

    WEATHER1_NAME = "Weather Service"
    if not WEATHER1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to weather.netfoundry:80 leaves Routers to wttr.in:80
        WEATHER1 = Network.createService(
            name=WEATHER1_NAME,
            attributes=["#welcomeWagon"],
            clientHostName="weather.netfoundry",
            clientPortRange="80",
            egressRouterId=EGRESS_ROUTER['id'],
            serverHostName="wttr.in",
            serverPortRange="80",
            serverProtocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(WEATHER1['name']))
    else:
        WEATHER1 = [svc for svc in SERVICES if svc['name'] == WEATHER1_NAME][0]
        print("INFO: found Service \"{:s}\"".format(WEATHER1['name']))

    ECHO1_NAME = "Echo Service"
    if not ECHO1_NAME in [svc['name'] for svc in SERVICES]:
        # traffic sent to echo.netfoundry:80 leaves Routers to eth0.me:80
        ECHO1 = Network.createService(
            name=ECHO1_NAME,
            attributes=["#welcomeWagon"],
            clientHostName="echo.netfoundry",
            clientPortRange="80",
            egressRouterId=EGRESS_ROUTER['id'],
            serverHostName="eth0.me",
            serverPortRange="80",
            serverProtocol="TCP"
        )
        print("INFO: created Service \"{:s}\"".format(ECHO1['name']))
    else:
        ECHO1 = [svc for svc in SERVICES if svc['name'] == ECHO1_NAME][0]
        print("INFO: found Service \"{:s}\"".format(ECHO1['name']))

    # create unless exists
    WELCOMEWAN1_NAME = "Welcome"
    APPWANS = Network.appWans()
    if not WELCOMEWAN1_NAME in [aw['name'] for aw in APPWANS]:
        # dialers may connect to welcomeWagon
        WELCOMEWAN1 = Network.createAppWan(name=WELCOMEWAN1_NAME,endpointAttributes=["#dialers"],serviceAttributes=["#welcomeWagon"])
        print("INFO: created AppWAN \"{:s}\"".format(WELCOMEWAN1['name']))
    else:
        WELCOMEWAN1 = [aw for aw in APPWANS if aw['name'] == WELCOMEWAN1_NAME][0]
        print("INFO: found AppWAN \"{:s}\"".format(WELCOMEWAN1['name']))

    print("SUCCESS! The next step is to enroll one or more of your dialer Endpoints on some device(s) and visit one of the demo Service URLs described in the demo document ({doc})."
            "You may also log in to the web console ({nfconsole}) to play with your Network".format(doc="https://developer.netfoundry.io/v2/tools/#demos",nfconsole=NetworkGroup.nfconsole))
    for svc in Network.services():
        print("* {name}:\thttp://{url}/".format(name=svc['name'],url=svc['clientHostName']))


if __name__ == '__main__':
    print("INFO: running demo script in \"{:s}\"".format(sys.argv[0]))
    if len(sys.argv) == 1:
        raise Exception("ERROR: Network name expected as first parameter")
    elif len(sys.argv) == 2:
        main(netName=sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[2] == "privateServices":
        main(netName=sys.argv[1], privateServices=True)
    else:
        raise Exception("ERROR: too many args, only network name expected")

