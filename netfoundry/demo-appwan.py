#!/usr/bin/env python3

import netfoundry
import os

Session = netfoundry.Session()

# yields a list of Network Groups in Organization.networkGroups[], but there's typically only one group
Organization = netfoundry.Organization(Session)

# use the default Network Group (the first Network Group ID known to the Organization)
NetworkGroup = netfoundry.NetworkGroup(Organization)

# create a Network
netName = "BibbidiBobbidiBoo"
if netName in NetworkGroup.networksByName.keys():
    # use the Network
    Network = netfoundry.Network(Session, networkName=netName)
else:
    raise Exception("ERROR: missing Network: {:s}".format(netName))

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
