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
        text = open('/root/.netfoundry/'+end['name']+'.jwt', "wt")
        text.write(end['jwt'])
        text.close()
