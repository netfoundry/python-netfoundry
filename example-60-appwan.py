import netfoundry
import os
import random

Session = netfoundry.Session(
    credentials=os.environ['HOME']+"/.netfoundry/credentials.json"#, proxy="http://localhost:4321"
)

# yields a list of Network Groups in Organization.networkGroups[], but there's typically only one group
Organization = netfoundry.Organization(Session)

# use the default Network Group (the first Network Group ID known to the Organization)
NetworkGroup = netfoundry.NetworkGroup(Organization)

# create a Network
netName = "BibbidiBobbidiBoo2312"
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

# create Service unless name exists
HELLO1_NAME = "helloService1"
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
