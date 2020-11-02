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
netName = "BibbidiBobbidiBoo1"
if netName in NetworkGroup.networksByName.keys():
    # use the Network
    Network = netfoundry.Network(Session, networkName=netName)
else:
    raise Exception("ERROR: missing Network: {:s}".format(netName))
#print('{} is {}\n'.format(Network.name, Network.status))

# a list of places where Endpoints or Services or both are located
PLACES = ("Americas", "EuropeMiddleEastAfrica")
DATACENTERS = list()
print('Datacenters:')
for place in PLACES:
    dc = random.choice(NetworkGroup.dataCentersByMajorRegion[place])
    DATACENTERS += dc
    print('\t{:s}: {:s}'.format(place, dc['locationCode']))