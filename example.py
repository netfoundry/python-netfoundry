import netfoundry
import os

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
    Network.waitForStatus("PROVISIONED",wait=999,progress=False)
    Network.deleteNetwork(wait=120)
    Network = netfoundry.Network(Session, networkName=netName)
else:
    netId = NetworkGroup.createNetwork(netName,wait=999,progress=True)
    Network = netfoundry.Network(Session, networkId=netId)
print('{} is {}\n'.format(Network.name, Network.status))

# a list of places where Endpoints or Services or both are located