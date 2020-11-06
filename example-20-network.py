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
netName = "BibbidiBobbidiBoo2312"
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