import netfoundry
import os

Org = netfoundry.Organization(
    credentials=os.environ['HOME']+"/.netfoundry/credentials.json"#, proxy="http://localhost:4321"
)
# use the default Network Group (the first Network Group ID known to the Organization)
NetworkGroup = netfoundry.NetworkGroup(Org.token, Org.networkGroupId)

# create and use a Network
netName = "BibbidiBobbidiBoo1"
if netName in NetworkGroup.networksByName.keys():
    NetworkGroup.waitForStatus("PROVISIONED","network",NetworkGroup.networksByName[netName],wait=999,progress=True)
    Network = netfoundry.Network(Org.token, NetworkGroup.id, networkName=netName)
else:
    netId = NetworkGroup.createNetwork(netName,wait=999,progress=False)
    Network = netfoundry.Network(Org.token, NetworkGroup.id, netId)
print('{} is {}\n'.format(Network.name, Network.status))
