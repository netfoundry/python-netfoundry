import netfoundry
import os
nfapi = netfoundry.client(
    credentials="/home/kbingham/.netfoundry/credentials.json", 
    environment="staging"#, proxy="http://localhost:4321"
)
netGroup = nfapi.networkGroups[0]['organizationShortName']
netName = "BibbidiBobbidiBoo"
if netName in nfapi.networksByName.keys():
    print(nfapi.getNetworkByName(netName)['status'])
else:
    netId = nfapi.createNetwork(netGroup, netName)
    print(nfapi.getNetwork(netId)['status'])
