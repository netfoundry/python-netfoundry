


```python
#!/usr/bin/env python3
import netfoundry

# default API account credential file is ~/.netfoundry/credentials.json
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
    Network.waitForStatus("PROVISIONED",wait=999,progress=True)
else:
    netId = NetworkGroup.createNetwork(netName)
    Network = netfoundry.Network(Session, networkId=netId)
    Network.waitForStatus("PROVISIONED",wait=999,progress=True)
    Network = netfoundry.Network(Session, networkId=netId)
```