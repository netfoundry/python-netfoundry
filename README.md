
## Play the demo

This creates a demo network named "BibbidiBobbidiBoo" with your API account stored in ~/.netfoundry/credentials.json

Learn about getting an API account by reading the [Authentication Guide](https://developer.netfoundry.io/v2/guides/authentication/)

```bash
$ python3 -m netfoundry.demo BibbidiBobbidiBoo
INFO: running demo script in /home/alice/.pyenv/versions/3.9.0/lib/python3.9/site-packages/netfoundry/demo.py
```

## Create network snippet from demo.py

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