
## User Guide

[Python module guide](https://developer.netfoundry.io/guides/python/)

## Play the demo

This creates a demo network named "BibbidiBobbidiBoo" with your API account stored in ~/.netfoundry/credentials.json

Learn about getting an API account by reading the [Authentication Guide](https://developer.netfoundry.io/v2/guides/authentication/)

```bash
python3 -m netfoundry.demo --network=BibbidiBobbidiBoo
```

## Create network snippet from demo.py

```python
#!/usr/bin/env python3
import netfoundry

# user-default path is ~/.netfoundry/
organization = netfoundry.Organization(credentials="credentials.json")

# use some Network Group, default is to use the first and there's typically only one
network_group = netfoundry.NetworkGroup(organization)

# create a Network
network_name = "BibbidiBobbidiBoo"
if network_name in network_group.networks_by_name().keys():
    # use the Network
    network = netfoundry.Network(network_group, network_name=network_name)
    network.wait_for_status("PROVISIONED",wait=999,progress=True)
else:
    network_id = network_group.create_network(name=network_name)['id']
    network = netfoundry.Network(network_group, network_id=network_id)
    network.wait_for_status("PROVISIONED",wait=999,progress=True)
```
