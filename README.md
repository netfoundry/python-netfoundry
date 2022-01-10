
## User Guide

[Python module guide](https://developer.netfoundry.io/guides/python/)

## Find the Version

```bash
$ python3 -m netfoundry.version
v5.2.0
```

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

## Publish a new version of the module

[![Video Tour of Release Procedure](https://img.youtube.com/vi/RlIa2mv8YIM/0.jpg)](https://youtu.be/RlIa2mv8YIM)

```
00:00 Welcome Pythonistas
00:50 Determine next version number
01:30 GitFlow Release Start
02:10 Project Conventional Release Branch Name in Actions Workflow
02:30 Make a Change to Patch the Module
04:00 Git Commit the Change
04:30 GitFlow Publish Release to Git Remote
05:00 Create Pull Request
05:30 GitHub Actions Checks Triggered by Pull Request
06:00 Local testing with "editable" module and TestPyPi
09:00 Complete Pull Request
09:30 GitFlow Release Finish and Push Git Tags
10:30 GitHub Create Release
12:00 Verify Published Artifacts in PyPi and Hub
12:30 PyPi Upgrade Gets New Version
13:30 Docker Run Check Version
```