# NetFoundry Python Module

This module has a general-purpose library for using the NetFoundry API and installs the CLI `nfctl`.

## User Guide

[Python module guide](https://developer.netfoundry.io/guides/python/)

## Find the Version

```bash
 $ python3 -m netfoundry.version
v5.2.0
 # or
 $ nfctl version
v5.2.0
```

## Play the demo

This creates a demo network with your API account file named `credentials.json` stored in the current directory or the XDG config directory e.g. `~/.config/netfoundry/`. Learn how to obtain and use an API account for your NetFoundry organization in [the Authentication Guide](https://developer.netfoundry.io/guides/authentication/)

```bash
nfctl demo
```

## Create network snippet from demo.py

```python
#!/usr/bin/env python3
import netfoundry

# user-default path is ~/.netfoundry/
organization = netfoundry.Organization(credentials="credentials.json")

# use some network group, default is to use the first and there's typically only one
network_group = netfoundry.NetworkGroup(organization)

# create a network
network_name = "BibbidiBobbidiBoo"
if network_group.network_exists(network_name):
    # use the network
    network = netfoundry.Network(network_group, network_name=network_name)
    network.wait_for_status("PROVISIONED")
else:
    network_id = network_group.create_network(name=network_name)['id']
    network = netfoundry.Network(network_group, network_id=network_id)
    network.wait_for_status("PROVISIONED")
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
