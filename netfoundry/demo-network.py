#!/usr/bin/env python3

import netfoundry
import os
import sys

def main():

    if len(sys.argv) == 0:
        netName = "BibbidiBobbidiBoo"
    elif len(sys.argv) == 1:
        netName = sys.argv[0]
    else:
        raise Exception("ERROR: too many arguments, need quotes? Network name expected")

    Session = netfoundry.Session()

    # yields a list of Network Groups in Organization.networkGroups[], but there's typically only one group
    Organization = netfoundry.Organization(Session)

    # use the default Network Group (the first Network Group ID known to the Organization)
    NetworkGroup = netfoundry.NetworkGroup(Organization)

    # create a Network
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

if __name__ == '__main__':
    main()

