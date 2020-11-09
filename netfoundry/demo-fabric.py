#!/usr/bin/env python3

import netfoundry
import os
import random
import sys

def main():

    # yields a list of Network Groups in Organization.networkGroups[], but there's typically only one group
    Organization = netfoundry.Organization(Session)

    # use the default Network Group (the first Network Group ID known to the Organization)
    NetworkGroup = netfoundry.NetworkGroup(Organization)

    # create a Network
    netName = "BibbidiBobbidiBoo"
    if netName in NetworkGroup.networksByName.keys():
        # use the Network
        Network = netfoundry.Network(Session, networkName=netName)
    else:
        raise Exception("ERROR: missing Network: {:s}".format(netName))

    # existing ERs
    EDGE_ROUTERS = Network.edgeRouters()
    # a list of places where Endpoints are dialing from
    MAJOR_REGIONS = ("Americas", "EuropeMiddleEastAfrica")
    # a list of locations to place one hosted ER
    FABRIC_PLACEMENTS = list()
    DESIRED_COUNT = 1
    for region in MAJOR_REGIONS:
        dataCenterIds = [dc['id'] for dc in NetworkGroup.dataCentersByMajorRegion[region]]
        existing_count = len([er for er in EDGE_ROUTERS if er['dataCenterId'] in dataCenterIds])
        if existing_count < DESIRED_COUNT:
            choice = random.choice(NetworkGroup.dataCentersByMajorRegion[region])
            # append the current major region to the randomly-chosen dataCenter object
            #   so we can use it as a role attribute when we create the hosted Edge Router
            choice['majorRegion'] = region
            FABRIC_PLACEMENTS += [choice]
        else:
            print("INFO: found at least {count} Edge Router(s) in {major}".format(count=DESIRED_COUNT, major=region))

    for location in FABRIC_PLACEMENTS:
        er = Network.createEdgeRouter(
            name=location['name'],
            attributes=[
                "#defaultRouters",
                "#"+location['locationCode'],
                "#"+location['majorRegion']
            ],
            dataCenterId=location['id']
        )
        print("INFO: Placed Edge Router in {major} ({locationName})".format(
            major=location['majorRegion'],
            locationName=location['name']
        ))

    # create a simple global Edge Router Policy unless one exists with the same name
    ERPs = Network.edgeRouterPolicies()
    DEFAULT_ERP_NAME = "defaultRouters"
    if not DEFAULT_ERP_NAME in [erp['name'] for erp in ERPs]:
        DEFAULT_ERP = Network.createEdgeRouterPolicy(name=DEFAULT_ERP_NAME,edgeRouterAttributes=["#defaultRouters"],endpointAttributes=["#all"])

if __name__ == '__main__':
    main()
