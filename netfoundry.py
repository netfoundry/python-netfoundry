"""classes for interacting with the NetFoundry Management Operations Platform (MOP)
"""
from __future__ import print_function # use print from python3 for stdout, stderr
import sys # open stderr
import json # operate on structured data
import requests # HTTP user agent
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import time # enforce a timeout; sleep
import uuid # generate a UUID as a businessKey if it is not provided
from uuid import UUID # validate UUIDv4 strings
import jwt # decode the JWT claimset to extract the organization UUID

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class nfapi(object):
    """interact with API gateways
    """

    def __init__(self):
        self.authEndpoints = {
            'localhost': 'https://netfoundry-sandbox.auth0.com/oauth/token',
            'sandbox': 'https://netfoundry-sandbox.auth0.com/oauth/token',
            'integration': 'https://netfoundry-integration.auth0.com/oauth/token',
            'staging': 'https://netfoundry-staging.auth0.com/oauth/token',
            'trial': 'https://netfoundry-trial.auth0.com/oauth/token',
            'private': 'https://netfoundry-private.auth0.com/oauth/token',
            'production': 'https://netfoundry-production.auth0.com/oauth/token'
        }

        self.statusesByCode = {
            100: ('new', 'created'),
            200: ('building', 'incomplete', 'allocated'),
            300: ('active', 'complete', 'provisioned'),
            400: ('registered', 'enrolled'),
            500: ('error', 'server_error'),
            600: ('updating', 'modifying'),
            800: ('deleting', 'released', 'decommissioned'),
            900: ('defunct', 'deleted')
        }

        self.codes = LookupDict(name='statuses')

        for code, titles in self.statusesByCode.items():
            for title in titles:
                setattr(self.codes, title.upper(), code)

    def client(self, auth, proxy=None):
        """initialize with a reusable MOP API gateway connector object
        where
        :param auth: required authorization bearer token
        :param proxy: optional HTTP proxy, e.g., http://localhost:8080
        The init function also gathers a few essential objects from the API and
        stores them for reuse in the instance namespace
        """

        self.orgId = jwt.decode(auth,
                                verify=False)['https://netfoundry.io/organization_id']
        # expected value is UUID
        UUID(self.orgId, version=4)

        self.aud = jwt.decode(auth,
                              verify=False)['aud']
        self.auth = auth

        # forward request to proxy if defined
        if proxy == None:
            self.proxies = dict()
            self.verify = True
        else:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
            # verify server certificate if proxy is type SOCKS
            if proxy[0:5] == 'socks':
                self.verify = True
            else:
                self.verify = False

        self.datacenters = self.getDataCenters()
        self.datacentersByRegion = dict()
        for dc in self.datacenters:
            self.datacentersByRegion[dc['locationCode']] = dc['_links']['self']['href'].split('/')[-1]
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

        self.georegions = self.getGeoRegions()
        self.geoRegionsByName = dict()
        for gr in self.georegions:
            self.geoRegionsByName[gr['name']] = gr['_links']['self']['href'].split('/')[-1]
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

        # an attribute that is a dict for resolving network UUIDs by name
        self.networksByName = dict()
        for net in self.getNetworks():
            self.networksByName[net['name']] = net['_links']['self']['href'].split('/')[-1]
            # e.g. { testNetwork: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

    def walkNetwork(self, netId):
        """return an object to serve as a lookup dict for the various resources associated with a NF network where
        :param netId: required UUID of NF network to walk
        """

        network = dict()

        # a list of all endpoint objects from which to extract the name and UUID
        endpoints = self.getEndpoints(netId)
        # a dict for resolving endpoint UUIDs by name
        network['endpointsByName'] = dict()
        for end in endpoints:
            network['endpointsByName'][end['name']] = end['_links']['self']['href'].split('/')[-1]
            # e.g. { testGateway: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

        # a list of all endpoint groups from which to extract the name and UUID
        endpointGroups = self.getEndpointGroups(netId)
        # a dict for resolving endpoint group UUIDs by name
        network['endpointGroupsByName'] = dict()
        for group in endpointGroups:
            network['endpointGroupsByName'][group['name']] = group['_links']['self']['href'].split('/')[-1]

        # a list of all services from which to extract the name and UUID
        services = self.getServices(netId)
        # a dict for resolving service UUIDs by name
        network['servicesByName'] = dict()
        for svc in services:
            network['servicesByName'][svc['name']] = svc['_links']['self']['href'].split('/')[-1]

        # a list of all AppWAN objects from which to extract the name and UUID
        appWans = self.getAppWans(netId)
        # a dict for resolving AppWAN UUIDs by name
        network['appWansByName'] = dict()
        for appWan in appWans:
            network['appWansByName'][appWan['name']] = appWan['_links']['self']['href'].split('/')[-1]

        return(network)

    def getDataCenters(self):
        """return the dataCenters object
        """
        try:
            # dataCenters returns a list of dicts (datacenter objects)
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(self.aud+'rest/v1/dataCenters',
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                datacenters = json.loads(response.text)['_embedded']['dataCenters']
            except ValueError as e:
                eprint('ERROR getting datacenters')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(datacenters)

    def getGeoRegions(self):
        """return the geoRegions object
        """
        try:
            # dataCenters returns a list of dicts (datacenter objects)
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(self.aud+'rest/v1/geoRegions',
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                geoRegions = json.loads(response.text)['_embedded']['geoRegions']
            except ValueError as e:
                eprint('ERROR getting geo regions')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(geoRegions)

    def organizationShortName(self):
        """resolve an org ID to a short name
        """
        try:
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(self.aud+'rest/v1/organizations/'+self.orgId,
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                shortName = json.loads(response.text)['organizationShortName']
            except ValueError as e:
                eprint('ERROR resolving organization UUID to short name')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(shortName)

    def getNetworks(self):
        """
        return the networks for a particular organization
        """

        try:
            # returns a list of dicts (network objects)
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(
                self.aud+'rest/v1/organizations/'+self.orgId+'/networks',
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networks = json.loads(response.text)['_embedded']['networks']
            except KeyError:
                networks = []
                pass
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(networks)

    def getEndpoints(self, netId):
        """
        return the endpoints as an object
        """
        try:
            # returns a list of dicts (network objects)
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(self.aud+'rest/v1/networks/'+netId+'/endpoints',
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                endpoints = json.loads(response.text)['_embedded']['endpoints']
            except KeyError:
                endpoints = []
                pass
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(endpoints)

    def getEndpointGroups(self, netId):
        """return the endpointGroups as an object
        """
        try:
            # returns a list of dicts (network objects)
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(self.aud+'rest/v1/networks/'+netId+'/endpointGroups',
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                endpointGroups = json.loads(response.text)['_embedded']['endpointGroups']
            except KeyError:
                endpointGroups = []
                pass
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(endpointGroups)

    def getServices(self, netId):
        """return the services object
        """
        try:
            # returns a list of dicts (network objects)
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(self.aud+'rest/v1/networks/'+netId+'/services',
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                services = json.loads(response.text)['_embedded']['services']
            except KeyError:
                services = []
                pass
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(services)

    def getAppWans(self, netId):
        """return the appWans object
        """
        try:
            # returns a list of dicts (network objects)
            headers = { "authorization": "Bearer " + self.auth }
            response = requests.get(self.aud+'rest/v1/networks/'+netId+'/appWans',
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers
                                   )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                appWans = json.loads(response.text)['_embedded']['appWans']
            except KeyError:
                appWans = []
                pass
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(appWans)

    def post(self,
             method,
             json,
             expected_response="ACCEPTED"
            ):
        """
        post arbitrary data as JSON to an API method
        """

        request = json

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1"+method,
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes[expected_response]:
            raise Exception('unexpected response: {} (HTTP {:d})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code
            )
                           )

        text = response.text

        return(text)

    def createNetwork(self, name, region, version=None, wait=0, family="dvn"):
        """
        create an NFN with
        :param name: network name
        :param region: required datacenter region name in which to create
        :param version: optional product version string like 3.6.6.11043_2018-03-21_1434
        :param wait: optional wait seconds for network to build before returning
        :param family: optional product family if not "dvn"
        """
        request = {
            "organizationId" : self.orgId,
            "name": name,
            "locationCode": region,
            "productFamily": family
        }
        if version:
            request['productVersion'] = version

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        netId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]
        # expected value is UUID
        UUID(netId, version=4) # validate the returned value is a UUID

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='ACTIVE',
                                         entType='network',
                                         netId=netId,
                                         wait=wait)
            except:
                raise

        return(netId)

    def createIpNetworkService(self,
                             netId,
                             name,
                             gatewayIp,
                             gatewayNetmask,
                             interceptIp,
                             endpointId,
                             wait=0
                            ):
        """publish a subnetwork (IP or range described by network address and netmask)
        :param netId: network UUID
        :param name: descriptive name allowing whitespace
        :param gatewayIp: the network address of the subnet (lowest IP)
        :param gatewayNetmask: the netmask describing the size of the published subnet
        :param interceptIp: the network address of the subnet used by clients
        :param endpointId: UUID of the serving gateway that will provide this service
        :param wait: optional wait seconds for service to become ACTIVE
        """
        request = {
            "name": name,
            "serviceClass": "GW",
            "gatewayIp": gatewayIp,
            "gatewayNetmask": gatewayNetmask,
            "interceptIp": interceptIp,
            "endpointId": endpointId
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks/"+netId+"/services",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        svcId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

        # expected value is UUID of new endpoint
        UUID(svcId, version=4) # validate the returned value is a UUID

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='ACTIVE',
                                         entType='service',
                                         netId=netId,
                                         entId=svcId,
                                         wait=wait)
            except:
                raise

        return(svcId)

    def createAwsGateway(self, name, netId, dataCenterId, wait=0):
        """
        create a managed AWS gateway endpoint with
        :param name: gateway name
        :param netId: network UUID
        :param dataCenterId: datacenter UUID
        :param wait: optional wait seconds for endpoint to become REGISTERED (400)
        """
        request = {
            "name": name,
            "endpointType": "GW",
            "dataCenterId": dataCenterId
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks/"+netId+"/endpoints",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        endId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

        # expected value is UUID of new endpoint
        UUID(endId, version=4) # validate the returned value is a UUID

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='REGISTERED',
                                         entType='endpoint',
                                         netId=netId,
                                         entId=endId,
                                         wait=wait)
            except:
                raise

        return(endId)

    def createAwsCpeGateway(self, name, netId, dataCenterId, wait=0):
        """
        create a self-hosted AWS gateway endpoint with
        :param name: gateway name
        :param netId: network UUID
        :param dataCenterId: datacenter UUID
        :param wait: optional wait seconds for endpoint to become REGISTERED (400)
        """
        request = {
            "name": name,
            "endpointType": "AWSCPEGW",
            "dataCenterId": dataCenterId
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks/"+netId+"/endpoints",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        endId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

        # expected value is UUID of new endpoint
        UUID(endId, version=4) # validate the returned value is a UUID

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='REGISTERED',
                                         entType='endpoint',
                                         netId=netId,
                                         entId=endId,
                                         wait=wait)
            except:
                raise

        return(endId)

    def createVcpeGateway(self, name, netId, geoRegionId, wait=0):
        """
        create a self-hosted gateway endpoint with
        :param name: gateway name
        :param netId: network UUID
        :param geoRegionId: geo region UUID
        :param wait: optional wait seconds for endpoint to become REGISTERED (400)
        """
        request = {
            "name": name,
            "endpointType": "VCPEGW",
            "geoRegionId": geoRegionId
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks/"+netId+"/endpoints",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        endId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

        # expected value is UUID of new endpoint
        UUID(endId, version=4) # validate the returned value is a UUID

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='REGISTERED',
                                         entType='endpoint',
                                         netId=netId,
                                         entId=endId,
                                         wait=wait)
            except:
                raise

        return(endId)

    def createIpHostService(self,
                            netId,
                            name,
                            networkIp,
                            networkFirstPort,
                            networkLastPort,
                            interceptIp,
                            interceptFirstPort,
                            interceptLastPort,
                            protocolType,
                            endpointId,
                            wait=0
                           ):
        """publish a host:port(s) couplet
        :param netId: network UUID
        :param name: descriptive name allowing whitespace
        :param networkIp: interface or masquerade address of the published service
        :param networkFirstPort: lower bound of published port range
        :param networkLastPort: upper bound of published port range
        :param interceptIp: destination address used by clients
        :param interceptFirstPort: lower bound of destination port range
        :param interceptLastPort: upper bound of destination port range
        :param protocolType: one of tcp, udp
        :param endpointId: UUID of the serving gateway that provides this service
        :param wait: optional wait seconds for service to become ACTIVE
        """
        request = {
            "name": name,
            "serviceClass": "CS",
            "networkIp": networkIp,
            "networkFirstPort": networkFirstPort,
            "networkLastPort": networkLastPort,
            "interceptIp": interceptIp,
            "interceptFirstPort": interceptFirstPort,
            "interceptLastPort": interceptLastPort,
            "protocolType": protocolType,
            "endpointId": endpointId,
            "serviceType": protocolType.upper(),
            "transparency": "NO",
            "bridgeStp": "YES",
            "collectionLocation": "BOTH",
            "cryptoLevel": "STRONG",
            "dnsOptions": "NONE",
            "icmpTunnel": "YES",
            "localNetworkGateway": "YES",
            "multicast": "OFF",
            "pbrType": "WAN",
            "permanentConnection": "NO",
            "rateSmoothing": "YES",
            "serviceInterceptType": "IP"
        }
        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks/"+netId+"/services",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        svcId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

        # expected value is UUID of new endpoint
        UUID(svcId, version=4) # validate the returned value is a UUID

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='ACTIVE',
                                         entType='service',
                                         netId=netId,
                                         entId=svcId,
                                         wait=wait)
            except:
                raise

        return(svcId)

    def createEndpointGroup(self, name, netId):
        """
        create an endpoint group in a network with
        :param name: group name
        :param netId: network UUID
        """
        request = {
            "name": name
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks/"+netId+"/endpointGroups",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.CREATED:
            groupId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(groupId)

    def updateEndpointGroup(self,
                            name,
                            groupId,
                            netId,
                           ):
        """
        update an endpoint group name
        :param name: group name
        :param groupId: endpoint group UUID
        :param netId: network UUID
        """
        request = {
            "name": name
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.put(
                self.aud+"rest/v1/networks/"+netId+"/endpointGroups/"+groupId,
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            #print(response)
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.OK:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(True)

    def addEndpointToGroup(self,
                           groupId,
                           netId,
                           endpointIds):
        """
        add an endpoint to a group
        :param groupId: endpoint group UUID
        :param netId: network UUID
        :param endpointIds: list of endpoint UUIDs to add
        """
        request = {
            "ids": endpointIds # is list
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(
                self.aud+"rest/v1/networks/"+netId+"/endpointGroups/"+groupId+"/endpoints",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(True)


    def deleteEndpoint(self,
                       netId,
                       endpointId,
                       wait=0
                      ):
        """
        delete an endpoint by UUID
        :param netId: network UUID in which to discover the endpoints
        :param endpointId: endpoint UUID to delete
        :param wait: optional seconds to wait for endpoint destruction
        """
        headers = {
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.delete(self.aud+"rest/v1/networks/"+netId+"/endpoints/"+endpointId,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='DELETED',
                                         entType='endpoint',
                                         netId=netId,
                                         entId=endpointId,
                                         wait=wait)
            except:
                raise

        return(True)

    def deleteService(self,
                       netId,
                       svcId,
                       wait=0
                      ):
        """
        delete a service by UUID
        :param netId: network UUID
        :param svcId: service UUID to delete
        :param wait: optional seconds to wait for service destruction
        """
        headers = {
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.delete(self.aud+"rest/v1/networks/"+netId+"/services/"+svcId,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='DELETED',
                                         entType='endpoint',
                                         netId=netId,
                                         entId=endpointId,
                                         wait=wait)
            except:
                raise

        return(True)

    def createAppWan(self,
                     netId,
                     name,
                     wait=0
                   ):
        """authorize endpoint(s) for service(s) where
        :param netId: network UUID
        :param name: descriptive name allowing whitespace
        """
        request = {
            "name": name,
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.post(self.aud+"rest/v1/networks/"+netId+"/appWans",
                                     json=request,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            #print(response)
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.ACCEPTED:
            appWanId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='ACTIVE',
                                         entType='appWan',
                                         netId=netId,
                                         entId=appWanId,
                                         wait=wait)
            except:
                raise

        return(appWanId)

    def updateAppWan(self,
                     appWanId,
                     netId,
                     services,
                     endpoints=[],
                     endpointGroups=[],
                     wait=0
                   ):
        """authorize endpoint(s) or endpoint group(s) or both for service(s) where
        :param appWanId: AppWAN UUID to update
        :param netId: network UUID housing the AppWAN
        :param services: list of service UUIDs to publish
        :param endpoints: optional list of endpoint UUIDs to authorize
        :param endpointGroups: optional list of endpoint group UUIDs to authorize
        """

        appWan = dict()

        appWan['services'] = {
            "ids": services
        }

        appWan['endpoints'] = {
            "ids": endpoints
        }

        appWan['endpointGroups'] = {
            "ids": endpointGroups
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        for resource in ['services', 'endpoints', 'endpointGroups']:
            try:
                response = requests.post(
                    self.aud+"rest/v1/networks/"+netId+"/appWans/"+appWanId+"/"+resource,
                         json=appWan[resource],
                         headers=headers,
                         proxies=self.proxies,
                         verify=self.verify)
                #print(response)
                http_code = response.status_code
            except:
                raise

            if not http_code == requests.status_codes.codes.ACCEPTED:
                raise Exception(
                    'unexpected response: {} (HTTP {:d})'.format(
                        requests.status_codes._codes[http_code][0].upper(),
                        http_code
                    )
                )

            if not wait == 0:
                try:
                    self.waitForEntityStatus(status='ACTIVE',
                                             entType='appWan',
                                             netId=netId,
                                             entId=appWanId,
                                             wait=wait)
                except:
                    raise

        return(True)

    def deleteAppWan(self, netId, appWanId, wait=0):
        """
        delete a service connection(s) by UUID
        :param netId: network UUID in which to discover the endpoints
        :param appWanId: AppWan UUID to delete
        """
        headers = {
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.delete(self.aud+"rest/v1/networks/"+netId+"/appWans/"+appWanId,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='DELETED',
                                         entType='appWan',
                                         netId=netId,
                                         entId=appWanId,
                                         wait=wait)
            except:
                raise

        return(True)

    def deleteNetwork(self, netId, wait=0):
        """
        delete an NFN (aka SDN) by UUID
        :param netId: network UUID
        :param wait: optional wait seconds for network destruction before return
        """
        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.auth
        }

        try:
            response = requests.delete(self.aud+"rest/v1/networks/"+netId,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.verify
                                    )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        if not wait == 0:
            try:
                self.waitForEntityStatus(status='DELETED',
                                         entType='network',
                                         netId=netId,
                                         wait=wait)
            except:
                raise

        return(True)

    def getEntity(self, entType, netId, entId=0):
        """return the full object describing an entity
        :param entType: the type of entity e.g. network, endpoint, service
        :param netId: the UUID of the network housing the entity
        :param entId: the UUID of the entity having a status if not a network
        """

        try:
            headers = { "authorization": "Bearer " + self.auth }
            entUrl = self.aud+'rest/v1/networks/'+netId
            if not entType == 'network':
                if entId == 0:
                    raise Exception("ERROR: entity UUID must be specified if not a network")
                entUrl += '/'+entType+'s/'+entId

            response = requests.get(entUrl,
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers)
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK:
            try:
                entity = json.loads(response.text)
            except:
                eprint('ERROR parsing entity object in response')
                raise
        else:
            status = None

        return(entity)

    def getEntityStatus(self, entType, netId, entId=0):
        """return an object describing an entity's API status or the symbolic HTTP code
        :param entType: the type of entity e.g. network, endpoint, service
        :param netId: the UUID of the network housing the entity
        :param entId: the UUID of the entity having a status if not a network
        """

        try:
            headers = { "authorization": "Bearer " + self.auth }
            entUrl = self.aud+'rest/v1/networks/'+netId
            if not entType == 'network':
                if entId == 0:
                    raise Exception("ERROR: entity UUID must be specified if not a network")
                entUrl += '/'+entType+'s/'+entId

            response = requests.get(entUrl,
                                    proxies=self.proxies,
                                    verify=self.verify,
                                    headers=headers)
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK:
            try:
                status = json.loads(response.text)['status']
            except:
                eprint('ERROR parsing entity object in response')
                raise
        else:
            status = None

        return {
            'http_status': requests.status_codes._codes[http_code][0].upper(),
            'http_code': http_code,
            'status': status
        }

    def waitForEntityStatus(self, status, entType, netId, wait, entId=0):
        """continuously poll for the expected status until expiry
        :param status: string that is the symbolic name of the expected status code
        :param netId: the UUID of the network housing the entity
        :param entId: the UUID of the entity having a status if entity is not a network
        :param entType: the type of entity e.g. network, endpoint, service
        :param wait: SECONDS after which to raise an exception
        """

        now = time.time()

        # poll for status until expiry
        sys.stdout.write(
            '\twaiting for status {:s} ({:d}) or until {:s}.'.format(
                status,
                self.codes[status],
                time.ctime(now+wait)
            )
        )

        status_code = int()
        http_code = int()
        while (
            time.time() < now+wait
        ) and (
            not status_code == self.codes[status]
        ) and (
            not http_code == requests.status_codes.codes.NOT_FOUND
        ):
            sys.stdout.write('.') # print a stop each iteration to imply progress
            sys.stdout.flush()

            try:
                entity = self.getEntityStatus(entType=entType,
                                        netId=netId,
                                        entId=entId)
            except:
                raise

            if entity['status']: # attribute is not None if HTTP OK
                if not status_code or ( # print the starting status
                    status_code and     # print on subsequent changes
                    not status_code == entity['status']
                ):
                    sys.stdout.write(
                        '\n\t\t:'
                        +'{:^19s}'.format(
                            self.statusesByCode[
                                entity['status']
                            ][0].upper()
                        )
                        +':'
                    )
                status_code = entity['status']
            else:
                http_code = entity['http_code']

            time.sleep(15)
        print() # newline terminates progress meter

        if (
            status_code == self.codes[status]
        ) or (
            status == 'DELETED' and
            http_code == requests.status_codes.codes.FORBIDDEN
        ):
            return(True)
        elif not status_code:
            raise Exception(
                'failed to read status while waiting for {:s} ({:d}); got {} ({:d})'.format(
                    status,
                    self.codes[status],
                    entity['http_status'],
                    entity['http_code']
                )
            )
        else:
            raise Exception(
                'timed out with status {} ({:d}) while waiting for {:s} ({:d})'.format(
                    self.statusesByCode[status_code][0].upper(),
                    status_code,
                    status,
                    self.codes[status]
                )
            )

    def waitForEntityHttpStatus(self, status, entType, netId, wait, entId=0):
        """continuously poll for the expected HTTP response code until expiry
        :param entType: the type of entity e.g. network, endpoint, service
        :param id: the UUID of the entity having a status
        :param status: string that is the symbolic name of the expected status code
        :param wait: SECONDS after which to raise an exception
        Example: status NOT_FOUND will succeed when response is HTTP 404
        """

        now = time.time()

        # poll for status until expiry
        sys.stdout.write(
            '\twaiting for status {:s} ({:d}) or until {:s}.'.format(
                status,
                requests.status_codes.codes[status],
                time.ctime(now+wait)
            )
        )
        # resolve the expected status to an HTTP code
        status_code = requests.status_codes.codes[status]
        # initialize a variable to store the last checked HTTP code
        http_code = int()
        while time.time() < now+wait and not status_code == http_code:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                entity = self.getEntityStatus(entType=entType,
                                        netId=netId,
                                        entId=entId)
                if not http_code or (
                    http_code and
                    not http_code == entity['http_code']
                ):
                    sys.stdout.write(
                        '\n\t\t:'
                        +'{:^19s}'.format(
                            requests.status_codes._codes[
                                entity['http_code']
                            ][0].upper()
                        )
                        +':'

                    )

                http_code = entity['http_code']
            except:
                raise

            time.sleep(15)

        print() # newline terminates progress meter

        if status_code == http_code:
            return(True)
        else:
            raise Exception(
                'timed out with status {} ({}) while waiting for {} ({})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code,
                    status,
                    status_code,
                )
            )

class LookupDict(dict):
    """Dictionary lookup object."""

    def __init__(self, name=None):
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return '<lookup \'%s\'>' % (self.name)

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)
