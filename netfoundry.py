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
from pathlib import Path

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class client(object):
    """interact with the NetFoundry API
    """

    def __init__(self, credentials=str(Path.home())+"/.netfoundry/credentials.json", proxy=None, environment="production"):
        """initialize with a reusable API client
        :param credentials: optional alternative path to API account credentials file
        :param proxy: optional HTTP proxy, e.g., http://localhost:8080
        :param environment optional override of "production"
        The init function also gathers a few essential objects from the API and
        stores them for reuse in the instance namespace
        """

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

        self.resources = {
            'networks': {
                'embedded': "networkList",
                'expect': "ACCEPTED"
            },
            'endpoints': {
                'embedded': "endpointList",
                'expect': "OK"
            },
            'edge-routers': {
                'embedded': "edgeRouterList",
                'expect': "ACCEPTED"
            },
            'services': {
                'embedded': "serviceList",
                'expect': "ACCEPTED"
            }
        }

        # TODO: [MOP-13441] associate locations with a short list of major regions / continents
        """
        self.locationsByContinent = {
            "Americas": ("Canada Central","Oregon","Virginia"),
            "EuropeMiddleEastAfrica": ("Frankfurt","London"),
            "AsiaPacific": ("Hong Kong","Jakarta","Mumbai","Seoul","Singapore","Sydney","Tokyo")
        }
        """

        for code, titles in self.statusesByCode.items():
            for title in titles:
                setattr(self.codes, title.upper(), code)

        with open(credentials) as f:
            self.account = json.load(f)
        self.tokenEndpoint = self.account['authenticationUrl']
        self.clientId = self.account['clientId']
        self.password = self.account['password']
        # verify auth endpoint's server certificate if proxy is type SOCKS or None
        if proxy == None:
            self.proxies = dict()
            self.verify = True
        else:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
            if proxy[0:5] == 'socks':
                self.verify = True
            else:
                self.verify = False
        # re: scope: we're not using scopes with Cognito, but a non-empty value is required;
        #  hence "/ignore-scope"
        if environment == 'localhost':
            self.scope = "http://localhost:8080//ignore-scope"
        else:
            self.scope = "https://gateway."+environment+".netfoundry.io//ignore-scope"
        self.assertion = {
            "scope": self.scope,
            "grant_type": "client_credentials"
        }
        try:
            self.response = requests.post(
                self.tokenEndpoint,
                auth=(self.clientId, self.password),
                data=self.assertion,
                verify=self.verify,
                proxies=self.proxies)
            self.responseCode = self.response.status_code
        except:
            eprint(
                'ERROR: failed to contact the authentication endpoint: {}'.format(self.tokenEndpoint)
            )
            raise

        if self.responseCode == requests.status_codes.codes.OK:
            try:
                self.tokenText = json.loads(self.response.text)
                self.token = self.tokenText['access_token']
            except:
                raise Exception(
                    'ERROR: failed to find an access_token in the response and instead got: {}'.format(
                        self.response.text
                    )
                )
        else:
            raise Exception(
                'ERROR: got unexpected HTTP response {} ({:d})'.format(
                    requests.status_codes._codes[self.responseCode][0].upper(),
                    self.responseCode
                )
            )

        # we can gather the URL of the API from the first part of the scope string by
        #  dropping the scope suffix
        self.audience = self.scope.replace('/ignore-scope','')
        self.claim = jwt.decode(self.token,verify=False)

        # TODO: [MOP-13438] auto-renew token when near expiry (now+1hour in epoch seconds)
        self.expiry = self.claim['exp']

        self.networkGroups = self.getNetworkGroups()
        self.networkGroupsByName = dict()
        for ng in self.networkGroups:
            self.networkGroupsByName[ng['organizationShortName']] = ng['id']
            # e.g. { NFADMIN: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

        self.networkConfigMetadatas = self.getNetworkConfigMetadatas()
        self.networkConfigMetadatasByName = dict()
        for config in self.networkConfigMetadatas:
            self.networkConfigMetadatasByName[config['name']] = config['id']
            # e.g. { small: 2616da5c-4441-4c3d-a9a2-ed37262f2ef4 }

        self.datacenters = self.getDataCenters()
        self.datacentersByRegion = dict()
        for dc in self.datacenters:
            self.datacentersByRegion[dc['locationCode']] = dc['id']
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

        # an attribute that is a dict for resolving network UUIDs by name
        self.networksByName = dict()
        for net in self.getNetworks():
            self.networksByName[net['name']] = net['id']
            # e.g. { testNetwork: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

    def getNetworkConfigMetadatas(self):
        """return the list of network config metadata which are required to create a network
        """
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'rest/v1/networkConfigMetadata',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networkConfigMetadatas = json.loads(response.text)['_embedded']['networkConfigMetadatas']
            except ValueError as e:
                eprint('ERROR getting network config metadatas')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(networkConfigMetadatas)

    def getNetworkGroups(self):
        """return the network groups object (formerly "organizations")
        """
        try:
            # /network-groups returns a list of dicts (network group objects)
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'rest/v1/network-groups',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networkGroups = json.loads(response.text)['_embedded']['organizations']
            except ValueError as e:
                eprint('ERROR getting network groups')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(networkGroups)

    def getDataCenters(self):
        """return the dataCenters object
        """
        try:
            # dataCenters returns a list of dicts (datacenter objects)
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'rest/v1/dataCenters',
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

    def getNetworks(self):
        """
        return all networks in this network group
        """

        try:
            # returns a list of dicts (network objects)
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'core/v2/networks',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networks = json.loads(response.text)['_embedded'][self.resources['networks']['embedded']]
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

    def getNetworkByName(self,name):
        """return the network object
            :token required API access token
            :networkId required name of the NF network may contain quoted whitespace
        """
    #    name_encoding = urllib.parse.quote(name)
        try:
            headers = { 
                "authorization": "Bearer " + self.token 
            }
            params = {
                "findByName": name
            }
            response = requests.get(
                self.audience+'/core/v2/networks',
                headers=headers,
                params=params
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networks = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load endpoints object from GET response')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )
        hits = networks['page']['totalElements']
        if hits == 1:
            network = networks['_embedded']['networkList'][0]
            return(network)
        else:
            raise Exception("ERROR: failed to find exactly one match for {}".format(name))

    def getNetwork(self,networkId):
        """return the network object
            :networkId [required] the UUID of the NF network
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.token 
            }
            response = requests.get(
                self.audience+'/core/v2/networks/'+networkId,
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                network = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = "network"))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(network)

    def getResources(token,type,networkId):
        """return the resources object
            :token [required] the API access token
            :type [required] one of endpoints, edge-routers, services
            :networkId [required] the UUID of the NF network
        """
        try:
            headers = { 
                "authorization": "Bearer " + token 
            }
            params = {
                "networkId": networkId,
                "page": 0,
                "size": 10,
                "sort": "name,asc"
            }
            response = requests.get(
                self.audience+'core/v2/'+type,
                headers=headers,
                params=params
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                resources = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = type))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        total_pages = resources['page']['totalPages']
        total_elements = resources['page']['totalElements']
        # if there are no resources
        if total_elements == 0:
            return([])
        # if there is one page of resources
        elif total_pages == 1:
            return(resources['_embedded'][self.resources[type]['embedded']])
        # if there are multiple pages of resources
        else:
            # initialize the list with the first page of resources
            all_pages = resources['_embedded'][self.resources[type]['embedded']]
            # append the remaining pages of resources
            for page in range(1,total_pages):
                try:
                    params["page"] = page
                    response = requests.get(
                        self.audience+'/core/v2/'+type,
                        headers=headers,
                        params=params
                    )
                    http_code = response.status_code
                except:
                    raise

                if http_code == requests.status_codes.codes.OK: # HTTP 200
                    try:
                        resources = json.loads(response.text)
                        all_pages += resources['_embedded'][self.resources[type]['embedded']]
                    except ValueError as e:
                        eprint('ERROR: failed to load resources object from GET response')
                        raise(e)
                else:
                    raise Exception(
                        'unexpected response: {} (HTTP {:d})'.format(
                            requests.status_codes._codes[http_code][0].upper(),
                            http_code
                        )
                    )
            return(all_pages)

    def patchAttributes(token,type,resource):
        """return the new resource object
            :token [required] the API access token
            :type [required] one of endpoints, edge-routers, services
            :resource [required] the resource object to PUT 
        """
        try:
            headers = { 
                'Content-Type': 'application/json',
                "authorization": "Bearer " + token 
            }
            response = requests.patch(
                self.audience+'/core/v2/'+type+'/'+resource['id'],
                json={
                    'name': resource['name'],
                    'attributes': resource['attributes']
                },
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes[self.resources[type]['expect']]: # HTTP 200
            try:
                updated = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load updated resource object from PUT response body')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d}\n{})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code,
                    response.text
                )
            )

        return(updated)

    def post(self,
        method,
        json,
        expected_response="ACCEPTED"):
        """
        post arbitrary data as JSON to an API method
        """

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.post(
                self.audience+"core/v2"+method,
                json=json,
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
                http_code)
            )
        text = response.text
        return(text)

    def createNetwork(self, netGroup, name, location='us-east-1', version=None, wait=0, netConfig="small"):
        """
        create a network with
        :param name: required network group short name
        :param name: required network name
        :param location: required datacenter region name in which to create
        :param version: optional product version string like 7.2.0-1234567
        :param wait: optional wait seconds for network to build before returning
        :param netConfig: optional network configuration metadata name e.g. "medium"
        """
        request = {
            "name": name,
            "locationCode": location,
            "networkGroupId": self.networkGroupsByName[netGroup],
            "networkConfigMetadataId": self.networkConfigMetadatasByName[netConfig]
        }
        if version:
            request['productVersion'] = version

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.post(
                self.audience+"core/v2/networks",
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

        netId = json.loads(response.text)['id']
        # expected value is UUID
        UUID(netId, version=4) # validate the returned value is a UUID

        if not wait == 0:
            try:
                self.waitForEntityStatus(
                    status='ACTIVE',
                    entType='network',
                    netId=netId,
                    wait=wait)
            except:
                raise

        return(netId)

    def createIpNetworkService(
            self,
            netId,
            name,
            gatewayIp,
            gatewayNetmask,
            interceptIp,
            endpointId,
            wait=0):
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
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.post(self.audience+"core/v2/networks/"+netId+"/services",
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

    def createAwsGateway(self, name, netId, dataCenterId, wait=0, family="dvn", managed=False):
        """
        create an AWS gateway endpoint with
        :param name: gateway name
        :param netId: network UUID
        :param dataCenterId: datacenter UUID
        :param wait: optional wait seconds for endpoint to become REGISTERED (400)
        :param family: optional family indicating endpoint type if not "dvn"
        :param managed: optional boolean indicating instance is launched and managed by MOP
        """

        if not managed and family == "ziti":
            endpointType = "ZTNHGW"
        elif not managed and family == "dvn":
            endpointType = "AWSCPEGW"
        elif managed and family == "ziti":
            endpointType = "ZTGW"
        elif managed and family == "dvn":
            endpointType = "GW"
        else:
            raise Exception(
                'unexpected family "{}" or endpoint type "{}"'.format(
                    family,
                    endpointType
                )
            )

        request = {
            "name": name,
            "endpointType": endpointType,
            "dataCenterId": dataCenterId
        }

        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.post(self.audience+"core/v2/networks/"+netId+"/endpoints",
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
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.post(self.audience+"core/v2/networks/"+netId+"/endpoints",
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
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.post(self.audience+"core/v2/networks/"+netId+"/services",
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

    def deleteResource(self,
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
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.delete(self.audience+"core/v2/networks/"+netId+"/endpoints/"+endpointId,
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
            "authorization": "Bearer " + self.token
        }

        try:
            response = requests.post(self.audience+"core/v2/networks/"+netId+"/appWans",
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
            "authorization": "Bearer " + self.token
        }

        for resource in ['services', 'endpoints', 'endpointGroups']:
            try:
                response = requests.post(
                    self.audience+"core/v2/networks/"+netId+"/appWans/"+appWanId+"/"+resource,
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

    def getEntity(self, entType, netId, entId=0):
        """return the full object describing an entity
        :param entType: the type of entity e.g. network, endpoint, service
        :param netId: the UUID of the network housing the entity
        :param entId: the UUID of the entity having a status if not a network
        """

        try:
            headers = { "authorization": "Bearer " + self.token }
            entUrl = self.audience+'core/v2/networks/'+netId
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
            headers = { "authorization": "Bearer " + self.token }
            entUrl = self.audience+'core/v2/networks/'+netId
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
