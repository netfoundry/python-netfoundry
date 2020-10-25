""" NetFoundry API for Python 3
"""
import sys # open stderr
import json # operate on structured data
import requests # HTTP user agent
import re # regex
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import time # enforce a timeout; sleep
import uuid # generate a UUID as a businessKey if it is not provided
from uuid import UUID # validate UUIDv4 strings
import jwt # decode the JWT claimset to extract the organization UUID
from pathlib import Path

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class Organization:
    """ Use an organization with a credentials file as described in https://developer.netfoundry.io/v2/guides/authentication/
    Example credentials file:
    {
        "clientId": "3tcm6to3qqfu78juj9huppk9g3",
        "password": "149a7ksfj3t5lstg0pesun69m1l4k91d6h8m779l43q0ekekr782",
        "authenticationUrl": "https://netfoundry-production-xfjiye.auth.us-east-1.amazoncognito.com/oauth2/token"
    }
    """

    def __init__(
        self, token=None, 
        credentials=str(Path.home())+"/.netfoundry/credentials.json", 
        networkGroupId=None,
        networkGroupName=None,
        proxy=None):
        """initialize with a reusable API client
        :param token: optional temporary API bearer/session token
        :param credentials: optional alternative path to API account credentials file
        :param networkGroupId: optional Network Group UUID to select, overrides networkGroupName
        :param networkGroupName: optional Network Group name to select
        :param proxy: optional HTTP proxy, e.g., http://localhost:8080
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
        
        if token:
            claim = jwt.decode(token,verify=False)
            # TODO: [MOP-13438] auto-renew token when near expiry (now+1hour in epoch seconds)
            expiry = claim['exp']
            epoch = time.time()
            # extract the API URL from the claim
            self.audience = claim['scope'].replace('/ignore-scope','')
            # e.g. https://gateway.production.netfoundry.io/

        # if no token or near expiry then use credentials to obtain a token
        if token and epoch < (expiry - 600):
            self.token = token
        else:
            with open(credentials) as f:
                account = json.load(f)
            tokenEndpoint = account['authenticationUrl']
            clientId = account['clientId']
            password = account['password']
            # extract the environment name from the authorization URL aka token API endpoint
            self.environment = re.sub(r'https://netfoundry-([^-]+)-.*', r'\1', tokenEndpoint, re.IGNORECASE)
            # re: scope: we're not using scopes with Cognito, but a non-empty value is required;
            #  hence "/ignore-scope"
            scope = "https://gateway."+self.environment+".netfoundry.io//ignore-scope"
            # we can gather the URL of the API from the first part of the scope string by
            #  dropping the scope suffix
            self.audience = scope.replace('/ignore-scope','')
            # e.g. https://gateway.production.netfoundry.io/
            assertion = {
                "scope": scope,
                "grant_type": "client_credentials"
            }
            # request a token
            try:
                response = requests.post(
                    tokenEndpoint,
                    auth=(clientId, password),
                    data=assertion,
                    verify=self.verify,
                    proxies=self.proxies)
                responseCode = response.status_code
            except:
                eprint(
                    'ERROR: failed to contact the authentication endpoint: {}'.format(self.tokenEndpoint)
                )
                raise

            if responseCode == requests.status_codes.codes.OK:
                try:
                    tokenText = json.loads(response.text)
                    self.token = tokenText['access_token']
                except:
                    raise Exception(
                        'ERROR: failed to find an access_token in the response and instead got: {}'.format(
                            response.text
                        )
                    )
            else:
                raise Exception(
                    'ERROR: got unexpected HTTP response {} ({:d})'.format(
                        requests.status_codes._codes[responseCode][0].upper(),
                        responseCode
                    )
                )

        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.networkGroups = self.getNetworkGroups()
        self.networkGroupsByName = dict()
        for ng in self.networkGroups:
            self.networkGroupsByName[ng['organizationShortName']] = ng['id']
            # e.g. { NFADMIN: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }
        if networkGroupId:
            self.networkGroupId = networkGroupId
            self.networkGroupName = [ ng['organizationShortName'] for ng in self.networkGroups if ng['id'] == networkGroupId ][0]
        # TODO: review the use of org short name ref https://netfoundry.slack.com/archives/C45UDKR8V/p1603655594135000?thread_ts=1580318187.149400&cid=C45UDKR8V
        elif networkGroupName:
            self.networkGroupName = networkGroupName
            self.networkGroupId = [ ng['id'] for ng in self.networkGroups if ng['organizationShortName'] == networkGroupName ][0]
        else:
            # first Network Group is typically the only Network Group
            self.networkGroupId = self.networkGroups[0]['id']
            self.networkGroupName = self.networkGroups[0]['organizationShortName']
            # warn if there are other groups
            if len(self.networkGroups) > 1:
                eprint("WARN: Using first Network Group {:s} and ignoring {:d} other(s) e.g. {:s}, etc...").format(
                    self.networkGroupName,
                    len(self.networkGroups) - 1,
                    self.networkGroups[1]['organizationShortName']
                )

    def getNetworkGroups(self):
        """return the Network Groups object (formerly "organizations")
        """
        try:
            # /network-groups returns a list of dicts (Network Group objects)
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
                eprint('ERROR getting Network Groups')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(networkGroups)

class NetworkGroup(Organization):
    """interact with the NetFoundry API on behalf of a Network Group
    """
    def __init__(self, token, networkGroupId=None, networkGroupName=None, **kwargs):

        if networkGroupId:
            super().__init__(token=token, networkGroupId=networkGroupId, **kwargs)
        elif networkGroupName:
            super().__init__(token=token, networkGroupName=networkGroupName, **kwargs)
        else:
            raise Exception("ERROR: need one of networkGroupId or networkGroupName")

        self.token = token
        self.id = self.networkGroupId
        self.name = self.networkGroupName

        # an attribute that is a dict for resolving network UUIDs by name
        self.networksByName = dict()
        for net in self.getNetworks():
            self.networksByName[net['name']] = net['id']
            # e.g. { testNetwork: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

        #inventory of infrequently-changing assets only when token is renewed 
        self.networkConfigMetadatas = self.getNetworkConfigMetadatas()
        self.networkConfigMetadatasByName = dict()
        for config in self.networkConfigMetadatas:
            self.networkConfigMetadatasByName[config['name']] = config['id']
            # e.g. { small: 2616da5c-4441-4c3d-a9a2-ed37262f2ef4 }

        self.dataCenters = self.getDataCenters()
        self.dataCentersByRegion = dict()
        for dc in self.dataCenters:
            self.dataCentersByRegion[dc['locationCode']] = dc['id']
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

    # remainder of Organization parent class
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
        
    def getDataCenters(self):
        """return the dataCenters object
        :param kwargs: optional named parameters as field filters
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
                dataCenters = json.loads(response.text)['_embedded']['dataCenters']
            except ValueError as e:
                eprint('ERROR getting dataCenters')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(dataCenters)

    def getDataCenterByLocation(self, locationCode):
        """return one dataCenter object
        :param locationCode: required single location to fetch
        """
        try:
            # dataCenters returns a list of dicts (datacenter objects)
            headers = { "authorization": "Bearer " + self.token }
            params = { "locationCode": locationCode }
            response = requests.get(
                self.audience+'rest/v1/dataCenters',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                params=params
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                dataCenter = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting dataCenter')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(dataCenter)

    def getNetworks(self):
        """
        return all networks in this Network Group
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

    def getNetworksByGroup(self,networkGroupId):
        """return list of network objects
            :param networkGroupId: required network group UUID
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.token 
            }
            params = {
                "findByNetworkGroupId": networkGroupId
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

    def createNetwork(self, name, netGroup=None, location="us-east-1", version=None, wait=0, netConfig="small", progress=False):
        """
        create a network with
        :param name: required network name
        :param netGroup: optional Network Group short name
        :param location: optional datacenter region name in which to create
        :param version: optional product version string like 7.2.0-1234567
        :param wait: optional wait seconds for network to build before returning
        :param netConfig: optional network configuration metadata name e.g. "medium"
        """
        request = {
            "name": name,
            "locationCode": location,
            "networkConfigMetadataId": self.networkConfigMetadatasByName[netConfig]
        }
        if netGroup:
            request["networkGroupId"] = netGroup
        else:
            request["networkGroupId"] = self.networkGroupId

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
                self.waitForStatus(
                    expect='PROVISIONED',
                    entType='network',
                    netId=netId,
                    wait=wait,
                    progress=progress)
            except:
                raise

        return(netId)

    def waitForStatus(self, expect, entType, netId, wait, sleep=9, entId=0, progress=False):
        """continuously poll for the expected status until expiry
        :param expect: the expected status symbol e.g. PROVISIONED
        :param netId: the UUID of the network housing the entity
        :param entId: the UUID of the entity having a status if entity is not a network
        :param entType: the type of entity e.g. network, endpoint, service
        :param wait: SECONDS after which to raise an exception
        :param sleep: SECONDS polling interval
        """

        now = time.time()

        if not wait >= sleep:
            raise Exception(
                "ERROR: wait duration ({:d}) must be greater than or equal to polling interval ({:d})".format(
                    wait, sleep
                )
            )

        # poll for status until expiry
        if progress:
            sys.stdout.write(
                '\twaiting for status {:s} or until {:s}.'.format(
                    expect,
                    time.ctime(now+wait)
                )
            )

        status = str()
        http_code = int()
        while (
            time.time() < now+wait
        ) and (
            not status == expect
        ) and (
            not http_code == requests.status_codes.codes.NOT_FOUND
        ):
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                entity = self.getResourceStatus(entType=entType,
                                        netId=netId,
                                        entId=entId)
            except:
                raise

            if entity['status']: # attribute is not None if HTTP OK
                if not status or ( # print the starting status
                    status and not entity['status'] == status # print on subsequent changes
                ):
                    if progress:
                        sys.stdout.write('\n{:^19s}:{:^19s}:'.format(entity['name'],entity['status']))
                status = entity['status']
            else:
                http_code = entity['http_code']

            if not expect == status:
                time.sleep(sleep)
        print() # newline terminates progress meter

        if (
            status == expect
        ) or (
            status == 'DELETED' and
            http_code == requests.status_codes.codes.FORBIDDEN
        ):
            return(True)
        elif not status:
            raise Exception(
                'failed to read status while waiting for {:s}; got {} ({:d})'.format(
                    expect,
                    entity['http_status'],
                    entity['http_code']
                )
            )
        else:
            raise Exception(
                'timed out with status {} while waiting for {:s}'.format(
                    status,
                    expect
                )
            )

    def getResourceStatus(self, entType, netId, entId=0):
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
                name = json.loads(response.text)['name']
            except:
                eprint('ERROR parsing entity object in response')
                raise
        else:
            status = None

        return {
            'http_status': requests.status_codes._codes[http_code][0].upper(),
            'http_code': http_code,
            'status': status,
            'name': name
        }

    def waitForHttpResponse(self, status, entType, netId, wait, entId=0):
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
                entity = self.getResourceStatus(entType=entType,
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

class Network(NetworkGroup):
    """describe and use a Network
    """
    def __init__(self, token, networkGroupId, networkId=None, networkName=None, **kwargs):
        """
        :param token: required bearer token for this session
        :param networkGroupId: required UUID of the network group from NetworkGroup.id
        :param networkName: optional name of the network to describe and use
        :param networkId: optional UUID of the network to describe and use
        """
        super().__init__(token=token, networkGroupId=networkGroupId, **kwargs)

        if networkId:
            self.describe = self.getNetwork(networkId)
        elif networkName:
            self.describe = self.getNetworkByName(networkName)
        else:
            raise Exception("ERROR: need one of networkId or networkName")

        # populate some attributes
        self.id = self.describe['id']
        self.name = self.describe['name']
        self.networkGroupId = self.describe['networkGroupId']
        self.status = self.describe['status']
        self.productVersion = self.describe['productVersion']
        self.ownerIdentityId = self.describe['ownerIdentityId']
        self.deletedBy = self.describe['deletedBy']
        self.networkConfigMetadataId = self.describe['networkConfigMetadataId']
        self.o365BreakoutCategory = self.describe['o365BreakoutCategory']
        self.deletedAt = self.describe['deletedAt']
        self.createdAt = self.describe['createdAt']
        self.updatedAt = self.describe['updatedAt']
        self.createdBy = self.describe['createdBy']

        if not self.networkGroupId == networkGroupId:
            raise Exception("ERROR: requested network {:s} is not in the specified network group {:s}").format(
                self.name,
                networkGroupId
            )

    def endpoints(self):
        return(self.getResources(self.token, "endpoints", self.id))

    def edgeRouters(self):
        return(self.getResources(self.token, "edge-routers", self.id))

    def services(self):
        return(self.getResources(self.token, "services", self.id))

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

    def getNetworkByName(self,name):
        """return exactly one network object
            :name required name of the NF network may contain quoted whitespace
        """
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
        """return the network object for a particular UUID
            :networkId [required] the UUID of the network
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
            response = requests.post(
                self.audience+"core/v2/networks/"+netId+"/services",
                json=request,
                headers=headers,
                proxies=self.proxies,
                verify=self.verify)
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
                self.waitForStatus(
                    status='ACTIVE',
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
                self.waitForStatus(status='REGISTERED',
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
                self.waitForStatus(status='REGISTERED',
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
                self.waitForStatus(status='ACTIVE',
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
                self.waitForStatus(status='DELETED',
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
                self.waitForStatus(status='ACTIVE',
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
                    self.waitForStatus(status='ACTIVE',
                                             entType='appWan',
                                             netId=netId,
                                             entId=appWanId,
                                             wait=wait)
                except:
                    raise

        return(True)

    def describeResource(self, entType, netId, entId=0):
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
