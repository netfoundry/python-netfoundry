""" Interface to NetFoundry API
"""
import sys                  # open stderr
import json                 # 
import requests             # HTTP user agent will not emit server cert warnings if verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re                   # regex
import time                 # enforce a timeout; sleep
from uuid import UUID       # validate UUIDv4 strings
import jwt                  # decode the JWT claimset
from pathlib import Path    #
import os

class Session:
    """ Use an API account from a credentials file as described in https://developer.netfoundry.io/v2/guides/authentication/
    Example credentials file:
    {
        "clientId": "3tcm6to3qqfu78juj9huppk9g3",
        "password": "149a7ksfj3t5lstg0pesun69m1l4k91d6h8m779l43q0ekekr782",
        "authenticationUrl": "https://netfoundry-production-xfjiye.auth.us-east-1.amazoncognito.com/oauth2/token"
    }
    """

    def __init__(
        self, 
        token=None, 
        credentials=None, 
        proxy=None):
        """initialize with a reusable API client
        :param token: optional temporary API bearer/session token
        :param credentials: optional alternative path to API account credentials file
        :param proxy: optional HTTP proxy, e.g., http://localhost:8080
        The init function also gathers a few essential objects from the API and
        stores them as attributes on the model
        """

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
        
        # if not token then use standard env var if defined
        if token is not None:
            self.token = token
        elif 'NETFOUNDRY_API_TOKEN' in os.environ:
            self.token = os.environ['NETFOUNDRY_API_TOKEN']

        # if the token was found then extract the expiry
        try: self.token
        except AttributeError: epoch = None
        else:
            claim = jwt.decode(self.token,verify=False)
            # TODO: [MOP-13438] auto-renew token when near expiry (now+1hour in epoch seconds)
            expiry = claim['exp']
            epoch = time.time()

        # if no token or near expiry then use credentials to obtain a token
        if epoch is not None and epoch < (expiry - 600):
            # extract the API URL from the claim
            self.audience = claim['scope'].replace('/ignore-scope','')
            # e.g. https://gateway.production.netfoundry.io/
        else:
            # persist the credentials filename in instances so that it may be used to refresh the token
            if credentials is not None:
                self.credentials = credentials
                os.environ['NETFOUNDRY_API_ACCOUNT'] = self.credentials
            elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
                self.credentials = os.environ['NETFOUNDRY_API_ACCOUNT']
            elif os.path.exists(str(Path.cwd())+"/credentials.json"):
                self.credentials = str(Path.cwd())+"/credentials.json"
            elif os.path.exists(str(Path.home())+"/.netfoundry/credentials.json"):
                self.credentials = str(Path.home())+"/.netfoundry/credentials.json"
            elif os.path.exists("/netfoundry/credentials.json"):
                self.credentials = "/netfoundry/credentials.json"
            else:
                raise Exception("ERROR: need credentials file. Specify as param to Session or save in default location for project: {project} or user: {user} or device: {device}".format(
                    project=str(Path.cwd())+"/credentials.json",
                    user=str(Path.home())+"/.netfoundry/credentials.json",
                    device="/netfoundry/credentials.json"
                ))

            with open(self.credentials) as f:
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

class Organization:
    """ Use an organization
    """

    def __init__(self, Session):
        self.session = Session
        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.networkGroups = self.getNetworkGroups()
        self.networkGroupsByName = dict()
        for ng in self.networkGroups:
            self.networkGroupsByName[ng['organizationShortName']] = ng['id']
            # e.g. { NFADMIN: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

    def getNetworkGroups(self):
        """return the Network Groups object (formerly "organizations")
        """
        try:
            # /network-groups returns a list of dicts (Network Group objects)
            headers = { "authorization": "Bearer " + self.session.token }
            response = requests.get(
                self.session.audience+'rest/v1/network-groups',
                proxies=self.session.proxies,
                verify=self.session.verify,
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

    def getNetworksByOrganization(self):
        """
        return all networks in this Network Group
        """

        try:
            # returns a list of dicts (network objects)
            headers = { "authorization": "Bearer " + self.session.token }
            response = requests.get(
                self.session.audience+'core/v2/networks',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networks = json.loads(response.text)['_embedded'][RESOURCES['networks']['embedded']]
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
                "authorization": "Bearer " + self.session.token 
            }
            params = {
                "findByNetworkGroupId": networkGroupId
            }
            response = requests.get(
                self.session.audience+'/core/v2/networks',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                embedded = json.loads(response.text)
                networks = embedded['_embedded'][RESOURCES['networks']['embedded']]
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

class NetworkGroup:
    """use a Network Group by name or ID or the first group in the organization
    """
    def __init__(self, Organization, networkGroupId=None, networkGroupName=None):
        if networkGroupId:
            self.networkGroupId = networkGroupId
            self.networkGroupName = [ ng['organizationShortName'] for ng in Organization.networkGroups if ng['id'] == networkGroupId ][0]
        # TODO: review the use of org short name ref https://netfoundry.slack.com/archives/C45UDKR8V/p1603655594135000?thread_ts=1580318187.149400&cid=C45UDKR8V
        elif networkGroupName:
            self.networkGroupName = networkGroupName
            self.networkGroupId = [ ng['id'] for ng in Organization.networkGroups if ng['organizationShortName'] == networkGroupName ][0]
        elif len(Organization.networkGroups) > 0:
            # first Network Group is typically the only Network Group
            self.networkGroupId = Organization.networkGroups[0]['id']
            self.networkGroupName = Organization.networkGroups[0]['organizationShortName']
            # warn if there are other groups
            if len(Organization.networkGroups) > 1:
                eprint("WARN: Using first Network Group {:s} and ignoring {:d} other(s) e.g. {:s}, etc...".format(
                    self.networkGroupName,
                    len(Organization.networkGroups) - 1,
                    Organization.networkGroups[1]['organizationShortName']
                ))
            elif len(Organization.networkGroups) == 1:
                eprint("WARN: Using the default Network Group: {:s}".format(
                    self.networkGroupName
                ))
        else:
            raise Exception("ERROR: need at least one Network Group in organization")

        self.session = Organization.session
        self.id = self.networkGroupId
        self.name = self.networkGroupName
        self.vanity = self.networkGroupName.lower()

        # learn about the environment from the token and predict the web console URL
        try:
            claim = jwt.decode(self.session.token,verify=False)
            iss = claim['iss']
            if re.match('.*cognito.*', iss):
                self.environment = re.sub(r'https://gateway\.([^.]+)\.netfoundry\.io.*',r'\1',claim['scope'])
            elif re.match('auth0', iss):
                self.environment = re.sub(r'https://netfoundry-([^.]+)\.auth0\.com.*',r'\1',claim['iss'])
            if self.environment == "production":
                self.nfconsole = "https://{vanity}.nfconsole.io".format(vanity=self.vanity)
            else:
                self.nfconsole = "https://{vanity}.{env}-nfconsole.io".format(vanity=self.vanity, env=self.environment)
        except: raise

        # an attribute that is a dict for resolving network UUIDs by name
        self.networksByName = dict()
        for net in Organization.getNetworksByGroup(self.networkGroupId):
            self.networksByName[net['name']] = net['id']
        self.id = self.networkGroupId
        self.name = self.networkGroupName

        #inventory of infrequently-changing assets: configs, dataCenters
        self.networkConfigMetadatas = self.getNetworkConfigMetadatas()
        self.networkConfigMetadatasByName = dict()
        for config in self.networkConfigMetadatas:
            self.networkConfigMetadatasByName[config['name']] = config['id']
            # e.g. { small: 2616da5c-4441-4c3d-a9a2-ed37262f2ef4 }
        self.dataCenters = self.getDataCenters()
        self.dataCentersByLocationCode = dict()
        for dc in self.dataCenters:
            self.dataCentersByLocationCode[dc['locationCode']] = dc['id']
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

        self.dataCentersByMajorRegion = dict()
        for major in MAJOR_REGIONS['AWS'].keys():
            self.dataCentersByMajorRegion[major] = [dc for dc in self.dataCenters if dc['provider'] == "AWS" and dc['locationName'] in MAJOR_REGIONS['AWS'][major]]

    def getNetworkConfigMetadatas(self):
        """return the list of network config metadata which are required to create a network
        """
        try:
            headers = { "authorization": "Bearer " + self.session.token }
            response = requests.get(
                self.session.audience+'core/v2/network-configs',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )

            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networkConfigMetadatas = json.loads(response.text)['_embedded']['networkConfigMetadataList']
            except ValueError as e:
                eprint('ERROR getting network config metadata')
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
            headers = { "authorization": "Bearer " + self.session.token }
            response = requests.get(
                self.session.audience+'rest/v1/dataCenters',
                proxies=self.session.proxies,
                verify=self.session.verify,
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
            headers = { "authorization": "Bearer " + self.session.token }
            params = { "locationCode": locationCode }
            response = requests.get(
                self.session.audience+'rest/v1/dataCenters',
                proxies=self.session.proxies,
                verify=self.session.verify,
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

    def createNetwork(self, name, netGroup=None, location="us-east-1", version=None, netConfig="small"):
        """
        create a network with
        :param name: required network name
        :param netGroup: optional Network Group short name
        :param location: optional datacenter region name in which to create
        :param version: optional product version string like 7.2.0-1234567
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
            "authorization": "Bearer " + self.session.token
        }

        try:
            response = requests.post(
                self.session.audience+"core/v2/networks",
                proxies=self.session.proxies,
                verify=self.session.verify,
                json=request,
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes[RESOURCES['networks']['expect']]:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        netId = json.loads(response.text)['id']
        # expected value is UUID
        UUID(netId, version=4) # validate the returned value is a UUID

        return(netId)

    def deleteNetwork(self, networkId=None, networkName=None):
        """
        delete a Network
        :param id: optional Network UUID to delete
        :param name: optional Network name to delete
        """
        try:
            if networkId:
                networkName = [ net['name'] for net in self.networksByName if net['id'] == networkId ][0]
            elif networkName and networkName in self.networksByName.keys():
                networkId = self.networksByName[networkName]
        except:
            raise Exception("ERROR: need one of networkId or networkName for a Network in this Network Group: {:s}".format(self.name))

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entityUrl = self.session.audience+'core/v2/networks/'+networkId
            response = requests.delete(
                entityUrl,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
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
class Network:
    """describe and use a Network
    """
    def __init__(self, Session, networkId=None, networkName=None):
        """
        :param token: required bearer token for this session
        :param networkName: optional name of the network to describe and use
        :param networkId: optional UUID of the network to describe and use
        """
        self.session = Session

        if networkId:
            self.describe = self.getNetworkById(networkId)
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
        self.networkConfigMetadataId = self.describe['networkConfigMetadataId']
        self.o365BreakoutCategory = self.describe['o365BreakoutCategory']
        self.createdAt = self.describe['createdAt']
        self.updatedAt = self.describe['updatedAt']
        self.createdBy = self.describe['createdBy']

    def endpoints(self):
        return(self.getResources("endpoints"))

    def edgeRouters(self):
        return(self.getResources("edge-routers"))

    def services(self):
        return(self.getResources("services"))

    def edgeRouterPolicies(self):
        return(self.getResources("edge-router-policies"))

    def appWans(self):
        return(self.getResources("app-wans"))

    def deleteNetwork(self,wait=300,progress=True):
        self.deleteResource(type="network",wait=wait,progress=progress)
#        raise Exception("ERROR: failed to delete Network {:s}".format(self.name))

    def getResources(self,type):
        """return the resources object
            :type [required] one of endpoints, edge-routers, services
        """
        try:
            headers = {
                "authorization": "Bearer " + self.session.token 
            }
            params = {
                "networkId": self.id,
                "page": 0,
                "size": 10,
                "sort": "name,asc"
            }
            response = requests.get(
                self.session.audience+'core/v2/'+type,
                proxies=self.session.proxies,
                verify=self.session.verify,
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
            return(resources['_embedded'][RESOURCES[type]['embedded']])
        # if there are multiple pages of resources
        else:
            # initialize the list with the first page of resources
            all_pages = resources['_embedded'][RESOURCES[type]['embedded']]
            # append the remaining pages of resources
            for page in range(1,total_pages):
                try:
                    params["page"] = page
                    response = requests.get(
                        self.session.audience+'core/v2/'+type,
                        proxies=self.session.proxies,
                        verify=self.session.verify,
                        headers=headers,
                        params=params
                    )
                    http_code = response.status_code
                except:
                    raise

                if http_code == requests.status_codes.codes.OK: # HTTP 200
                    try:
                        resources = json.loads(response.text)
                        all_pages += resources['_embedded'][RESOURCES[type]['embedded']]
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

    def createEndpoint(self, name, attributes=[]):
        """create an Endpoint
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception("ERROR: hashtag role attributes on an Endpoint must begin with #")
            body = {
                "networkId": self.id,
                "name": name,
                "attributes": attributes,
                "enrollmentMethod": { "ott": True }
            }
            response = requests.post(
                self.session.audience+'core/v2/endpoints',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            http_code = response.status_code
        except:
            raise
        if http_code == requests.status_codes.codes.OK: # HTTP 200 (synchronous fulfillment)
            try:
                endpoint = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Endpoint"))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(endpoint)

    def createEdgeRouter(self, name, attributes=[], linkListener=False, dataCenterId=None):
        """create an Edge Router
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception("ERROR: hashtag role attributes on an Endpoint must begin with #")
            body = {
                "networkId": self.id,
                "name": name,
                "attributes": attributes,
                "linkListener": linkListener
            }
            if dataCenterId:
                body['dataCenterId'] = dataCenterId
                body['linkListener'] = True
            response = requests.post(
                self.session.audience+'core/v2/edge-routers',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            http_code = response.status_code
        except:
            raise
        if http_code == requests.status_codes.codes[RESOURCES['edge-routers']['expect']]:
            try:
                router = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Edge Router"))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(router)

    def createEdgeRouterPolicy(self, name, endpointAttributes=[], edgeRouterAttributes=[]):
        """create an Edge Router Policy
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in endpointAttributes+edgeRouterAttributes:
                if not re.match('^[#@]', role):
                    raise Exception("ERROR: role attributes on a policy must begin with # or @")
            body = {
                "networkId": self.id,
                "name": name,
                "endpointAttributes": endpointAttributes,
                "edgeRouterAttributes": edgeRouterAttributes
            }
            response = requests.post(
                self.session.audience+'core/v2/edge-router-policies',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            http_code = response.status_code
        except:
            raise
        if http_code == requests.status_codes.codes[RESOURCES['edge-router-policies']['expect']]:
            try:
                policy = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Edge Router Policy"))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(policy)

    def createService(self, name: str, clientHostName: str, clientPortRange: int, serverHostName: str, 
        serverPortRange: int, serverProtocol: str="TCP", attributes: list=[], edgeRouterAttributes: list=[], 
        egressRouterId: str=None, endpoints: list=[], encryptionRequired: bool=True):
        """create a Service
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception("ERROR: hashtag role attributes on an Endpoint must begin with #")
            body = {
                "networkId": self.id,
                "name": name,
                "attributes": attributes,
                "clientHostName": clientHostName,
                "clientPortRange": clientPortRange,
                "serverHostName": serverHostName,
                "serverPortRange": serverPortRange,
                "serverProtocol": serverProtocol,
                "encryptionRequired": encryptionRequired
            }
            # resolve exit hosting params
            if egressRouterId and endpoints:
                raise Exception("ERROR: specify only one of egressRouterId or endpoints to host the exit for this Service")
            elif endpoints:
                body['endpoints'] = endpoints
            elif egressRouterId:
                body['egressRouterId'] = egressRouterId

            # resolve Edge Router param
            if edgeRouterAttributes:
                eprint("WARN: overriding default Service Edge Router Policy #all for new Service {:s}".format(name))
                body['edgeRouterAttributes'] = edgeRouterAttributes

            response = requests.post(
                self.session.audience+'core/v2/services',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            http_code = response.status_code
        except:
            raise
        if http_code == requests.status_codes.codes[RESOURCES['services']['expect']]:
            try:
                service = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Service"))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(service)

    def createAppWan(self, name: str, endpointAttributes: list=[], serviceAttributes: list=[], postureCheckAttributes: list=[]):
        """create an AppWAN
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in endpointAttributes+serviceAttributes+postureCheckAttributes:
                if not re.match('^[#@]', role):
                    raise Exception("ERROR: role attributes on an AppWAN must begin with # or @")
            body = {
                "networkId": self.id,
                "name": name,
                "endpointAttributes": endpointAttributes,
                "serviceAttributes": serviceAttributes,
                "postureCheckAttributes": postureCheckAttributes
            }

            response = requests.post(
                self.session.audience+'core/v2/app-wans',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            http_code = response.status_code
        except:
            raise
        if http_code == requests.status_codes.codes[RESOURCES['app-wans']['expect']]:
            try:
                appwan = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("AppWAN"))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(appwan)

    def getNetworkByName(self,name):
        """return exactly one network object
            :name required name of the NF network may contain quoted whitespace
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            params = {
                "findByName": name
            }
            response = requests.get(
                self.session.audience+'/core/v2/networks',
                proxies=self.session.proxies,
                verify=self.session.verify,
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
            network = networks['_embedded'][RESOURCES['networks']['embedded']][0]
            return(network)
        else:
            raise Exception("ERROR: failed to find exactly one match for {}".format(name))

    def getNetworkById(self,networkId):
        """return the network object for a particular UUID
            :networkId [required] the UUID of the network
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            response = requests.get(
                self.session.audience+'/core/v2/networks/'+networkId,
                proxies=self.session.proxies,
                verify=self.session.verify,
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

    def waitForStatus(self, expect, type="network", wait=300, sleep=9, id=None, progress=False):
        """continuously poll for the expected status until expiry
        :param expect: the expected status symbol e.g. PROVISIONED
        :param id: the UUID of the entity having a status if entity is not a network
        :param type: optional type of entity e.g. network (default), endpoint, service, edge-router
        :param wait: optional SECONDS after which to raise an exception defaults to five minutes (300)
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
                entity = self.getResourceStatus(type=type, id=id)
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

    def getResourceStatus(self, type, id=None):
        """return an object describing an entity's API status or the symbolic HTTP code
        :param type: the type of entity e.g. network, endpoint, service, edge-router
        :param id: the UUID of the entity having a status if not a network
        """

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entityUrl = self.session.audience+'core/v2/'
            if type == 'network':
                entityUrl += 'networks/'+self.id
            elif id is None:
                raise Exception("ERROR: entity UUID must be specified if not a network")
            else:
                entityUrl += type+'s/'+id
            params = {
                "networkId": self.id
            }
            response = requests.get(
                entityUrl,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
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
                return {
                    'http_status': requests.status_codes._codes[http_code][0].upper(),
                    'http_code': http_code,
                    'status': status,
                    'name': name
                }
        else:
            return {
                'http_status': requests.status_codes._codes[http_code][0].upper(),
                'http_code': http_code
            }

    def deleteResource(self, type, id=None, wait=int(0), progress=False):
        """
        delete a resource
        :param type: required entity type to delete i.e. network, endpoint, service, edge-router
        :param id: required entity UUID to delete
        :param wait: optional seconds to wait for entity destruction
        """
        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entityUrl = self.session.audience+'core/v2/networks/'+self.id
            if not type == 'network':
                if id is None:
                    raise Exception("ERROR: need entity UUID to delete")
                entityUrl += '/'+type+'s/'+id

            response = requests.delete(
                entityUrl,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
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
                self.waitForStatus(
                    expect='DELETED',
                    type=type,
                    id=self.id if type == 'network' else id,
                    wait=wait,
                    progress=progress
                )
            except:
                raise

        return(True)

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

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

STATUSES_BY_CODE = {
    100: ('new', 'created'),
    200: ('building', 'incomplete', 'allocated'),
    300: ('active', 'complete', 'provisioned'),
    400: ('registered', 'enrolled'),
    500: ('error', 'server_error'),
    600: ('updating', 'modifying'),
    800: ('deleting', 'released', 'decommissioned'),
    900: ('defunct', 'deleted')
}

CODES = LookupDict(name='statuses')
for code, titles in STATUSES_BY_CODE.items():
    for title in titles:
        setattr(CODES, title.upper(), code)

RESOURCES = {
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
    'edge-router-policies': {
        'embedded': "edgeRouterPolicyList",
        'expect': "ACCEPTED"
    },
    'app-wans': {
        'embedded': "appWanList",
        'expect': "OK"
    },
    'services': {
        'embedded': "serviceList",
        'expect': "OK"
    }
}

# TODO: [MOP-13441] associate locations with a short list of major regions / continents
MAJOR_REGIONS = {
    "AWS" : {
        "Americas": ("Canada Central","N. California","N. Virginia","Ohio","Oregon","Sao Paulo"),
        "EuropeMiddleEastAfrica": ("Bahrain","Cape Town South Africa","Frankfurt","Ireland","London","Milan","Paris","Stockholm"),
        "AsiaPacific": ("Hong Kong","Mumbai","Seoul","Singapore","Sydney","Tokyo")
    }
}

