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
            print("DEBUG: found API token in env NETFOUNDRY_API_TOKEN")

        # if no token or near expiry then use credentials to obtain a token
        if epoch is not None and epoch < (expiry - 600):
            # extract the API URL from the claim
            self.audience = claim['scope'].replace('/ignore-scope','')
            # e.g. https://gateway.production.netfoundry.io/
            print("DEBUG: using API token from env NETFOUNDRY_API_TOKEN")
        else:
            # persist the credentials filename in instances so that it may be used to refresh the token
            if credentials is not None:
                self.credentials = credentials
                os.environ['NETFOUNDRY_API_ACCOUNT'] = self.credentials
            elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
                self.credentials = os.environ['NETFOUNDRY_API_ACCOUNT']
            else:
                self.credentials = "credentials.json"

            # unless a valid path assume relative and search the default chain
            if not os.path.exists(self.credentials):
                default_creds_chain = [
                    {
                        "scope": "project",
                        "base": str(Path.cwd())
                    },
                    {
                        "scope": "user",
                        "base": str(Path.home())+"/.netfoundry"
                    },
                    {
                        "scope": "device",
                        "base": "/netfoundry"
                    }
                ]
                for link in default_creds_chain:
                    candidate = link['base']+"/"+self.credentials
                    if os.path.exists(candidate):
                        print("INFO: using default {scope} credentials in {path}".format(
                            scope=link['scope'],
                            path=candidate
                        ))
                        self.credentials = candidate
                        break
            else:
                print("INFO: using credentials in {path}".format(
                    path=self.credentials
                ))

            try:
                with open(self.credentials) as file:
                    try: account = json.load(file)
                    except: raise Exception("ERROR: failed to load JSON from {file}".format(file=file))
            except: raise Exception("ERROR: failed to open {file} while working in {dir}".format(
                file=self.credentials,dir=str(Path.cwd())))
            token_endpoint = account['authenticationUrl']
            client_id = account['clientId']
            password = account['password']
            # extract the environment name from the authorization URL aka token API endpoint
            self.environment = re.sub(r'https://netfoundry-([^-]+)-.*', r'\1', token_endpoint, re.IGNORECASE)
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
                    token_endpoint,
                    auth=(client_id, password),
                    data=assertion,
                    verify=self.verify,
                    proxies=self.proxies)
                response_code = response.status_code
            except:
                eprint(
                    'ERROR: failed to contact the authentication endpoint: {}'.format(token_endpoint)
                )
                raise

            if response_code == requests.status_codes.codes.OK:
                try:
                    token_text = json.loads(response.text)
                    self.token = token_text['access_token']
                except:
                    raise Exception(
                        'ERROR: failed to find an access_token in the response and instead got: {}'.format(
                            response.text
                        )
                    )
            else:
                raise Exception(
                    'ERROR: got unexpected HTTP response {} ({:d})'.format(
                        requests.status_codes._codes[response_code][0].upper(),
                        response_code
                    )
                )

class Organization:
    """ Use an organization
    """

    def __init__(self, Session):
        self.session = Session
        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.network_groups = self.get_network_groups()
        self.describe = self.get_organization()
        self.label = self.describe['label']

    def get_organization(self):
        """return the Organizations object (formerly "tenants")
        """
        try:
            headers = { "authorization": "Bearer " + self.session.token }
            response = requests.get(
                self.session.audience+'identity/v1/organizations',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                organizations = json.loads(response.text)
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

        return(organizations[0])


    def get_network_group(self,network_group_id):
        """describe a Network Group
        """
        try:
            # /network-groups/{id} returns a Network Group object
            headers = { "authorization": "Bearer " + self.session.token }
            response = requests.get(
                self.session.audience+'rest/v1/network-groups/'+network_group_id,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                network_group = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Group')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(network_group)

    def get_network_groups(self):
        """list Network Groups
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
                network_groups = json.loads(response.text)['_embedded']['organizations']
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

        return(network_groups)

    def get_networks_by_organization(self):
        """
        return all networks known to this Organization
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

    def get_networks_by_group(self,network_group_id):
        """return list of network objects
            :param network_group_id: required network group UUID
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            params = {
                "findByNetworkGroupId": network_group_id
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
    def __init__(self, Organization, network_group_id=None, network_group_name=None):
        if network_group_id:
            self.network_group_id = network_group_id
            self.network_group_name = [ ng['organizationShortName'] for ng in Organization.network_groups if ng['id'] == network_group_id ][0]
        # TODO: review the use of org short name ref https://netfoundry.slack.com/archives/C45UDKR8V/p1603655594135000?thread_ts=1580318187.149400&cid=C45UDKR8V
        elif network_group_name:
            self.network_group_name = network_group_name
            self.network_group_id = [ ng['id'] for ng in Organization.network_groups if ng['organizationShortName'] == network_group_name ][0]
        elif len(Organization.network_groups) > 0:
            # first Network Group is typically the only Network Group
            self.network_group_id = Organization.network_groups[0]['id']
            self.network_group_name = Organization.network_groups[0]['organizationShortName']
            # warn if there are other groups
            if len(Organization.network_groups) > 1:
                eprint("WARN: Using first Network Group {:s} and ignoring {:d} other(s) e.g. {:s}, etc...".format(
                    self.network_group_name,
                    len(Organization.network_groups) - 1,
                    Organization.network_groups[1]['organizationShortName']
                ))
            elif len(Organization.network_groups) == 1:
                eprint("WARN: Using the default Network Group: {:s}".format(
                    self.network_group_name
                ))
        else:
            raise Exception("ERROR: need at least one Network Group in organization")

        self.session = Organization.session
        self.describe = Organization.get_network_group(self.network_group_id)
        self.id = self.network_group_id
        self.name = self.network_group_name
        self.vanity = Organization.label.lower()

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
        self.networks_by_name = dict()
        for net in Organization.get_networks_by_group(self.network_group_id):
            self.networks_by_name[net['name']] = net['id']
        self.id = self.network_group_id
        self.name = self.network_group_name

        #inventory of infrequently-changing assets: configs, datacenters
        self.network_config_metadata = self.get_network_config_metadata()
        self.network_config_metadata_by_name = dict()
        for config in self.network_config_metadata:
            self.network_config_metadata_by_name[config['name']] = config['id']
            # e.g. { small: 2616da5c-4441-4c3d-a9a2-ed37262f2ef4 }
        self.nc_datacenters = self.get_controller_datacenters()
        self.nc_datacenters_by_location = dict()
        for dc in self.nc_datacenters:
            self.nc_datacenters_by_location[dc['locationCode']] = dc['id']
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }

    def get_network_config_metadata(self):
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
                network_config_metadata = json.loads(response.text)['_embedded']['networkConfigMetadataList']
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

        return(network_config_metadata)

    def get_controller_datacenters(self):
        """list the datacenters where a Network Controller may be created
        """
        try:
            # datacenters returns a list of dicts (datacenter objects)
            headers = { "authorization": "Bearer " + self.session.token }
            params = {
                "hostType": "NC",
                "provider": "AWS"
            }
            response = requests.get(
                self.session.audience+'core/v2/data-centers',
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

    def get_datacenter_by_location(self, location):
        """return one datacenter object
        :param location: required single location to fetch
        """
        try:
            # datacenters returns a list of dicts (datacenter objects)
            headers = { "authorization": "Bearer " + self.session.token }
            params = { "locationCode": location }
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
                datacenter = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting datacenter')
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(datacenter)

    def create_network(self, name, network_group_id=None, location="us-east-1", version=None, network_config="small"):
        """
        create a network with
        :param name: required network name
        :param network_group: optional Network Group ID
        :param location: optional datacenter region name in which to create
        :param version: optional product version string like 7.2.0-1234567
        :param network_config: optional network configuration metadata name e.g. "medium"
        """
        request = {
            "name": name,
            "locationCode": location,
            "networkConfigMetadataId": self.network_config_metadata_by_name[network_config]
        }
        if network_group_id:
            request["networkGroupId"] = network_group_id
        else:
            request["networkGroupId"] = self.network_group_id

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

        network_id = json.loads(response.text)['id']
        # expected value is UUID
        UUID(network_id, version=4) # validate the returned value is a UUID

        return(network_id)

    def delete_network(self, network_id=None, network_name=None):
        """
        delete a Network
        :param id: optional Network UUID to delete
        :param name: optional Network name to delete
        """
        try:
            if network_id:
                network_name = [ net['name'] for net in self.networks_by_name if net['id'] == network_id ][0]
            elif network_name and network_name in self.networks_by_name.keys():
                network_id = self.networks_by_name[network_name]
        except:
            raise Exception("ERROR: need one of network_id or network_name for a Network in this Network Group: {:s}".format(self.name))

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/networks/'+network_id
            response = requests.delete(
                entity_url,
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
    def __init__(self, Session, network_id=None, network_name=None):
        """
        :param token: required bearer token for this session
        :param network_name: optional name of the network to describe and use
        :param network_id: optional UUID of the network to describe and use
        """
        self.session = Session

        if network_id:
            self.describe = self.get_network_by_id(network_id)
        elif network_name:
            self.describe = self.get_network_by_name(network_name)
        else:
            raise Exception("ERROR: need one of network_id or network_name")

        # populate some attributes
        self.id = self.describe['id']
        self.name = self.describe['name']
        self.network_group_id = self.describe['networkGroupId']
        self.status = self.describe['status']
        self.product_version = self.describe['productVersion']
        self.owner_identity_id = self.describe['ownerIdentityId']
        self.network_confi_metadata_id = self.describe['networkConfigMetadataId']
        self.o365_breakout_category = self.describe['o365BreakoutCategory']
        self.created_at = self.describe['createdAt']
        self.updated_at = self.describe['updatedAt']
        self.created_by = self.describe['createdBy']

        self.aws_geo_regions = dict()
        for geo in MAJOR_REGIONS['AWS'].keys():
            self.aws_geo_regions[geo] = [dc for dc in self.get_edge_router_datacenters(provider="AWS") if dc['locationName'] in MAJOR_REGIONS['AWS'][geo]]

    def endpoints(self):
        return(self.get_resources("endpoints"))

    def edge_routers(self):
        return(self.get_resources("edge-routers"))

    def services(self):
        return(self.get_resources("services"))

    def edge_router_policies(self):
        return(self.get_resources("edge-router-policies"))

    def app_wans(self):
        return(self.get_resources("app-wans"))

    def delete_network(self,wait=300,progress=True):
        self.delete_resource(type="network",wait=wait,progress=progress)
#        raise Exception("ERROR: failed to delete Network {:s}".format(self.name))

    def get_edge_router_datacenters(self,provider=None):
        """list the datacenters where an Edge Router may be created
        """
        try:
            # datacenters returns a list of dicts (datacenter objects)
            headers = { "authorization": "Bearer " + self.session.token }
            params = {
                "productVersion": self.product_version,
                "hostType": "ER"
            }
            if provider is not None:
                if provider in ["AWS", "AZURE", "GCP", "ALICLOUD", "NetFoundry"]:
                    params['provider'] = provider
                else:
                    raise Exception("ERROR: illegal cloud provider {:s}".format(provider))
            response = requests.get(
                self.session.audience+'core/v2/data-centers',
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

    def share_endpoint(self,recipient,endpoint_id):
        """share the new endpoint enrollment token with an email address
            :recipient [required] the email address
            :endpoint_id [required] the UUID of the endpoint
        """
        try:
            headers = {
                "authorization": "Bearer " + self.session.token 
            }
            body = [
                {
                    "toList": [recipient],
                    "subject": "Your enrollment token for {:s}".format(self.name),
                    "id": endpoint_id
                }
            ]
            response = requests.post(
                self.session.audience+'core/v2/endpoints/share',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes['ACCEPTED']:
            raise Exception(
                'unexpected response: {} (HTTP {:d}\n{})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code,
                    response.text
                )
            )
            
    def get_resources(self,type,name=None):
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
            if name is not None:
                params['name'] = name
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

    def patch_resource(self,patch):
        """return a resources
            :patch: required dictionary with the new properties 
        """
        try:
            headers = {
                "authorization": "Bearer " + self.session.token 
            }
            response = requests.patch(
                patch['_links']['self']['href'],
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=patch
            )
            http_code = response.status_code
        except:
            raise

        if http_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                resource = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from PATCH response'.format(r = type))
                raise(e)
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )
        return(resource)

    def create_endpoint(self, name, attributes=[]):
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

    def create_edge_router(self, name, attributes=[], link_listener=False, datacenter_id=None):
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
                "linkListener": link_listener
            }
            if datacenter_id:
                body['dataCenterId'] = datacenter_id
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
                print('DEBUG: created Edge Router trace ID {:s}'.format(response.headers._store['x-b3-traceid'][1]))
        else:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        return(router)

    def create_edge_router_policy(self, name, endpoint_attributes=[], edge_router_attributes=[]):
        """create an Edge Router Policy
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in endpoint_attributes+edge_router_attributes:
                if not re.match('^[#@]', role):
                    raise Exception("ERROR: role attributes on a policy must begin with # or @")
            body = {
                "networkId": self.id,
                "name": name,
                "endpointAttributes": endpoint_attributes,
                "edgeRouterAttributes": edge_router_attributes
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

    def create_service(self, name: str, client_host_name: str, client_port_range: int, server_host_name: str, 
        server_port_range: int, server_protocol: str="TCP", attributes: list=[], edge_router_attributes: list=[], 
        egress_router_id: str=None, endpoints: list=[], encryption_required: bool=True):
        """create a Service
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception('ERROR: invalid role "{:s}". Must begin with "#"'.format(role))
            body = {
                "networkId": self.id,
                "name": name,
                "attributes": attributes,
                "clientHostName": client_host_name,
                "clientPortRange": client_port_range,
                "serverHostName": server_host_name,
                "serverPortRange": server_port_range,
                "serverProtocol": server_protocol,
                "encryptionRequired": encryption_required
            }
            # resolve exit hosting params
            if egress_router_id and endpoints:
                raise Exception("ERROR: specify only one of egress_router_id or endpoints to host the exit for this Service")
            elif endpoints:
                body['endpoints'] = endpoints
            elif egress_router_id:
                body['egressRouterId'] = egress_router_id

            # resolve Edge Router param
            if edge_router_attributes:
                eprint("WARN: overriding default Service Edge Router Policy #all for new Service {:s}".format(name))
                body['edgeRouterAttributes'] = edge_router_attributes

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

    def create_app_wan(self, name: str, endpoint_attributes: list=[], service_attributes: list=[], posture_check_attributes: list=[]):
        """create an AppWAN
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in endpoint_attributes+service_attributes+posture_check_attributes:
                if not re.match('^[#@]', role):
                    raise Exception("ERROR: role attributes on an AppWAN must begin with # or @")
            body = {
                "networkId": self.id,
                "name": name,
                "endpointAttributes": endpoint_attributes,
                "serviceAttributes": service_attributes,
                "postureCheckAttributes": posture_check_attributes
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
                app_wan = json.loads(response.text)
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

        return(app_wan)

    def get_network_by_name(self,name):
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

    def get_network_by_id(self,network_id):
        """return the network object for a particular UUID
            :network_id [required] the UUID of the network
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            response = requests.get(
                self.session.audience+'/core/v2/networks/'+network_id,
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

    def wait_for_status(self, expect, type="network", wait=300, sleep=20, id=None, progress=False):
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
        while time.time() < now+wait and not status == expect:
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                entity = self.get_resource_status(type=type, id=id)
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

        if status == expect:
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

    def get_resource_status(self, type, id=None):
        """return an object describing an entity's API status or the symbolic HTTP code
        :param type: the type of entity e.g. network, endpoint, service, edge-router
        :param id: the UUID of the entity having a status if not a network
        """

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/'
            if type == 'network':
                entity_url += 'networks/'+self.id
            elif id is None:
                raise Exception("ERROR: entity UUID must be specified if not a network")
            else:
                entity_url += type+'s/'+id
            params = {
                "networkId": self.id
            }
            response = requests.get(
                entity_url,
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

    def delete_resource(self, type, id=None, wait=int(0), progress=False):
        """
        delete a resource
        :param type: required entity type to delete i.e. network, endpoint, service, edge-router
        :param id: required entity UUID to delete
        :param wait: optional seconds to wait for entity destruction
        """
        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/networks/'+self.id
            expect = requests.status_codes.codes.ACCEPTED
            if not type == 'network':
                if id is None:
                    raise Exception("ERROR: need entity UUID to delete")
                entity_url = self.session.audience+'core/v2/'+type+'s/'+id
                expect = requests.status_codes.codes.OK
            eprint("WARN: deleting {:s}".format(entity_url))
            response = requests.delete(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            http_code = response.status_code
        except:
            raise

        if not http_code == expect:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        if not wait == 0:
            try:
                self.wait_for_status(
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

# TODO: [MOP-13441] associate locations with a short list of major geographic regions / continents
MAJOR_REGIONS = {
    "AWS" : {
        "Americas": ("Canada Central","N. California","N. Virginia","Ohio","Oregon","Sao Paulo"),
        "EuropeMiddleEastAfrica": ("Bahrain","Cape Town South Africa","Frankfurt","Ireland","London","Milan","Paris","Stockholm"),
        "AsiaPacific": ("Hong Kong","Mumbai","Seoul","Singapore","Sydney","Tokyo")
    }
}

