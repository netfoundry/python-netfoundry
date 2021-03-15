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
from re import sub

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
        self.proxy = proxy
        if proxy is None:
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
        try: 
            self.token
#            import q; q(self.token)
        except AttributeError: epoch = None
        else:
            claim = jwt.decode(jwt=self.token, algorithms=["RS256"], options={"verify_signature": False})
            # TODO: [MOP-13438] auto-renew token when near expiry (now+1hour in epoch seconds)
            expiry = claim['exp']
            epoch = time.time()

        # persist the credentials filename in instances so that it may be used to refresh the token
        if credentials is not None:
            self.credentials = credentials
            os.environ['NETFOUNDRY_API_ACCOUNT'] = self.credentials
        elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
            self.credentials = os.environ['NETFOUNDRY_API_ACCOUNT']
        else:
            self.credentials = "credentials.json"

        # import q; q(epoch)
        # import epdb; epdb.serve()

        # if no token or near expiry (30 min) then use credentials to obtain a token
        if epoch is None or epoch > (expiry - 1800):
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
                    'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                        requests.status_codes._codes[response_code][0].upper(),
                        response_code,
                        response.text
                    )
                )

        # learn about the environment from the token
        try:
            claim = jwt.decode(jwt=self.token, algorithms=["RS256"], options={"verify_signature": False})
            iss = claim['iss']
            if re.match(r'https://cognito-', iss):
                self.environment = re.sub(r'https://gateway\.([^.]+)\.netfoundry\.io.*',r'\1',claim['scope'])
            elif re.match(r'.*\.auth0\.com', iss):
                self.environment = re.sub(r'https://netfoundry-([^.]+)\.auth0\.com.*',r'\1',claim['iss'])
            # import q; q(claim)
            # import epdb; epdb.serve()
            self.audience = 'https://gateway.'+self.environment+'.netfoundry.io/'
        except: raise

class Organization:
    """ Use an organization
    """

    def __init__(self, Session):
        self.session = Session
        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.network_groups = self.get_network_groups_by_organization()
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
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                organizations = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Groups')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                network_group = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Group')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(network_group)

    def get_network(self,network_id):
        """describe a Network by ID
        """
        try:
            # /networks/{id} returns a Network object
            headers = { "authorization": "Bearer " + self.session.token }
            response = requests.get(
                self.session.audience+'rest/v1/networks/'+network_id,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                network = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Group')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(network)

    def get_network_groups_by_organization(self):
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
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                network_groups = json.loads(response.text)['_embedded']['organizations']
            except ValueError as e:
                eprint('ERROR getting Network Groups')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networks = json.loads(response.text)['_embedded'][RESOURCES['networks']['embedded']]
            except KeyError:
                networks = []
                pass
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
                self.session.audience+'core/v2/networks',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                embedded = json.loads(response.text)
                networks = embedded['_embedded'][RESOURCES['networks']['embedded']]
            except KeyError:
                networks = []
                pass
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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

        if self.session.environment == "production":
            self.nfconsole = "https://{vanity}.nfconsole.io".format(vanity=self.vanity)
        else:
            self.nfconsole = "https://{vanity}.{env}-nfconsole.io".format(vanity=self.vanity, env=self.session.environment)

        # an attribute that is a dict for resolving network UUIDs by name
        self.networks_by_name = dict()
        for net in Organization.get_networks_by_group(self.network_group_id):
            self.networks_by_name[net['name']] = net['id']
        self.id = self.network_group_id
        self.name = self.network_group_name

        #inventory of infrequently-changing assets: configs, data centers
        self.network_config_metadata = self.get_network_config_metadata()
        self.network_config_metadata_by_name = dict()
        for config in self.network_config_metadata:
            self.network_config_metadata_by_name[config['name']] = config['id']
            # e.g. { small: 2616da5c-4441-4c3d-a9a2-ed37262f2ef4 }
        self.nc_data_centers = self.get_controller_data_centers()
        self.nc_data_centers_by_location = dict()
        for dc in self.nc_data_centers:
            self.nc_data_centers_by_location[dc['locationCode']] = dc['id']
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

            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                network_config_metadata = json.loads(response.text)['_embedded']['networkConfigMetadataList']
            except ValueError as e:
                eprint('ERROR getting network config metadata')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(network_config_metadata)

    def get_controller_data_centers(self):
        """list the data centers where a Network Controller may be created
        """
        try:
            # data centers returns a list of dicts (data center objects)
            headers = { "authorization": "Bearer " + self.session.token }
            params = {
                # "productVersion": self.product_version,
                # "hostType": "NC",
                # "provider": "AWS"
            }
            response = requests.get(
                self.session.audience+'core/v2/data-centers',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                all_data_centers = json.loads(response.text)['_embedded']['dataCenters']
                aws_data_centers = [dc for dc in all_data_centers if dc['provider'] == "AWS"]
            except ValueError as e:
                eprint('ERROR getting data centers')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(aws_data_centers)

    def create_network(self, name: str, network_group_id: str=None, location: str="us-east-1", version: str=None, size: str="small"):
        """
        create a network with
        :param name: required network name
        :param network_group: optional Network Group ID
        :param location: optional data center region name in which to create
        :param version: optional product version string like 7.3.17
        :param size: optional network configuration metadata name from /core/v2/network-configs e.g. "medium"
        """
        
        if not size in self.network_config_metadata_by_name.keys():
            raise Exception("ERROR: unexpected Network size '{:s}'. Valid sizes include: {}.".format(size, str(self.network_config_metadata_by_name.keys())))

        if not location in self.nc_data_centers_by_location.keys():
            raise Exception("ERROR: unexpected Network location '{:s}'. Valid locations include: {}.".format(location, self.nc_data_centers_by_location.keys()))

        request = {
            "name": name,
            "locationCode": location,
            "size": size,
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
            response_code = response.status_code
        except:
            raise

        if not response_code == requests.status_codes.codes[RESOURCES['networks']['expect']]:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        network = json.loads(response.text)
        return(network)

    def delete_network(self, network_id=None, network_name=None):
        """
        delete a Network
        :param id: optional Network UUID to delete
        :param name: optional Network name to delete
        """
        try:
            if network_id:
#                import epdb; epdb.serve()
                network_name = next(name for name, uuid in self.networks_by_name.items() if uuid == network_id)
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
            response_code = response.status_code
        except:
            raise

        if not response_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        network = json.loads(response.text)
        return(network)

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
        self.size = self.describe['size']
        self.o365_breakout_category = self.describe['o365BreakoutCategory']
        self.created_at = self.describe['createdAt']
        self.updated_at = self.describe['updatedAt']
        self.created_by = self.describe['createdBy']

        self.aws_geo_regions = dict()
        for geo in major_regions['AWS'].keys():
            self.aws_geo_regions[geo] = [dc for dc in self.get_edge_router_data_centers(provider="AWS") if dc['locationName'] in major_regions['AWS'][geo]]

    def endpoints(self):
        return(self.get_resources("endpoints"))

    def edge_routers(self, only_hosted: bool=False, only_customer: bool=False):
        all_edge_routers = self.get_resources("edge-routers")
        if only_hosted and only_customer:
            raise Exception("ERROR: specify only one of only_hosted or only_customer")
        elif only_hosted:
            hosted_edge_routers = [er for er in all_edge_routers if er['dataCenterId']]
            return(hosted_edge_routers)
        elif only_customer:
            customer_edge_routers = [er for er in all_edge_routers if not er['dataCenterId']]
            return(customer_edge_routers)
        else:
            return(all_edge_routers)

    def services(self):
        return(self.get_resources("services"))

    def edge_router_policies(self):
        return(self.get_resources("edge-router-policies"))

    def app_wans(self):
        return(self.get_resources("app-wans"))

    def posture_checks(self):
        return(self.get_resources("posture-checks"))

    def delete_network(self,wait=300,progress=True):
        self.delete_resource(type="network",wait=wait,progress=progress)
#        raise Exception("ERROR: failed to delete Network {:s}".format(self.name))

    def get_edge_router_data_centers(self,provider: str=None,location_code: str=None):
        """list the data centers where an Edge Router may be created
        """
        try:
            # data centers returns a list of dicts (data centers)
            headers = { "authorization": "Bearer " + self.session.token }
            params = {
                "productVersion": self.product_version,
                "hostType": "ER"
            }
            if provider is not None:
                if provider in ["AWS", "AZURE", "GCP", "ALICLOUD", "NETFOUNDRY", "OCP"]:
                    params['provider'] = provider
                else:
                    raise Exception("ERROR: unexpected cloud provider {:s}".format(provider))
            response = requests.get(
                self.session.audience+'core/v2/data-centers',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                data_centers = json.loads(response.text)['_embedded']['dataCenters']
            except ValueError as e:
                eprint('ERROR getting data centers')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )
        if location_code:
            matching_data_centers = [dc for dc in data_centers if dc['locationCode'] == location_code]
#            import epdb; epdb.serve()
            return(matching_data_centers)
        else:
            return(data_centers)

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
            response_code = response.status_code
        except:
            raise

        if not response_code == requests.status_codes.codes['ACCEPTED']:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )
            
    def get_resources(self,type,name=None):
        """return the resources object
            :type [required]
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
            if type == "services": 
                params["beta"] = ''

            if name is not None:
                params['name'] = name

            response = requests.get(
                self.session.audience+'core/v2/'+type,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                resources = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = type))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
                    response_code = response.status_code
                except:
                    raise

                if response_code == requests.status_codes.codes.OK: # HTTP 200
                    try:
                        resources = json.loads(response.text)
                        all_pages += resources['_embedded'][RESOURCES[type]['embedded']]
                    except ValueError as e:
                        eprint('ERROR: failed to load resources object from GET response')
                        raise(e)
                else:
                    raise Exception(
                        'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                            requests.status_codes._codes[response_code][0].upper(),
                            response_code,
                            response.text
                        )
                    )
            return(all_pages)

    def patch_resource(self,patch):
        """returns a resource
            :patch: required dictionary with changed properties 
        """

        headers = {
            "authorization": "Bearer " + self.session.token 
        }

        try:
            before_response = requests.get(
                patch['_links']['self']['href'],
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            before_response_code = before_response.status_code
        except:
            raise

        if before_response_code in [requests.status_codes.codes.OK]: # HTTP 200
            try:
                before_resource = json.loads(before_response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = type))
                raise(e)
        else:
            json_formatted = json.dumps(patch, indent=2)
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s} for GET {:s}'.format(
                    requests.status_codes._codes[before_response_code][0].upper(),
                    before_response_code,
                    before_response.text,
                    json_formatted
                )
            )
        # compare the patch to the discovered, current state, adding new or updated keys to pruned_patch
        pruned_patch = dict()
        for k in patch.keys():
            if k in before_resource.keys() and not before_resource[k] == patch[k]:
                pruned_patch[k] = patch[k]

        if re.match(r'.*/services/',patch['_links']['self']['href']) and patch['zitiId'] == "zFdiFkJD1":
            import epdb; epdb.serve()

        # attempt to update if there's at least one difference between the current resource and the submitted patch
        if len(pruned_patch.keys()) > 0:
            if not "name" in pruned_patch.keys():
                pruned_patch["name"] = before_resource["name"]
            try:
                after_response = requests.patch(
                    patch['_links']['self']['href'],
                    proxies=self.session.proxies,
                    verify=self.session.verify,
                    headers=headers,
                    json=pruned_patch
                )
                after_response_code = after_response.status_code
            except:
                raise
            if after_response_code in [requests.status_codes.codes.OK, requests.status_codes.codes.ACCEPTED]: # HTTP 202
                try:
                    after_resource = json.loads(after_response.text)
                except ValueError as e:
                    eprint('ERROR: failed to load {r} object from PATCH response'.format(r = type))
                    raise(e)
            else:
                json_formatted = json.dumps(patch, indent=2)
                raise Exception(
                    'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s} for PATCH update {:s}'.format(
                        requests.status_codes._codes[after_response_code][0].upper(),
                        after_response_code,
                        after_response.text,
                        json_formatted
                    )
                )
            return(after_resource)
        else:
            return(before_resource)

    def put_resource(self,put):
        """returns a resource
            :put: required dictionary with all properties required by the particular resource's model 
        """
        try:
            headers = {
                "authorization": "Bearer " + self.session.token 
            }
            response = requests.put(
                put['_links']['self']['href'],
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=put
            )
            response_code = response.status_code
        except:
            raise

        if response_code in [requests.status_codes.codes.OK, requests.status_codes.codes.ACCEPTED]: # HTTP 202
            try:
                resource = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from PUT response'.format(r = type))
                raise(e)
        else:
            json_formatted = json.dumps(put, indent=2)
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s} for PUT update {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text,
                    json_formatted
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
            response_code = response.status_code
        except:
            raise
        if response_code == requests.status_codes.codes.OK: # HTTP 200 (synchronous fulfillment)
            try:
                endpoint = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Endpoint"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(endpoint)

    def create_edge_router(self, name, attributes=[], link_listener=False, data_center_id=None):
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
            if data_center_id:
                body['dataCenterId'] = data_center_id
                body['linkListener'] = True
            response = requests.post(
                self.session.audience+'core/v2/edge-routers',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except:
            raise
        if response_code == requests.status_codes.codes[RESOURCES['edge-routers']['expect']]:
            try:
                router = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Edge Router"))
                raise(e)
            else:
#                print('DEBUG: created Edge Router trace ID {:s}'.format(response.headers._store['x-b3-traceid'][1]))
                pass
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
            response_code = response.status_code
        except:
            raise
        if response_code == requests.status_codes.codes[RESOURCES['edge-router-policies']['expect']]:
            try:
                policy = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Edge Router Policy"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(policy)

    def create_service(self, name: str, client_host_name: str, client_port_range: int, server_host_name: str=None, 
        server_port_range: int=None, server_protocol: str="tcp", attributes: list=[], edge_router_attributes: list=["#all"], 
        egress_router_id: str=None, endpoints: list=[], encryption_required: bool=True):
        """create a Service to be accessed by Tunneler Endpoints
        There are three types of servers that may be published with this method: SDK, Tunneler, or Router. 
        If server details are absent then the type is inferred to be SDK (Service is hosted by a Ziti SDK,
        not a Tunneler or Router). If server details are present then the Service is either hosted by a
        Tunneler or Router, depending on which value is present i.e. Tunneler Endpoint or Edge Router. 
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
                "encryptionRequired": encryption_required,
                "model": {
                    "clientIngress" : {
                        "host": client_host_name, 
                        "port": client_port_range,
                    },
                    "edgeRouterAttributes" : edge_router_attributes
                },
                "attributes" : attributes,
            }
            # resolve exit hosting params
            if not server_host_name:
                body['modelType'] = "TunnelerToSdk"
                if server_port_range:
                    eprint("WARN: ignoring unexpected server details for SDK-hosted Service")
            else:
                server_egress = {
                    "protocol": server_protocol.lower(),
                    "host": server_host_name,
                    "port": server_port_range
                }            
                if endpoints and not egress_router_id:
                    body['modelType'] = "TunnelerToEndpoint"
                    # parse out the elements in the list of endpoints as one of #attribute, UUID, or resolvable Endoint name
                    bind_endpoints = list()
                    for endpoint in endpoints:
                        if endpoint[0:1] == '#':
                            bind_endpoints += [endpoint]
                        else:
                            # strip leading @ if present and re-add later after verifying the named Endpoint exists
                            if endpoint[0:1] == '@':
                                endpoint = endpoint[1:]

                            # if UUIDv4 then resolve to name, else verify the named Endpoint exists 
                            try:
                                UUID(endpoint, version=4) # assigned below under "else" if already a UUID
                            except ValueError:
                                # else assume is a name and resolve to ID
                                try: 
                                    name_lookup = self.get_resources(type="endpoints",name=endpoint)[0]
                                    endpoint_name = name_lookup['name']
                                except Exception as e:
                                    raise Exception('ERROR: Failed to find exactly one hosting Endpoint named "{}". Caught exception: {}'.format(endpoint, e))
                                # append to list after successfully resolving name to ID
                                else: bind_endpoints += ['@'+endpoint_name] 
                            else:
                                try:
                                    name_lookup = self.get_resource(type="endpoint",id=endpoint)
                                    endpoint_name = name_lookup['name']
                                except Exception as e:
                                    raise Exception('ERROR: Failed to find exactly one hosting Endpoint with ID "{}". Caught exception: {}'.format(endpoint, e))
                                else: bind_endpoints += ['@'+endpoint_name] 
                    body['model']['bindEndpointAttributes'] = bind_endpoints
                    body['model']['serverEgress'] = server_egress

                elif egress_router_id and not endpoints:
                    body['modelType'] = "TunnelerToEdgeRouter"
                    # check if UUIDv4
                    try: UUID(egress_router_id, version=4)
                    except ValueError:
                        # else assume is a name and resolve to ID
                        try: 
                            name_lookup = self.get_resources(type="edge-routers",name=egress_router_id)[0]
                            egress_router_id = name_lookup['id'] # clobber the name value with the looked-up UUID
                        except Exception as e:
                            raise Exception('ERROR: Failed to find exactly one egress Router "{}". Caught exception: {}'.format(egress_router_id, e))
                    body['model']['edgeRouterHosts'] = [{
                            "edgeRouterId": egress_router_id,
                            "serverEgress": server_egress,
                        }]
                else:
                    raise Exception('ERROR: invalid Service model: need only one of binding "endpoints" or hosting "egress_router_id" if "server_host_name" is specified')
                
            # resolve Edge Router param
            if edge_router_attributes and not edge_router_attributes == ['#all']:
                eprint("WARN: overriding default Service Edge Router Policy #all for new Service {:s}".format(name))
                body['edgeRouterAttributes'] = edge_router_attributes
            # TODO: remove when legacy Services API is decommissioned in favor of Platform Services API
            # results in HTMLv5-compliant URL param singleton with empty string value like ?beta= to invoke the Platform Services API
            params = {
                "beta": ''
            }

            response = requests.post(
                self.session.audience+'core/v2/services',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except:
            raise
        if response_code == requests.status_codes.codes[RESOURCES['services']['expect']]:
            try:
                service = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Service"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
            response_code = response.status_code
        except:
            raise
        if response_code == requests.status_codes.codes[RESOURCES['app-wans']['expect']]:
            try:
                app_wan = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("AppWAN"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
                self.session.audience+'core/v2/networks',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                networks = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load endpoints object from GET response')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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
                self.session.audience+'core/v2/networks/'+network_id,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                network = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = "network"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(network)

    def wait_for_status(self, expect: str="PROVISIONED", type: str="network", wait: int=300, sleep: int=20, id: str=None, progress: bool=False):
        """continuously poll for the expected status until expiry
        :param expect: the expected status symbol e.g. PROVISIONED
        :param id: the UUID of the entity having a status if entity is not a network
        :param type: optional type of entity e.g. network (default), endpoint, service, edge-router
        :param wait: optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param sleep: SECONDS polling interval
        """

        # use the id of this instance's Network unless another one is specified
        if type == "network" and not id:
            id = self.id

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
        response_code = int()
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
                response_code = entity['response_code']

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
                    entity['response_code']
                )
            )
        else:
            raise Exception(
                'timed out with status {} while waiting for {:s}'.format(
                    status,
                    expect
                )
            )

    def wait_for_statuses(self, expected_statuses: list, type: str="network", wait: int=300, sleep: int=20, id: str=None, progress: bool=False):
        """continuously poll for the expected statuses until expiry
        :param expected_statuses: list of strings as expected status symbol(s) e.g. ["PROVISIONING","PROVISIONED"]
        :param id: the UUID of the entity having a status if entity is not a network
        :param type: optional type of entity e.g. network (default), endpoint, service, edge-router
        :param wait: optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param sleep: SECONDS polling interval
        """

        # use the id of this instance's Network unless another one is specified
        if type == "network" and not id:
            id = self.id

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
                '\twaiting for any status in {} or until {:s}.'.format(
                    expected_statuses,
                    time.ctime(now+wait)
                )
            )

        status = str()
        response_code = int()
        while time.time() < now+wait and not status in expected_statuses:
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
                response_code = entity['response_code']

            if not status in expected_statuses:
                time.sleep(sleep)
        print() # newline terminates progress meter

        if status in expected_statuses:
            return(True)
        elif not status:
            raise Exception(
                'failed to read status while waiting for any status in {}; got {} ({:d})'.format(
                    expected_statuses,
                    entity['http_status'],
                    entity['response_code']
                )
            )
        else:
            raise Exception(
                'timed out with status {} while waiting for any status in {}'.format(
                    status,
                    expected_statuses
                )
            )

    def get_resource_status(self, type: str, id: str):
        """return an object describing an entity's API status or the symbolic HTTP code
        :param type: the type of entity e.g. network, endpoint, service, edge-router, edge-router-policy, posture-check
        :param id: the UUID of the entity having a status if not a network
        """

        try:
            headers = { "authorization": "Bearer " + self.session.token }

            params = dict()
            if not type == "network":
                params["networkId"] = self.id
            elif type == "service": 
                params["beta"] = ''

            entity_url = self.session.audience+'core/v2/'
            if type == 'network':
                entity_url += 'networks/'+self.id
            elif id is None:
                raise Exception("ERROR: entity UUID must be specified if not a network")
            else:
                entity_url += type+'s/'+id
            # TODO: remove "beta" when legacy Services API is decommissioned in favor of Platform Services API
            # results in HTMLv5-compliant URL param singleton with empty string value like ?beta= to invoke the Platform Services API

            response = requests.get(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK:
            try:
                status = json.loads(response.text)['status']
                name = json.loads(response.text)['name']
            except:
                eprint('ERROR parsing entity object in response')
                raise
            else:
                return {
                    'http_status': requests.status_codes._codes[response_code][0].upper(),
                    'response_code': response_code,
                    'status': status,
                    'name': name
                }
        else:
            return {
                'http_status': requests.status_codes._codes[response_code][0].upper(),
                'response_code': response_code
            }

    def get_resource(self, type: str, id: str):
        """return an object describing an entity
        :param type: the type of entity e.g. network, endpoint, service, edge-router, edge-router-policy, posture-check
        :param id: the UUID of the entity if not a network
        """

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/'+type+'s/'+id
            # TODO: remove "beta" when legacy Services API is decommissioned in favor of Platform Services API
            # results in HTMLv5-compliant URL param singleton with empty string value like ?beta= to invoke the Platform Services API
            params = dict()
            if not type == "network":
                params["networkId"] = self.id
            if type == "service": 
                params["beta"] = ''

            response = requests.get(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK:
            try:
                entity = json.loads(response.text)
            except:
                raise Exception('ERROR parsing response as object, got:\n{}'.format(response.text))
            else:
                return(entity)

    def get_edge_router_registration(self, id: str):
        """return the registration key and expiration as a dict
        :param id: the UUID of the edge router
        """

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/edge-routers/'+id+'/registration-key'
            response = requests.post(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK:
            try:
                registration_object = json.loads(response.text)
            except:
                raise Exception('ERROR parsing response as object, got:\n{}'.format(response.text))
            else:
                return(registration_object)

    def delete_resource(self, type, id=None, wait=int(0), progress=False):
        """
        delete a resource
        :param type: required entity type to delete i.e. network, endpoint, service, edge-router
        :param id: required entity UUID to delete
        :param wait: optional seconds to wait for entity destruction
        """
#        import epdb; epdb.serve()
        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/networks/'+self.id
            expected_responses = [
                requests.status_codes.codes.ACCEPTED,
                requests.status_codes.codes.OK
            ]
            if not type == 'network':
                if id is None:
                    raise Exception("ERROR: need entity UUID to delete")
                entity_url = self.session.audience+'core/v2/'+type+'s/'+id
            eprint("WARN: deleting {:s}".format(entity_url))
            # TODO: remove "beta" when legacy Services API is decommissioned in favor of Platform Services API
            # results in HTMLv5-compliant URL param singleton with empty string value like ?beta= to invoke the Platform Services API
            params = dict()
            if type == "service":
                params["beta"] = ''

            response = requests.delete(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if not response_code in expected_responses:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
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

class Utility:
    def __init__(self):
        pass

    def camel(self, snake_str):
        first, *others = snake_str.split('_')
        return ''.join([first.lower(), *map(str.title, others)])

    def snake(self, camel_str):
        return sub(r'(?<!^)(?=[A-Z])', '_', camel_str).lower()

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
        'expect': "ACCEPTED"
    },
    'posture-checks': {
        'embedded': "postureCheckList",
        'expect': "ACCEPTED"
    }
}

# TODO: [MOP-13441] associate locations with a short list of major geographic regions / continents
major_regions = {
    "AWS" : {
        "Americas": ("Canada Central","N. California","N. Virginia","Ohio","Oregon","Sao Paulo"),
        "EuropeMiddleEastAfrica": ("Bahrain","Cape Town South Africa","Frankfurt","Ireland","London","Milan","Paris","Stockholm"),
        "AsiaPacific": ("Hong Kong","Mumbai","Seoul","Singapore","Sydney","Tokyo")
    }
}

