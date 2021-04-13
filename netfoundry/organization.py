import os
import json                 # 
import requests             # HTTP user agent will not emit server cert warnings if verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re                   # regex
import time                 # enforce a timeout; sleep
import jwt                  # decode the JWT claimset
from pathlib import Path    #

from .utility import RESOURCES, eprint

class Organization:
    """ Default is to use the Organization of the caller's user or API account identity
    :param: organization_id is optional string UUID of an alternative Organization
    :param: organization_label is optional string `label` property of an alternative Organization
    :param token: continue using a session with this optional token from an existing instance of Organization
    :param credentials: optional alternative path to API account credentials file, default is ~/.netfoundry/credentials.json
    :param proxy: optional HTTP proxy, e.g., http://localhost:8080
    """

    def __init__(self, 
        credentials=None, 
        organization_id: str=None, 
        organization_label: str=None,
        token=None, 
        proxy=None):

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

        # if no token or near expiry (30 min) then use credentials to obtain a token
        if epoch is None or epoch > (expiry - 600):
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
            self.audience = 'https://gateway.'+self.environment+'.netfoundry.io/'
        except: raise

        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.network_groups = self.get_network_groups_by_organization()
        # Obtain a session token and find own `.caller` identity and `.organizations`
        self.caller = self.get_caller_identity()
        if organization_id:
            self.describe = self.get_organization(id=organization_id)
        elif organization_label:
            self.organizations_by_label = dict()
            for org in self.get_organizations():
                self.organizations_by_label[org['label']] = org['id']
            self.describe = self.get_organization(id=self.organizations_by_label[organization_label])
        else:
            self.describe = self.get_organization(id=self.caller['organizationId'])

        self.label = self.describe['label']
        self.id = self.describe['id']

        self.network_groups_by_name = dict()
        for group in self.network_groups:
            self.network_groups_by_name[group['name']] = group['id']

    def network_groups(self):
        return(self.get_network_groups_by_organization())
        
    def get_caller_identity(self):
        """return the caller's identity object
        """
        # try the API account endpoint first, then the endpoint for human, interactive users
        request = {
            "url": self.audience+'identity/v1/api-account-identities/self',
            "proxies": self.proxies,
            "verify": self.verify,
            "headers": { "authorization": "Bearer " + self.token }
        }
        try:
            response = requests.get(**request)
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                caller = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting caller\'s API account identity from response document')
                raise(e)
        else:
            try:
                request["url"] = self.audience+'identity/v1/user-identities/self'
                response = requests.get(**request)
                response_code = response.status_code
            except:
                raise

            if response_code == requests.status_codes.codes.OK: # HTTP 200
                try:
                    caller = json.loads(response.text)
                except ValueError as e:
                    eprint('ERROR getting caller\'s user identity from response document')
                    raise(e)
            else:
                raise Exception(
                    'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                        requests.status_codes._codes[response_code][0].upper(),
                        response_code,
                        response.text
                    )
                )

        return(caller)

    def get_organizations(self):
        """return the list of Organizations (formerly "tenants")
        """
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'identity/v1/organizations',
                proxies=self.proxies,
                verify=self.verify,
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

        return(organizations)

    def get_organization(self, id):
        """return a single Organizations by ID
        """
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'identity/v1/organizations/'+id,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                organization = json.loads(response.text)
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

        return(organization)

    def get_network_group(self,network_group_id):
        """describe a Network Group
        """
        try:
            # /network-groups/{id} returns a Network Group object
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'rest/v1/network-groups/'+network_group_id,
                proxies=self.proxies,
                verify=self.verify,
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
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'rest/v1/networks/'+network_id,
                proxies=self.proxies,
                verify=self.verify,
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
        TODO: filter by Organization when that capability is available
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
            headers = { "authorization": "Bearer " + self.token }
            response = requests.get(
                self.audience+'core/v2/networks',
                proxies=self.proxies,
                verify=self.verify,
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
                "authorization": "Bearer " + self.token 
            }
            params = {
                "findByNetworkGroupId": network_group_id
            }
            response = requests.get(
                self.audience+'core/v2/networks',
                proxies=self.proxies,
                verify=self.verify,
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
