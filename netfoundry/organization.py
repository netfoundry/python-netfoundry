"""Use an identity organization and find authorized network groups and networks."""

import json
import logging
import os
import re  # regex
import time  # enforce a timeout; sleep
from pathlib import Path

import jwt  # decode the JWT claimset

from .utility import RESOURCES, STATUS_CODES, Utility, eprint, http

utility = Utility()


class Organization:
    """Authenticate as an identity ID in an organization.
    
    The default is to use the calling identity's organization. 

    :param str organization_id: optional UUID of an alternative organization
    :param str organization_label: is optional `label` property of an alternative organization
    :param str token: continue using a session with this optional token from an existing instance of organization
    :param str credentials: optional alternative path to API account credentials file, default is project, user, or device default directories containing file name credentials.json
    :param int expiry_minimum: renew if possible else reject token with error if expires in < N seconds, ignore if N=0
    :param str proxy: optional HTTP proxy, e.g., http://localhost:8080
    """

    def __init__(self, 
        credentials=None, 
        organization_id: str=None, 
        organization_label: str=None,
        token: str=None,
        expiry_minimum: int=600,
        proxy: str=None):
        """Initialize an instance of organization."""
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
        
        epoch = None
        expiry_offset = 0
        client_id = None
        password = None
        token_endpoint = None
        credentials_configured = False

        # if not token then use standard env var if defined
        if token is not None:
            self.token = token
        elif 'NETFOUNDRY_API_TOKEN' in os.environ:
            self.token = os.environ['NETFOUNDRY_API_TOKEN']
        else:
            self.token = None

        # if the token was found then extract the expiry
        if self.token:
            try:
                claim = jwt.decode(jwt=self.token, algorithms=["RS256"], options={"verify_signature": False})
            except jwt.exceptions.PyJWTError:
                logging.error("failed to parse bearer token as JWT")
                raise
            else:
                expiry = claim['exp']
                epoch = time.time()
                expiry_offset = expiry - epoch
                logging.debug("bearer token expiry in %ds", expiry_offset)
        else:
            logging.debug("no bearer token found in param or env")

        # find credentials from param or env so we can renew the token later
        if credentials is not None:
            self.credentials = credentials
            os.environ['NETFOUNDRY_API_ACCOUNT'] = self.credentials
            logging.debug("got param credentials=%s", self.credentials)
        elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
            self.credentials = os.environ['NETFOUNDRY_API_ACCOUNT']
            logging.debug("got path to credentials file from env NETFOUNDRY_API_ACCOUNT=%s", self.credentials)
        # if any credentials var then require all credentials vars
        elif ('NETFOUNDRY_CLIENT_ID' in os.environ
                    or 'NETFOUNDRY_PASSWORD' in os.environ
                    or 'NETFOUNDRY_OAUTH_URL' in os.environ):
            if ('NETFOUNDRY_CLIENT_ID' in os.environ 
                    and 'NETFOUNDRY_PASSWORD' in os.environ 
                    and 'NETFOUNDRY_OAUTH_URL' in os.environ):
                client_id = os.environ['NETFOUNDRY_CLIENT_ID']
                password = os.environ['NETFOUNDRY_PASSWORD']
                token_endpoint = os.environ['NETFOUNDRY_OAUTH_URL']
                credentials_configured = True
                logging.debug("configured API account credentials from env NETFOUNDRY_CLIENT_ID, NETFOUNDRY_PASSWORD, NETFOUNDRY_OAUTH_URL")
            else:
                logging.error("some but not all credentials vars present. Need NETFOUNDRY_CLIENT_ID, NETFOUNDRY_PASSWORD, and NETFOUNDRY_OAUTH_URL or a credentials file in default file locations or NETFOUNDRY_API_ACCOUNT as path to credentials file.")
                raise Exception()
        else:
            self.credentials = "credentials.json"
            logging.debug("token renewal will look for default credentials file name 'credentials.json' in project (cwd), user, and device default paths")

        # continue if we already found the credentials in env
        if not credentials_configured:
            logging.debug("searching for credentials file %s", self.credentials)
            # continue if valid path to creds file, else search the default dirs
            if not os.path.exists(self.credentials):
                default_creds_dirs = [
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
                for link in default_creds_dirs:
                    candidate = link['base']+"/"+self.credentials
                    if os.path.exists(candidate):
                        logging.debug("found credentials file %s in %s-default directory",
                            candidate,
                            link['scope'],
                        )
                        self.credentials = candidate
                        break
            else:
                logging.info("using credentials in %s", self.credentials)

            try: 
                file = open(self.credentials)
            except FileNotFoundError: 
                pass # this means we can't renew the token, but it's not fatal
            else:
                account = json.load(file)
                token_endpoint = account['authenticationUrl']
                client_id = account['clientId']
                password = account['password']
                credentials_configured = True

        else:
            logging.debug("credentials are configured %s", str(credentials_configured))

        if not credentials_configured:
            logging.warning("token renewal is disabled without API account credentials")

        # renew token if not existing or imminent expiry, else continue
        if not self.token or expiry_offset < expiry_minimum:
            if not credentials_configured:
                logging.exception("credentials needed to renew expired or imminently-expiring token")
                raise Exception()

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
                response = http.post(
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

            if response_code == STATUS_CODES.codes.OK:
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
                        STATUS_CODES._codes[response_code][0].upper(),
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
            if organization_label in self.organizations_by_label.keys():
                self.describe = self.get_organization(id=self.organizations_by_label[organization_label])
            else:
                raise Exception(
                    'ERROR: failed to find org label {:s} in the list of orgs {:s}'.format(
                        organization_label,
                        str(self.organizations_by_label.keys())
                    )
                )

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
            response = http.get(**request)
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                caller = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting caller\'s API account identity from response document')
                raise(e)
        else:
            try:
                request["url"] = self.audience+'identity/v1/user-identities/self'
                response = http.get(**request)
                response_code = response.status_code
            except:
                raise

            if response_code == STATUS_CODES.codes.OK: # HTTP 200
                try:
                    caller = json.loads(response.text)
                except ValueError as e:
                    eprint('ERROR getting caller\'s user identity from response document')
                    raise(e)
            else:
                raise Exception(
                    'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                        STATUS_CODES._codes[response_code][0].upper(),
                        response_code,
                        response.text
                    )
                )

        return(caller)

    def get_organizations(self):
        """return the list of organizations
        """
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = http.get(
                self.audience+'identity/v1/organizations',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                organizations = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Groups')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(organizations)

    def get_organization(self, id):
        """return a single organizations by ID
        """
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = http.get(
                self.audience+'identity/v1/organizations/'+id,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                organization = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Groups')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
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
            response = http.get(
                self.audience+'rest/v1/network-groups/'+network_group_id,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                network_group = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Group')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
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
            response = http.get(
                self.audience+'rest/v1/networks/'+network_id,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                network = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting Network Group')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(network)

    def get_network_groups_by_organization(self):
        """list Network Groups
        TODO: filter by organization when that capability is available
        """
        try:
            # /network-groups returns a list of dicts (Network Group objects)
            headers = { "authorization": "Bearer " + self.token }
            response = http.get(
                self.audience+'rest/v1/network-groups',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                network_groups = json.loads(response.text)['_embedded']['organizations']
            except ValueError as e:
                logging.error('failed loading list of network groups as object')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(network_groups)

    def get_networks_by_organization(self, name: str=None, deleted: bool=False, **kwargs):
        """Find networks known to this organization.

        :param str name: filter results by name
        :param str kwargs: filter results by any supported query param
        :param bool deleted: include resource entities that have a non-null property deletedAt
        """
        try:
            headers = { "authorization": "Bearer " + self.token }

            params = {
                "page": 0,
                "size": 100,
                "sort": "name,asc"
            }

            for param in kwargs.keys():
                params[param] = kwargs[param]            
            if name is not None:
                params['findByName'] = name
            if deleted:
                params['status'] = "DELETED"

            response = http.get(
                self.audience+'core/v2/networks',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                resources = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = type))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
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
            all_entities = resources['_embedded'][RESOURCES['networks']['embedded']]
        # if there are multiple pages of resources
        else:
            # initialize the list with the first page of resources
            all_entities = resources['_embedded'][RESOURCES['networks']['embedded']]
            # append the remaining pages of resources
            for page in range(1,total_pages):
                try:
                    params["page"] = page
                    response = http.get(
                        self.audience+'core/v2/networks',
                        proxies=self.proxies,
                        verify=self.verify,
                        headers=headers,
                        params=params
                    )
                    response_code = response.status_code
                except:
                    raise

                if response_code == STATUS_CODES.codes.OK: # HTTP 200
                    try:
                        resources = json.loads(response.text)
                        all_entities.extend(resources['_embedded'][RESOURCES['networks']['embedded']])
                    except ValueError as e:
                        eprint('ERROR: failed to load resources object from GET response')
                        raise(e)
                else:
                    raise Exception(
                        'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                            STATUS_CODES._codes[response_code][0].upper(),
                            response_code,
                            response.text
                        )
                    )

        return(all_entities)

    def count_networks_with_name(self, name: str, deleted: bool=False, unique: bool=True):
        """
        Count the networks with a particular name for this organization.

        We can use this to determine whether a network group is needed to
        filter a particular network. This is more useful than a true/false
        existence check because network names are not unique for an
        organization.  
        
        :param str name: the case-insensitive name to search
        :param bool deleted: search deleted networks
        :param bool unique: raise an exception if the name is not unique
        """
        normal_names = list()
        for normal in self.get_networks_by_organization(name=name, deleted=deleted):
            normal_names.append(utility.normalize_caseless(normal['name']))

        return normal_names.count(utility.normalize_caseless(name))

    def get_networks_by_group(self,network_group_id: str, deleted: bool=False):
        """Find networks by network group ID.

        :param network_group_id: required network group UUIDv4
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.token 
            }
            params = {
                "findByNetworkGroupId": network_group_id
            }
            if deleted:
                params['status'] = "DELETED"
            response = http.get(
                self.audience+'core/v2/networks',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                embedded = response.json
            except ValueError:
                logging.error("response is not JSON")
                raise ValueError("response is not JSON")
            logging.debug(str(embedded))
            try:
                networks = embedded['_embedded'][RESOURCES['networks']['embedded']]
            except KeyError:
                networks = list()
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(networks)
