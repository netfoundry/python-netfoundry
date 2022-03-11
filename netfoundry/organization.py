"""Use an identity organization and find authorized network groups and networks."""

import json
import logging
import os
import re  # regex
import stat
import time  # enforce a timeout; sleep
from pathlib import Path

from platformdirs import user_cache_path, user_config_path

from .exceptions import NFAPINoCredentials
from .utility import (MUTABLE_NETWORK_RESOURCES, NETWORK_RESOURCES,
                      RESOURCES, STATUS_CODES, Utility, eprint, http,
                      is_uuidv4)

utility = Utility()


class Organization:
    """Authenticate as an identity ID in an organization.
    
    The default is to use the calling identity's organization. 

    :param str organization: optional identifier of an alternative organization, ignored if organization_id or organization_label
    :param str profile: login profile name for storing and retrieving separate concurrent sessions
    :param str organization_id: optional UUID of an alternative organization
    :param str organization_label: is optional `label` property of an alternative organization
    :param str token: continue using a session with this optional token from an existing instance of organization
    :param str credentials: optional alternative path to API account credentials file, default is project, user, or device default directories containing file name credentials.json
    :param int expiry_minimum: renew if possible else reject token with error if expires in < N seconds, ignore if N=0
    :param str proxy: optional HTTP proxy, e.g., http://localhost:8080
    """

    def __init__(self, 
        credentials: str=None,
        organization: str=None, 
        organization_id: str=None, 
        organization_label: str=None,
        profile: str="default",
        token: str=None,
        authorization: dict=dict(),
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
        self.expiry_seconds = 0
        client_id = None
        password = None
        token_endpoint = None
        credentials_configured = False

        if profile is None:
            profile = "default"
        self.profile = profile

        cache_dir_path = user_cache_path(appname='netfoundry')
        token_cache_file_name = self.profile+'.jwt'
        config_dir_path = user_config_path(appname='netfoundry')

        try:
            # create and correct mode to 0o700
            cache_dir_path.mkdir(mode=stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR, parents=True, exist_ok=True)
            cache_dir_path.chmod(mode=stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
        except:
            logging.error("failed to create cache dir '%s'", cache_dir_path.__str__())
            raise
        else:
            cache_dir_stats = os.stat(cache_dir_path)
            logging.debug("token cache dir exists with mode %s", stat.filemode(cache_dir_stats.st_mode))
        self.token_cache_file_path = Path(cache_dir_path / token_cache_file_name)
        logging.debug("cache file path is computed '%s'", self.token_cache_file_path.__str__())

        # if not token then use standard env var if defined
        if token is not None:
            self.token = token
            logging.debug("got token as param to Organization")
        elif 'NETFOUNDRY_API_TOKEN' in os.environ:
            self.token = os.environ['NETFOUNDRY_API_TOKEN']
            logging.debug("got token from env NETFOUNDRY_API_TOKEN")
        else:
            try:
                self.token = self.token_cache_file_path.read_text()
            except FileNotFoundError as e:
                logging.debug("cache file '%s' not found", self.token_cache_file_path.__str__())
                self.token = None
            except Exception as e:
                logging.debug("failed to read cache file '%s', got %s", self.token_cache_file_path.__str__(), e)
            else:
                cache_file_stats = os.stat(self.token_cache_file_path)
                logging.debug("read token as %dB from cache file '%s' with mode %s", len(self.token), self.token_cache_file_path.__str__(), stat.filemode(cache_file_stats.st_mode))


        # if the token was found then extract the expiry
        if self.token:
            try:
                claim = utility.jwt_decode(self.token)
            except:
                raise
            else:
                self.expiry = claim['exp']
                epoch = time.time()
                self.expiry_seconds = self.expiry - epoch
        else:
            logging.debug("no bearer token found in param, env, or cache")

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
            # if valid relative or absolute path to creds file, else search the default dirs
            if os.path.exists(self.credentials):
                logging.debug("found credentials file '%s'", self.credentials)
            else:
                default_creds_scopes = [
                    {
                        "scope": "project",
                        "path": Path.cwd()
                    },
                    {
                        "scope": "user",
                        "path": Path.home() / ".netfoundry"
                    },
                    {
                        "scope": "device",
                        "path": Path("/netfoundry")
                    },
                    {
                        "scope": "site",
                        "path": config_dir_path
                    },
                ]
                for scope in default_creds_scopes:
                    candidate = scope['path'] / self.credentials
                    if candidate.exists():
                        logging.debug("found credentials file %s in %s-default directory",
                            candidate.__str__(),
                            scope['scope'],
                        )
                        self.credentials = candidate.__str__()
                        break
                    else:
                        logging.debug("no credentials file %s in %s-default directory",
                            candidate.__str__(),
                            scope['scope'],
                        )

            try: 
                file = open(self.credentials, 'r')
            except FileNotFoundError:
                logging.debug("failed to open credentials file '%s' for reading", self.credentials)
                pass # this means we can't renew the token, but it's not fatal
            else:
                account = json.load(file)
                token_endpoint = account['authenticationUrl']
                client_id = account['clientId']
                password = account['password']
                credentials_configured = True
                logging.debug("configured credentials from file '%s'", self.credentials)

        if not credentials_configured:
            logging.debug("token renewal is disabled because API account credentials are not configured")

        # renew token if not existing or imminent expiry, else continue
        if not self.token or self.expiry_seconds < expiry_minimum:
            if self.token and self.expiry_seconds < expiry_minimum:
                logging.debug("token expiry %ds is less than configured minimum %ds", self.expiry_seconds, expiry_minimum)
            if not credentials_configured:
                logging.debug("credentials needed to renew token")
                raise NFAPINoCredentials("credentials needed to renew token")
            else:
                logging.debug("renewing token")

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
                    self.expiry = token_text['expires_in']
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
            claim = utility.jwt_decode(self.token)
            iss = claim['iss']
            if re.match(r'https://cognito-', iss):
                self.environment = re.sub(r'https://gateway\.([^.]+)\.netfoundry\.io.*',r'\1',claim['scope'])
            elif re.match(r'.*\.auth0\.com', iss):
                self.environment = re.sub(r'https://netfoundry-([^.]+)\.auth0\.com.*',r'\1',claim['iss'])
            self.audience = 'https://gateway.'+self.environment+'.netfoundry.io/'
            self.expiry = claim['exp']
            epoch = time.time()
            self.expiry_seconds = self.expiry - epoch
            logging.debug("bearer token expiry in %ds", self.expiry_seconds)
        except: raise

        try:
            # set file mode 0o600 at creation
            self.token_cache_file_path.touch(mode=stat.S_IRUSR|stat.S_IWUSR)
            self.token_cache_file_path.write_text(self.token)
        except:
            logging.warn("failed to cache token in '%s'", self.token_cache_file_path.__str__())
            import epdb; epdb.serve()
        else:
            logging.debug("cached token in '%s'", self.token_cache_file_path.__str__())

        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.network_groups = self.get_network_groups_by_organization()
        # Obtain a session token and find own `.caller` identity and `.organizations`
        self.caller = self.get_caller_identity()

        if (not organization_id and not organization_label) and organization:
            if is_uuidv4(organization):
                organization_id = organization
            else:
                organization_label = organization

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
        self.name = self.describe['name']
        self.id = self.describe['id']

        self.network_groups_by_name = dict()
        for group in self.network_groups:
            self.network_groups_by_name[group['name']] = group['id']

    # END init

    def logout(self):
        """Logout from NF organization by removing the cached token file."""
        if os.path.exists(self.token_cache_file_path):
            try:
                os.remove(self.token_cache_file_path)
            except Exception as e:
                logging.error("failed to remove cached token file '%s'", self.token_cache_file_path.__str__())
                return False
            else:
                return True
        else:
            logging.debug("cached token file '%s' does not exist", self.token_cache_file_path.__str__())
            return True
        
    def get_caller_identity(self):
        """Return the caller's identity object."""
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
                eprint('failed loading caller\'s API account identity as an object from response document')
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

    def get_identity(self, identity_id: str):
        """Get an identity by ID.

        :param str identity: UUIDv4 of the identity to get
        """
        params = dict()
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = http.get(
                self.audience+'identity/v1/identities/'+identity_id,
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
                identity = response.json()
            except ValueError as e:
                logging.error('failed loading identities as an object from response document')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(identity)

    def get_identities(self, **kwargs):
        """Find identities.

        :param str kwargs: filter results by logical AND query parameters
        """
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = http.get(
                self.audience+'identity/v1/identities',
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
                identities = response.json()
            except ValueError as e:
                logging.error('failed loading identities as an object from response document')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return(identities)

    def get_organizations(self, **kwargs):
        """Find organizations.

        :param str kwargs: filter results by logical AND query parameters
        """
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        try:
            headers = { "authorization": "Bearer " + self.token }
            response = http.get(
                self.audience+'identity/v1/organizations',
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

    def get_network(self, network_id: str, embed: str=None, accept: str=None):
        """Describe a Network by ID.
        
        :param str network_id: UUIDv4 of the network to get
        :param str embed: magic 'all' embeds all resource types in network domain, else comma-separated list of resource types to embed in response e.g. 'endpoints,services'
        :param str accept: specifying the form of the desired response. Choices ["create","update"] where
                "create" is useful for comparing an existing entity to a set of properties that are used to create the same type of
                entity in a POST request, and "update" may be used in the same way for a PUT update.
        """
        headers = dict()
        if accept:
            if not accept in ["update","create"]:
                logging.error("param 'accept' must be one of 'update' or 'create', got '{:s}'".format(accept))
                raise Exception("param 'accept' must be one of 'update' or 'create', got '{:s}'".format(accept))
            else:
                headers['accept'] = "application/json;as="+accept
        headers["authorization"] = "Bearer " + self.token
        params = dict()
        if embed == "all":
            params['embed'] = ','.join(MUTABLE_NETWORK_RESOURCES)
            logging.debug("requesting embed all resource types in network domain: {:s}".format(params['embed']))
        elif embed:
            params['embed'] = ','.join([type for type in embed.split(',') if RESOURCES[type]['domain'] == "network"])
            logging.debug("requesting embed some resource types in network domain: {:s}".format(params['embed']))
            for type in embed.split(','):
                if not type in NETWORK_RESOURCES.keys():
                    logging.debug("not requesting embed of resource type '{:s}' because not a valid resource type or not in network domain".format(type))
        try:
            response = http.get(
                self.audience+'core/v2/networks/'+network_id,
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
                network = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = "network"))
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


    def get_network_groups_by_organization(self, **kwargs):
        """Find network groups.

        :param str kwargs: filter results by any supported query param
        """
        params = {
            'size': 1000,
            'page': 0
        }
        for param in kwargs.keys():
            params[param] = kwargs[param]            
        try:
            # /network-groups returns a list of dicts (Network Group objects)
            headers = { "authorization": "Bearer " + self.token }
            response = http.get(
                self.audience+'rest/v1/network-groups',
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
                response_object = response.json()
            except ValueError:
                logging.error('failed loading list of network groups as object')
                raise ValueError("response is not JSON")
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        total_pages = response_object['page']['totalPages']
        total_elements = response_object['page']['totalElements']
        # if there are no resources
        if total_elements == 0:
            return([])
        else:
            network_groups = response_object['_embedded'][RESOURCES['network-groups']._embedded]

        # if there is one page of resources
        if total_pages == 1:
            return network_groups
        # if there are multiple pages of resources
        else:
            # append the remaining pages of resources
            for page in range(1,total_pages+1): # +1 to work around 1-base bug in MOP-17890
                try:
                    params["page"] = page
                    response = http.get(
                        self.audience+'rest/v1/network-groups',
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
                        response_object = response.json()
                        network_groups.extend(response_object['_embedded'][RESOURCES['network-groups']._embedded])
                    except ValueError:
                        logging.error('failed loading list of network groups as object')
                        raise ValueError("response is not JSON")
                else:
                    raise Exception(
                        'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                            STATUS_CODES._codes[response_code][0].upper(),
                            response_code,
                            response.text
                        )
                    )

        return(network_groups)

    network_groups = get_network_groups_by_organization

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
            all_entities = resources['_embedded'][RESOURCES['networks']._embedded]
        # if there are multiple pages of resources
        else:
            # initialize the list with the first page of resources
            all_entities = resources['_embedded'][RESOURCES['networks']._embedded]
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
                        all_entities.extend(resources['_embedded'][RESOURCES['networks']._embedded])
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

    def network_exists(self, name: str, deleted: bool=False):
        """Check if a network exists.
        
        :param name: the case-insensitive string to search
        :param deleted: include deleted networks in results
        """
        if self.count_networks_with_name(name=name, deleted=deleted) > 0:
            return(True)
        else:
            return(False)

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

    def get_networks_by_group(self,network_group_id: str, deleted: bool=False, **kwargs):
        """Find networks by network group ID.

        :param network_group_id: required network group UUIDv4
        :param str kwargs: filter results by logical AND query parameters
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.token 
            }
            params = {
                "findByNetworkGroupId": network_group_id
            }
            for param in kwargs.keys():
                params[param] = kwargs[param]
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
                embedded = response.json()
            except ValueError:
                logging.error("response is not JSON")
                raise ValueError("response is not JSON")
            try:
                networks = embedded['_embedded'][RESOURCES['networks']._embedded]
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
