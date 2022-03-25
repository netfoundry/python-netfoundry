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
from .utility import (DEFAULT_TOKEN_EXPIRY, ENVIRONMENTS,
                      MUTABLE_NETWORK_RESOURCES, NETWORK_RESOURCES, RESOURCES,
                      STATUS_CODES, find_resources, get_resource, http,
                      is_uuidv4, normalize_caseless, get_token_cache, jwt_decode, jwt_environment, jwt_expiry)


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
    :param str environment: base name of Gateway Service audience URL e.g. "production" may be configured here because token issuer URL and claimset schema are unpredictable
    :param str proxy: optional HTTP proxy, e.g., http://localhost:8080
    """

    def __init__(self, 
        credentials: str=None,
        organization: str=None, 
        organization_id: str=None, 
        organization_label: str=None,
        profile: str="default",
        token: str=None,
        expiry_minimum: int=600,
        environment: str=None,
        logout: bool=False,
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
        
        epoch = time.time()
        self.expiry_seconds = 0 # initialize a placeholder for remaining seconds until expiry
        client_id = None
        password = None
        token_endpoint = None
        credentials_configured = False

        if profile is None:
            profile = "default"
        self.profile = profile
        if environment is None:
            self.environment = None
        else:
            self.environment = environment

        # the token_cache dict is the schema for the file that persists what we think we know about the session
        token_cache = {
            'token': None,
            'expiry': None,
            'audience': None
        }
        cache_dir_path = user_cache_path(appname='netfoundry')
        token_cache_file_name = self.profile+'.json'
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

        # short circuit if logout only
        if logout:
            try:
                self.logout()
            except Exception as e:
                logging.error("unexpected error while logging out: %s", e)
            else:
                return None

        # if not token then use standard env var if defined, else look for cached token in file
        if token is not None:
            self.token = token
            self.expiry = None
            self.audience = None
            logging.debug("got token as param to Organization")
        elif 'NETFOUNDRY_API_TOKEN' in os.environ:
            self.token = os.environ['NETFOUNDRY_API_TOKEN']
            self.expiry = None
            self.audience = None
            logging.debug("got token from env NETFOUNDRY_API_TOKEN as %dB", len(self.token))
        else:
            try:
                token_cache = get_token_cache(self.token_cache_file_path)
            except Exception as e:
                self.token = None
                self.expiry = None
                self.audience = None
            else:
                self.token = token_cache['token']
                self.expiry = token_cache['expiry']
                self.expiry_seconds = self.expiry - epoch
                self.audience = token_cache['audience']

        # if the token was found but not the expiry then try to parse to extract the expiry so we can enforce minimum lifespan seconds
        if self.token and not self.expiry:
            try:
                self.expiry = jwt_expiry(self.token)
            except:
                self.expiry = epoch + DEFAULT_TOKEN_EXPIRY
                self.expiry_seconds = DEFAULT_TOKEN_EXPIRY
                logging.debug("failed to parse token as JWT, estimating expiry in %ds", DEFAULT_TOKEN_EXPIRY)
            else:
                self.expiry_seconds = self.expiry - epoch
                logging.debug("bearer token expiry in %ds", self.expiry_seconds)
        elif not self.token:
            logging.debug("no bearer token found")

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
                logging.debug("credentials file '%s' does not exist", self.credentials)
                # this means we can't renew the token, but it's not fatal
            else:
                account = json.load(file)
                token_endpoint = account['authenticationUrl']
                client_id = account['clientId']
                password = account['password']
                credentials_configured = True
                logging.debug("configured credentials from file '%s'", self.credentials)

        if not credentials_configured:
            logging.debug("token renewal impossible because API account credentials are not configured")

        # The purpose of this flow is to compose the audience URL. The mode of
        # the try-except block is to soft-fail all attempts to parse the JWT,
        # which is intended for the API, not this application
        if not self.audience and self.token and not self.environment:
            try:
                self.environment = jwt_environment(self.token)
            except:
                # an exception here is very unlikely because the called
                # function is designed to provide a sane default in case the
                # token can't be parsed
                logging.debug("unexpected error extracting environment from JWT")
                raise
            else:
                logging.debug("parsed token as JWT and found environment %s", self.environment)
            finally:
                if not self.environment in ENVIRONMENTS:
                    logging.warn("unexpected environment '%s'", self.environment)

        if self.environment and not self.audience:
            self.audience = 'https://gateway.{env}.netfoundry.io/'.format(env=self.environment)

        if self.environment and self.audience:
            if not re.search(self.environment, self.audience):
                logging.error("mismatched audience URL '%s' and environment '%s'", self.audience, self.environment)
                exit(1)

        # the purpose of this try-except block is to soft-fail all attempts
        # to parse the JWT, which is intended for the API, not this
        # application
        if self.token and not self.expiry: # if token was obtained in this pass then expiry is already defined by response 'expires_in' property 
            try:
                self.expiry = jwt_expiry(self.token)
            except:
                logging.debug("unexpected error getting expiry from token")
                raise
            else:
                self.expiry_seconds = self.expiry - epoch
                logging.debug("bearer token expiry in %ds", self.expiry_seconds)

        # renew token if not existing or imminent expiry, else continue
        if not self.token or self.expiry_seconds < expiry_minimum:
            # we've already done the work to determine the cached token is expired or imminently-expiring, might as well save other runs the same trouble
            self.logout()
            self.expiry = None
            self.audience = None
            if self.token and self.expiry_seconds < expiry_minimum:
                logging.debug("token expiry %ds is less than configured minimum %ds", self.expiry_seconds, expiry_minimum)
            if not credentials_configured:
                logging.debug("credentials needed to renew token")
                raise NFAPINoCredentials("credentials needed to renew token")
            else:
                logging.debug("renewing token with credentials")

            # extract the environment name from the authorization URL aka token API endpoint
            if self.environment is None:
                self.environment = re.sub(r'https://netfoundry-([^-]+)-.*', r'\1', token_endpoint, re.IGNORECASE)
                logging.debug("using environment parsed from token_endpoint URL %s", self.environment)
            # re: scope: we're not using scopes with Cognito, but a non-empty value is required;
            #  hence "/ignore-scope"
            scope = "https://gateway."+self.environment+".netfoundry.io//ignore-scope"
            # we can gather the URL of the API from the first part of the scope string by
            #  dropping the scope suffix
            self.audience = scope.replace('/ignore-scope','')
            logging.debug("using audience parsed from token_endpoint URL %s", self.audience)
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
                logging.error('failed to contact the authentication endpoint: {}'.format(token_endpoint))
                raise

            if response_code == STATUS_CODES.codes.OK:
                try:
                    token_text = json.loads(response.text)
                    self.token = token_text['access_token']
                    self.expiry = token_text['expires_in'] + epoch
                except:
                    raise Exception(
                        'ERROR: failed to find an access_token in the response and instead got: {}'.format(
                            response.text
                        )
                    )
                else:
                    self.expiry_seconds = self.expiry - epoch
                    logging.debug("bearer token expiry in %ds", self.expiry_seconds)
            else:
                raise Exception(
                    'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                        STATUS_CODES._codes[response_code][0].upper(),
                        response_code,
                        response.text
                    )
                )
        else:
            logging.debug("found token with %ss until expiry", self.expiry_seconds)

        # write to the token cache if we have all three things: the token,
        # expiry, and audience URL, unless it matches the token cache, which
        # would mean we would be needlessly writing the same token back to the
        # same cache. 
        if self.token and self.expiry and self.audience:
            if not token_cache['token'] == self.token:
                # cache token state w/ expiry and Gateway Service audience URL
                try:
                    # set file mode 0o600 at creation
                    self.token_cache_file_path.touch(mode=stat.S_IRUSR|stat.S_IWUSR)
                    token_cache_out = {
                        'token': self.token,
                        'expiry': self.expiry,
                        'audience': self.audience
                    }
                    self.token_cache_file_path.write_text(json.dumps(token_cache_out, indent=4))
                except:
                    logging.warn("failed to cache token in '%s'", self.token_cache_file_path.__str__())
                else:
                    logging.debug("cached token in '%s'", self.token_cache_file_path.__str__())
            else:
                logging.debug("not caching token because it exactly matches the existing cache")
        else:
            logging.debug("not caching token because not all of token, expiry, audience were found")

        # Obtain a session token and find own `.caller` identity and `.organizations`
        self.caller = self.get_caller_identity()

        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.network_groups = self.get_network_groups_by_organization()

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
                logging.debug("removed cached token file '%s'", self.token_cache_file_path.__str__())
                return True
        else:
            logging.debug("cached token file '%s' does not exist", self.token_cache_file_path.__str__())
            return True
        
    def get_caller_identity(self):
        """Return the caller's identity object."""
        # try the generic endpoint, then the API account endpoint, then the endpoint for interactive users
        urls = [
            self.audience+'identity/v1/identities/self',
            self.audience+'identity/v1/api-account-identities/self',
            self.audience+'identity/v1/user-identities/self',
        ]
        headers = { "authorization": "Bearer " + self.token }
        for url in urls:
            try:
                caller = get_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
            except:
                logging.debug("failed to get caller identity from url: '%s'", url)
            else:
                return(caller)
        logging.error("failed to get caller identity from any url")
        raise RuntimeError

    def get_identity(self, identity_id: str):
        """Get an identity by ID.

        :param str identity: UUIDv4 of the identity to get
        """
        url = self.audience+'identity/v1/identities/'+identity_id
        headers = { "authorization": "Bearer " + self.token }
        try:
            identity = get_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except:
            logging.debug("failed to get identity from url: '%s'", url)
            raise
        else:
            return(identity)

    def get_identities(self, **kwargs):
        """Find identities.

        :param str kwargs: filter results by logical AND query parameters
        """
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        if 'sort' in params.keys():
            logging.warn("query param 'sort' is not supported by Identity Service")
        if 'size' in params.keys():
            logging.warn("query param 'size' is not supported by Identity Service")
        if 'page' in params.keys():
            logging.warn("query param 'page' is not supported by Identity Service")

        url = self.audience+'identity/v1/identities'
        headers = { "authorization": "Bearer " + self.token }
        try:
            identities = find_resources(url=url, headers=headers, proxies=self.proxies, verify=self.verify, **params)
        except:
            logging.debug("failed to get identities from url: '%s'", url)
            raise
        else:
            return(identities)

    def get_organizations(self, **kwargs):
        """Find organizations.

        :param str kwargs: filter results by logical AND query parameters
        """
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        if 'sort' in params.keys():
            logging.warn("query param 'sort' is not supported by Identity Service")
        if 'size' in params.keys():
            logging.warn("query param 'size' is not supported by Identity Service")
        if 'page' in params.keys():
            logging.warn("query param 'page' is not supported by Identity Service")

        url = self.audience+'identity/v1/organizations'
        headers = { "authorization": "Bearer " + self.token }
        try:
            organizations = find_resources(url=url, headers=headers, proxies=self.proxies, verify=self.verify, **params)
        except:
            logging.debug("failed to get organizations from url: '%s'", url)
            raise
        else:
            return(organizations)

    def get_organization(self, id):
        """
        Get a single organizations by ID.
        
        :param id: the UUID of the org
        """
        url = self.audience+'identity/v1/organizations/'+id
        headers = { "authorization": "Bearer " + self.token }
        try:
            organization = get_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except:
            logging.debug("failed to get organization from url: '%s'", url)
            raise
        else:
            return(organization)

    def get_network_group(self,network_group_id):
        """
        Get a network group by ID.

        :param network_group_id: the UUID of the network group
        """
        url = self.audience+'rest/v1/network-groups/'+network_group_id
        headers = { "authorization": "Bearer " + self.token }
        try:
            network_group = get_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except:
            logging.debug("failed to get network_group from url: '%s'", url)
            raise
        else:
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
            valid_types = [type for type in embed.split(',') if RESOURCES[type]['domain'] == "network"]
            params['embed'] = ','.join(valid_types)
            logging.debug("requesting embed some resource types in network domain: {:s}".format(valid_types))
            for type in embed.split(','):
                if not type in NETWORK_RESOURCES.keys():
                    logging.warning("not requesting '{:s}', not a resource type in the network domain".format(type))

        url = self.audience+'core/v2/networks/'+network_id
        try:
            network = get_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except:
            logging.debug("failed to get network from url: '%s'", url)
            raise
        else:
            return(network)

    def get_network_groups_by_organization(self, **kwargs):
        """Find network groups.

        :param str kwargs: filter results by any supported query param
        """
        url = self.audience+'rest/v1/network-groups'
        headers = { "authorization": "Bearer " + self.token }
        try:
            network_groups = find_resources(url=url, headers=headers, embedded=RESOURCES['network-groups']._embedded, proxies=self.proxies, verify=self.verify, **kwargs)
        except:
            logging.debug("failed to get network_groups from url: '%s'", url)
            raise
        else:
            return(network_groups)

    network_groups = get_network_groups_by_organization

    def get_networks_by_organization(self, name: str=None, deleted: bool=False, **kwargs):
        """
        Find networks known to this organization.

        :param str name: filter results by name
        :param str kwargs: filter results by any supported query param
        :param bool deleted: include resource entities that have a non-null property deletedAt
        """
        url = self.audience+'core/v2/networks'
        headers = { "authorization": "Bearer " + self.token }
        params = {
            "findByName": name
        }
        for param in kwargs.keys():
            params[param] = kwargs[param]
        try:
            networks = find_resources(url=url, headers=headers, embedded=RESOURCES['networks']._embedded, proxies=self.proxies, verify=self.verify, **params)
        except:
            logging.debug("failed to get networks from url: '%s'", url)
            raise
        else:
            return(networks)

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
            normal_names.append(normalize_caseless(normal['name']))

        return normal_names.count(normalize_caseless(name))

    def get_networks_by_group(self, network_group_id: str, deleted: bool=False, **kwargs):
        """Find networks by network group ID.

        :param network_group_id: required network group UUIDv4
        :param str kwargs: filter results by logical AND query parameters
        """
        params = {
            "findByNetworkGroupId": network_group_id
        }
        for param in kwargs.keys():
            params[param] = kwargs[param]
        if deleted:
            params['status'] = "DELETED"

        url = self.audience+'core/v2/networks'
        headers = { "authorization": "Bearer " + self.token }
        try:
            networks = find_resources(url=url, headers=headers, embedded=RESOURCES['networks']._embedded, proxies=self.proxies, verify=self.verify, **params)
        except:
            logging.debug("failed to get networks from url: '%s'", url)
            raise
        else:
            return(networks)

