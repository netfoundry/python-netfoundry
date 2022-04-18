"""Use an identity organization and find authorized network groups and networks."""

import json
import logging
import logging.config
import os
import re
import time
from pathlib import Path
from stat import S_IRUSR, S_IWUSR, S_IXUSR, filemode

from platformdirs import user_cache_path, user_config_path

from .exceptions import NFAPINoCredentials
from .utility import DEFAULT_TOKEN_EXPIRY, EMBED_NET_RESOURCES, ENVIRONMENTS, NET_RESOURCES, RESOURCES, STATUS_CODES, find_generic_resources, get_generic_resource, get_token_cache, http, is_uuidv4, jwt_environment, jwt_expiry, normalize_caseless, plural


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
                 credentials: str = None,
                 organization: str = None,
                 organization_id: str = None,
                 organization_label: str = None,
                 profile: str = "default",
                 token: str = None,
                 expiry_minimum: int = 600,
                 environment: str = None,
                 logout: bool = False,
                 log_file: str = None,
                 debug: bool = False,
                 logger: logging.Logger = None,
                 proxy: str = None):
        """Initialize an instance of organization."""
        # set debug and file if specified and let the calling application dictate logging handlers
        self.log_file = log_file
        self.debug = debug
        if logger:
            # print(f"using logger '{logger}' from param")
            self.logger = logger
        else:
            # print("initializing null logger")
            self.logger = logging.getLogger(__name__)
#        self.logger = logger or logging.getLogger(__name__)
            self.logger.addHandler(logging.NullHandler())

        if self.debug:
            self.logger.setLevel(logging.DEBUG)

        if self.log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            formatter.converter = time.gmtime
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

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

        epoch = round(time.time())
        self.expiry_seconds = 0  # initialize a placeholder for remaining seconds until expiry
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
            cache_dir_path.mkdir(mode=S_IRUSR | S_IWUSR | S_IXUSR, parents=True, exist_ok=True)
            cache_dir_path.chmod(mode=S_IRUSR | S_IWUSR | S_IXUSR)
        except Exception as e:
            raise RuntimeError(f"failed to create cache dir '{str(cache_dir_path.resolve())}', caught {e}")
        else:
            cache_dir_stats = os.stat(cache_dir_path)
            self.logger.debug(f"token cache dir exists with mode {filemode(cache_dir_stats.st_mode)}")
        self.token_cache_file_path = Path(cache_dir_path / token_cache_file_name)
        self.logger.debug(f"cache file path is computed '{str(self.token_cache_file_path.resolve())}'")

        # short circuit if logout only
        if logout:
            try:
                self.logout()
            except Exception as e:
                self.logger.error(f"unexpected error while logging out: {e}")
            else:
                return None

        # if not token then use standard env var if defined, else look for cached token in file
        if token is not None:
            self.token = token
            self.expiry = None
            self.audience = None
            self.logger.debug("got token as param to Organization")
        elif 'NETFOUNDRY_API_TOKEN' in os.environ:
            self.token = os.environ['NETFOUNDRY_API_TOKEN']
            self.expiry = None
            self.audience = None
            self.logger.debug(f"got token from env NETFOUNDRY_API_TOKEN as {len(self.token)}B")
        else:
            try:
                token_cache = get_token_cache(self.token_cache_file_path)
            except Exception as e:
                self.token = None
                self.expiry = None
                self.audience = None
                self.logger.debug(f"ignoring exception while checking for token cache, caught {e}")
            else:
                self.token = token_cache['token']
                self.expiry = token_cache['expiry']
                self.expiry_seconds = round(self.expiry - epoch)
                self.audience = token_cache['audience']

        # if the token was found but not the expiry then try to parse to extract the expiry so we can enforce minimum lifespan seconds
        if self.token and not self.expiry:
            try:
                self.expiry = jwt_expiry(self.token)
            except Exception as e:
                self.expiry = round(epoch + DEFAULT_TOKEN_EXPIRY)
                self.expiry_seconds = DEFAULT_TOKEN_EXPIRY
                self.logger.debug(f"failed to parse token as JWT, estimating expiry in {DEFAULT_TOKEN_EXPIRY}s, caught {e}")
            else:
                self.expiry_seconds = round(self.expiry - epoch)
                self.logger.debug(f"bearer token expiry in {self.expiry_seconds}s")
        elif not self.token:
            self.logger.debug("no bearer token found")

        # find credentials from param or env so we can renew the token later
        if credentials is not None:
            self.credentials = credentials
            os.environ['NETFOUNDRY_API_ACCOUNT'] = self.credentials
            self.logger.debug(f"got Organization(credentials={self.credentials})")
        elif 'NETFOUNDRY_API_ACCOUNT' in os.environ:
            self.credentials = os.environ['NETFOUNDRY_API_ACCOUNT']
            self.logger.debug(f"got path to credentials file from env NETFOUNDRY_API_ACCOUNT={self.credentials}")
        # if any credentials var then require all credentials vars
        elif ('NETFOUNDRY_CLIENT_ID' in os.environ or 'NETFOUNDRY_PASSWORD' in os.environ or 'NETFOUNDRY_OAUTH_URL' in os.environ):
            if ('NETFOUNDRY_CLIENT_ID' in os.environ and 'NETFOUNDRY_PASSWORD' in os.environ and 'NETFOUNDRY_OAUTH_URL' in os.environ):
                client_id = os.environ['NETFOUNDRY_CLIENT_ID']
                password = os.environ['NETFOUNDRY_PASSWORD']
                token_endpoint = os.environ['NETFOUNDRY_OAUTH_URL']
                credentials_configured = True
                self.logger.debug("configured API account credentials from env NETFOUNDRY_CLIENT_ID, NETFOUNDRY_PASSWORD, NETFOUNDRY_OAUTH_URL")
            else:
                raise RuntimeError("""
some but not all credentials vars present. Need NETFOUNDRY_CLIENT_ID, NETFOUNDRY_PASSWORD, and
NETFOUNDRY_OAUTH_URL or a credentials file in default file locations or NETFOUNDRY_API_ACCOUNT as
path to credentials file.
""")
        else:
            self.credentials = "credentials.json"
            self.logger.debug("token renewal will look for default credentials file name 'credentials.json' in project (cwd), user, and device default paths")

        # continue if we already found the credentials in env
        if not credentials_configured:
            # if valid relative or absolute path to creds file, else search the default dirs
            if os.path.exists(self.credentials):
                self.logger.debug(f"found credentials file '{self.credentials}'")
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
                        self.logger.debug(f"found credentials file {str(candidate.resolve())} in {scope['scope']}-default directory")
                        self.credentials = str(candidate.resolve())
                        break
                    else:
                        self.logger.debug(f"no credentials file {str(candidate.resolve())} in {scope['scope']}-default directory")

            try:
                file = open(self.credentials, 'r')
            except FileNotFoundError:
                self.logger.debug(f"credentials file '{self.credentials}' does not exist")
                # this means we can't renew the token, but it's not fatal
            else:
                account = json.load(file)
                token_endpoint = account['authenticationUrl']
                client_id = account['clientId']
                password = account['password']
                credentials_configured = True
                self.logger.debug(f"configured credentials from file '{self.credentials}'")

        if not credentials_configured:
            self.logger.debug("token renewal impossible because API account credentials are not configured")

        # The purpose of this flow is to compose the audience URL. The mode of
        # the try-except block is to soft-fail all attempts to parse the JWT,
        # which is intended for the API, not this application
        if self.token and not self.environment:
            try:
                self.environment = jwt_environment(self.token)
            except Exception as e:
                # an exception here is very unlikely because the called
                # function is designed to provide a sane default in case the
                # token can't be parsed
                raise RuntimeError(f"unexpected error extracting environment from JWT, caught {e}")
            else:
                self.logger.debug(f"parsed token as JWT and found environment {self.environment}")
            finally:
                if self.environment not in ENVIRONMENTS:
                    self.logger.warn(f"unexpected environment '{self.environment}'")

        if self.environment and not self.audience:
            self.audience = f'https://gateway.{self.environment}.netfoundry.io/'

        if self.environment and self.audience:
            if not re.search(self.environment, self.audience):
                self.logger.error(f"mismatched audience URL '{self.audience}' and environment '{self.environment}'")
                exit(1)

        # the purpose of this try-except block is to soft-fail all attempts
        # to parse the JWT, which is intended for the API, not this
        # application
        if self.token and not self.expiry:  # if token was obtained in this pass then expiry is already defined by response 'expires_in' property
            try:
                self.expiry = jwt_expiry(self.token)
            except Exception as e:
                raise RuntimeError(f"unexpected error getting expiry from token, caught {e}")
            else:
                self.expiry_seconds = round(self.expiry - epoch)
                self.logger.debug(f"bearer token expiry in {self.expiry_seconds}s")

        # renew token if not existing or imminent expiry, else continue
        if not self.token or self.expiry_seconds < expiry_minimum:
            # we've already done the work to determine the cached token is expired or imminently-expiring, might as well save other runs the same trouble
            self.logout()
            self.expiry = None
            self.audience = None
            if self.token and self.expiry_seconds < expiry_minimum:
                self.logger.debug(f"token expiry {self.expiry_seconds}s is less than configured minimum {expiry_minimum}s")
            if not credentials_configured:
                raise NFAPINoCredentials("unable to renew because credentials are not configured")
            else:
                self.logger.debug("renewing token with credentials")

            # extract the environment name from the authorization URL aka token API endpoint
            if self.environment is None:
                self.environment = re.sub(r'https://netfoundry-([^-]+)-.*', r'\1', token_endpoint, re.IGNORECASE)
                self.logger.debug(f"using environment parsed from token_endpoint URL {self.environment}")
            # re: scope: we're not using scopes with Cognito, but a non-empty value is required;
            #  hence "/ignore-scope"
            scope = "https://gateway."+self.environment+".netfoundry.io//ignore-scope"
            # we can gather the URL of the API from the first part of the scope string by
            #  dropping the scope suffix
            self.audience = scope.replace(r'/ignore-scope', '')
            self.logger.debug(f"using audience parsed from token_endpoint URL {self.audience}")
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
            except Exception as e:
                raise RuntimeError(f'failed to contact the authentication endpoint: {token_endpoint}, caught {e}')

            if response_code == STATUS_CODES.codes.OK:
                try:
                    token_text = json.loads(response.text)
                    self.token = token_text['access_token']
                    self.expiry = round(token_text['expires_in'] + epoch)
                    self.logger.debug(f"computed expiry epoch {self.expiry} from 'expires_in={token_text['expires_in']}'")
                except Exception as e:
                    raise RuntimeError(f"failed to find an access_token in the response and instead got: {response.text}, {e}")
                else:
                    self.expiry_seconds = round(self.expiry - epoch)
                    self.logger.debug(f"bearer token expiry in {self.expiry_seconds}s")
            else:
                raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")
        elif credentials_configured:
            self.logger.debug(f"ignoring configured credentials, already logged in with {self.expiry_seconds}s until token expiry")

        # write to the token cache if we have all three things: the token,
        # expiry, and audience URL, unless it matches the token cache, which
        # would mean we would be needlessly writing the same token back to the
        # same cache.
        if self.token and self.expiry and self.audience:
            if not token_cache['token'] == self.token:
                # cache token state w/ expiry and Gateway Service audience URL
                try:
                    # set file mode 0o600 at creation
                    self.token_cache_file_path.touch(mode=S_IRUSR | S_IWUSR)
                    token_cache_out = {
                        'token': self.token,
                        'expiry': self.expiry,
                        'audience': self.audience
                    }
                    self.token_cache_file_path.write_text(json.dumps(token_cache_out, indent=4))
                except Exception as e:
                    self.logger.warn(f"failed to cache token in '{str(self.token_cache_file_path.resolve())}', caught {e}")
                else:
                    self.logger.debug(f"cached token in '{str(self.token_cache_file_path.resolve())}'")
            else:
                self.logger.debug("not caching token because it exactly matches the existing cache")
        else:
            self.logger.debug("not caching token because not all of token, expiry, audience were found")

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
            if self.organizations_by_label.get(organization_label):
                self.describe = self.get_organization(id=self.organizations_by_label[organization_label])
            else:
                raise RuntimeError(f"failed to find org label {organization_label} in the list of orgs {', '.join(self.organizations_by_label.keys())}")
        else:
            self.describe = self.get_organization(id=self.caller['organizationId'])

        self.label = self.describe['label']
        self.name = self.describe['name']
        self.id = self.describe['id']

        # always resolve Network Groups so we can specify either name or ID when calling super()
        self.network_groups_by_name = dict()
        for group in self.get_network_groups_by_organization():
            self.network_groups_by_name[group['name']] = group['id']

    # END init

    def logout(self):
        """Logout from NF organization by removing the cached token file."""
        if os.path.exists(self.token_cache_file_path):
            try:
                os.remove(self.token_cache_file_path)
            except Exception as e:
                self.logger.error(f"failed to remove cached token file '{str(self.token_cache_file_path.resolve())}', caught {e}")
                return False
            else:
                self.logger.debug(f"removed cached token file '{str(self.token_cache_file_path.resolve())}'")
                return True
        else:
            self.logger.debug(f"cached token file '{str(self.token_cache_file_path.resolve())}' does not exist")
            return True

    def get_caller_identity(self):
        """Return the caller's identity object."""
        # try the generic endpoint, then the API account endpoint, then the endpoint for interactive users
        urls = [
            self.audience+'identity/v1/identities/self',
            self.audience+'identity/v1/api-account-identities/self',
            self.audience+'identity/v1/user-identities/self',
        ]
        headers = {"authorization": "Bearer " + self.token}
        for url in urls:
            try:
                caller, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
            except Exception as e:
                self.logger.debug(f"failed to get caller identity from url: '{url}', trying next until last, caught {e}")
            else:
                return(caller)
        raise RuntimeError("failed to get caller identity from any url")

    def get_identity(self, identity_id: str):
        """Get an identity by ID.

        :param str identity: UUIDv4 of the identity to get
        """
        url = self.audience+'identity/v1/identities/'+identity_id
        headers = {"authorization": "Bearer " + self.token}
        try:
            identity, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get identity from url: '{url}', caught {e}")
        else:
            return(identity)

    def find_identities(self, type: str = 'identities', **kwargs):
        """Get identities as a collection.

        :param str type: optional sub-type "user-identities" or "api-account-identities"
        :param str kwargs: filter results by logical AND query parameters
        """
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        for noop in ['sort', 'size', 'page']:
            if params.get(noop):
                self.logger.warn(f"query param '{noop}' is not supported by Identity Service")
        if type in ["UserIdentity", "user-identities"]:
            url = self.audience+'identity/v1/user-identities'
        elif type in ["ApiAccountIdentity", "api-account-identities"]:
            url = self.audience+'identity/v1/api-account-identities'
        elif type == "identities":
            url = self.audience+'identity/v1/identities'
        else:
            raise RuntimeError(f"unexpected value for param 'type', got {type}, need one of 'user-identities' or 'api-account-identities'")
        headers = {"authorization": "Bearer " + self.token}
        try:
            identities = list()
            for i in find_generic_resources(url=url, headers=headers, proxies=self.proxies, verify=self.verify, **params):
                identities.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get identities from url: '{url}', caught {e}")
        else:
            return(identities)
    get_identities = find_identities

    def find_roles(self, **kwargs):
        """Get roles as a collection."""
        params = dict()
        for k, v in kwargs.items():
            if k == 'name':
                params['nameLike'] = v
            elif k == 'description':
                params['descriptionLike'] = v
            elif k == 'identityId':
                identity_id = self.get_identity(identity_id=v)
                if identity_id['type'] == 'ApiAccountIdentity':
                    self.logger.warning("Auth Service may not report roles for identityId type ApiAccountIdentity")
                params[k] = v
            else:
                params[k] = v
        for noop in ['size', 'page']:
            if params.get(noop):
                self.logger.warn(f"query param '{noop}' is not implemented for Authorization Service in this application")

        url = self.audience+'auth/v1/roles'
        headers = {"authorization": "Bearer " + self.token}
        try:
            roles = list()
            for i in find_generic_resources(url=url, headers=headers, proxies=self.proxies, verify=self.verify, **params):
                roles.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get roles from url: '{url}', caught {e}")
        else:
            return(roles)

    def get_role(self, role_id: str):
        """Get roles as a collection."""

        url = f"{self.audience}auth/v1/roles/{role_id}"
        headers = {"authorization": "Bearer " + self.token}
        try:
            role, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get role from url: '{url}', caught {e}")
        else:
            return(role)

    def find_organizations(self, **kwargs):
        """Find organizations as a collection.

        :param str kwargs: filter results by logical AND query parameters
        """
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        for noop in ['sort', 'size', 'page']:
            if params.get(noop):
                self.logger.warn(f"query param '{noop}' is not supported by Identity Service")

        url = self.audience+'identity/v1/organizations'
        headers = {"authorization": "Bearer " + self.token}
        try:
            organizations = list()
            for i in find_generic_resources(url=url, headers=headers, proxies=self.proxies, verify=self.verify, **params):
                organizations.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get organizations from url: '{url}', caught {e}")
        else:
            return(organizations)
    get_organizations = find_organizations

    def get_organization(self, id):
        """
        Get a single organizations by ID.

        :param id: the UUID of the org
        """
        url = self.audience+'identity/v1/organizations/'+id
        headers = {"authorization": "Bearer " + self.token}
        try:
            organization, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get organization from url: '{url}', caught {e}")
        else:
            return(organization)

    def get_network_group(self, network_group_id):
        """
        Get a network group by ID.

        :param network_group_id: the UUID of the network group
        """
        url = self.audience+'rest/v1/network-groups/'+network_group_id
        headers = {"authorization": "Bearer " + self.token}
        try:
            network_group, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get network_group from url: '{url}', caught {e}")
        else:
            return(network_group)

    def get_network(self, network_id: str, embed: object = None, accept: str = None):
        """Describe a Network by ID.

        :param str network_id: UUIDv4 of the network to get
        :param str embed: magic 'all' embeds all resource types in network domain, else comma-separated list of resource types to embed in response e.g. 'endpoints,services'
        :param str accept: specifying the form of the desired response. Choices ["create","update"] where
                "create" is useful for comparing an existing entity to a set of properties that are used to create the same type of
                entity in a POST request, and "update" may be used in the same way for a PUT update.
        """
        headers = dict()
        headers["authorization"] = "Bearer " + self.token
        params = dict()
        requested_types = list()
        valid_types = set()
        if embed:
            if isinstance(embed, list):
                requested_types.extend(embed)
            else:
                requested_types.extend(embed.split(','))
            if 'all' in requested_types:
                valid_types = ['all']
            else:
                valid_types = [plural(type) for type in requested_types if EMBED_NET_RESOURCES.get(plural(type))]
            params['embed'] = ','.join(valid_types)
            self.logger.debug(f"requesting embed of: '{valid_types}'")

        url = self.audience+'core/v2/networks/'+network_id
        network, status_symbol = get_generic_resource(url=url, headers=headers, accept=accept, proxies=self.proxies, verify=self.verify, **params)
        return(network)

    def find_network_groups_by_organization(self, **kwargs):
        """Find network groups as a collection.

        :param str kwargs: filter results by any supported query param
        """
        url = self.audience+'rest/v1/network-groups'
        headers = {"authorization": "Bearer " + self.token}
        network_groups = list()
        for i in find_generic_resources(url=url, headers=headers, embedded=RESOURCES['network-groups']._embedded, proxies=self.proxies, verify=self.verify, **kwargs):
            network_groups.extend(i)
        return(network_groups)
    get_network_groups_by_organization = find_network_groups_by_organization
    network_groups = get_network_groups_by_organization

    def find_networks_by_organization(self, name: str = None, deleted: bool = False, accept: str = None, **kwargs):
        """
        Find networks by organization as a collection.

        :param str name: filter results by name
        :param str kwargs: filter results by any supported query param
        :param bool deleted: include resource entities that have a non-null property deletedAt
        """
        url = self.audience+'core/v2/networks'
        headers = {"authorization": "Bearer " + self.token}
        params = {
            "findByName": name
        }
        for param in kwargs.keys():
            params[param] = kwargs[param]
        if deleted:
            params['status'] = 'DELETED'
        try:
            networks = list()
            for i in find_generic_resources(url=url, headers=headers, embedded=RESOURCES['networks']._embedded, accept=accept, proxies=self.proxies, verify=self.verify, **params):
                networks.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get networks from url: '{url}', caught {e}")
        else:
            return(networks)
    get_networks_by_organization = find_networks_by_organization

    def network_exists(self, name: str, deleted: bool = False):
        """Check if a network exists.

        :param name: the case-insensitive string to search
        :param deleted: include deleted networks in results
        """
        if self.count_networks_with_name(name=name, deleted=deleted) > 0:
            return(True)
        else:
            return(False)

    def count_networks_with_name(self, name: str, deleted: bool = False, unique: bool = True):
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

    def find_networks_by_group(self, network_group_id: str, deleted: bool = False, accept: str = None, **kwargs):
        """Find networks by network group as a collection.

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
        headers = {"authorization": "Bearer " + self.token}
        try:
            networks = list()
            for i in find_generic_resources(url=url, headers=headers, embedded=RESOURCES['networks']._embedded, accept=accept, proxies=self.proxies, verify=self.verify, **params):
                networks.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get networks from url: '{url}', caught {e}")
        else:
            return(networks)
    get_networks_by_group = find_networks_by_group
