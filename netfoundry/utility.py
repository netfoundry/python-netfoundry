"""Shared helper functions, constants, and classes."""

import json
from json import JSONDecodeError
import logging
import os
from stat import filemode
import re  # regex
from urllib.parse import urlparse
import time  # enforce a timeout; sleep
import unicodedata  # case insensitive compare in Utility
from dataclasses import dataclass, field
from re import sub
from uuid import UUID  # validate UUIDv4 strings

import inflect  # singular and plural nouns
import jwt
from requests import Session  # HTTP user agent will not emit server cert warnings if verify=False
from requests import status_codes
from requests.exceptions import HTTPError
from requests.adapters import HTTPAdapter
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from .exceptions import UnknownResourceType

disable_warnings(InsecureRequestWarning)

p = inflect.engine()


def any_in(a, b):
    "True if any of a are in b"
    return any(i in b for i in a)


def plural(singular):
    """Pluralize a singular form."""
    # if already plural then return, else pluralize
    if singular[-1:] == 's':
        return(singular)
    else:
        return(p.plural_noun(singular))


def singular(plural):
    """Singularize a plural form."""
    return(p.singular_noun(plural))


def kebab2camel(kebab: str, case: str = "lower"):          # "lower" dromedary or "upper" Pascal
    """Convert kebab case to camel case."""
    if not isinstance(kebab, str):
        raise RuntimeError(f"bad arg to kebab2camel {str(kebab)}")
    kebab_words = kebab.split('-')
    camel_words = list()
    if case in ["lower", "dromedary"]:
        camel_words.append(kebab_words[0].lower())  # first word is lowercase
    elif case in ["upper", "pascal"]:
        camel_words.append(kebab_words[0].upper())  # first word is uppercase
    else:
        raise Exception("param 'case' wants 'lower' or 'upper'")
    for word in kebab_words[1:]:                    # subsequent words are capitalized (cameled)
        lower_word = word.lower()
        capital = lower_word[0].upper()
        camel_word = capital+lower_word[1:]
        camel_words.append(camel_word)
    camel = ''.join(camel_words)
    return camel


def snake2camel(snake_str):
    """Convert a string from snake case to camel case."""
    first, *others = snake_str.split('_')
    return ''.join([first.lower(), *map(str.title, others)])


def camel2snake(camel_str):
    """Convert a string from camel case to snake case."""
    return sub(r'(?<!^)(?=[A-Z])', '_', camel_str).lower()


def abbreviate(kebab):
    """Abbreviate a kebab-case string with the first letter of each word."""
    kebab_words = kebab.split('-')
    letters = list()
    for word in kebab_words:
        letters.extend(word[0])
    return ''.join(letters)


def normalize_caseless(text):
    """Normalize a string as lowercase unicode KD form.

    The normal form KD (NFKD) will apply the compatibility decomposition,
    i.e. replace all compatibility characters with their equivalents.
    """
    return unicodedata.normalize("NFKD", text.casefold())


def caseless_equal(left, right):
    """Compare the KD normal form of left, right strings."""
    return normalize_caseless(left) == normalize_caseless(right)


def get_token_cache(path):
    """Try to read the token cache file and return the object."""
    try:
        token_cache = json.loads(path.read_text())
    except FileNotFoundError as e:
        raise RuntimeError(f"cache file '{path.__str__()}' not found, caught {e}")
    except JSONDecodeError as e:
        raise RuntimeError(f"failed to parse cache file '{path.__str__()}' as JSON, caught {e}")
    except Exception as e:
        raise RuntimeError(f"failed to read cache file '{path.__str__()}', caught {e}")
    else:
        cache_file_stats = os.stat(path)
        logging.debug(f"parsed token cache file '{path.__str__()}' as JSON with mode {filemode(cache_file_stats.st_mode)}")

    if all(k in token_cache for k in ['token', 'expiry', 'audience']):
        return token_cache
    else:
        raise Exception("not all expected token cache file keys were found: token, expiry, audience")


def jwt_expiry(token):
    """Return an epoch timestampt when the token will be expired.

    First, try to parse JWT to extract expiry. If that fails then estimate +1h.
    """
    try:
        claim = jwt_decode(token)
        expiry = claim['exp']
    except jwt.exceptions.PyJWTError:
        logging.debug(f"error parsing JWT to extract expiry, estimating +{DEFAULT_TOKEN_EXPIRY}s")
        expiry = time.time() + DEFAULT_TOKEN_EXPIRY
    except KeyError:
        logging.debug(f"failed to extract expiry epoch from claimset as key 'exp', estimating +{DEFAULT_TOKEN_EXPIRY}s")
        expiry = time.time() + DEFAULT_TOKEN_EXPIRY
    except Exception as e:
        raise RuntimeError(f"unexpect error, caught {e}")
    else:
        logging.debug("successfully extracted expiry from JWT")
    finally:
        return expiry


def jwt_environment(token):
    """Try to extract the environment name from a JWT.

    First, try to parse JWT to extract the audience. If that fails then assume "production".
    """
    try:
        claim = jwt_decode(token)
        iss = claim['iss']
    except jwt.exceptions.PyJWTError:
        environment = "production"
        logging.debug("error parsing JWT to extract audience, assuming environment is Production")
    except KeyError:
        environment = "production"
        logging.debug("failed to extract the issuer URL from claimset as key 'iss', assuming environment is Production")
    except Exception as e:
        raise RuntimeError(f"unexpect error, caught {e}")

    else:
        if re.match(r'https://cognito-', iss):
            environment = re.sub(r'https://gateway\.([^.]+)\.netfoundry\.io.*', r'\1', claim['scope'])
            logging.debug(f"matched Cognito issuer URL convention, found environment '{environment}'")
        elif re.match(r'.*\.auth0\.com', iss):
            environment = re.sub(r'https://netfoundry-([^.]+)\.auth0\.com.*', r'\1', claim['iss'])
            logging.debug(f"matched Auth0 issuer URL convention, found environment '{environment}'")
        else:
            environment = "production"
            logging.debug(f"failed to match Auth0 and Cognito issuer URL conventions, assuming environment is '{environment}'")
    finally:
        return environment


def jwt_decode(token):
    # TODO: figure out how to stop doing this because the token is for the
    # API, not this app, and so may change algorithm unexpectedly or stop
    # being a JWT altogether, currently needed to build the URL for HTTP
    # requests, might need to start using env config
    """Parse the token and return claimset."""
    try:
        claim = jwt.decode(jwt=token, algorithms=["RS256"], options={"verify_signature": False})
    except jwt.exceptions.PyJWTError as e:
        raise jwt.exceptions.PyJWTError(f"failed to parse bearer token as JWT, caught {e}")
    except Exception as e:
        raise RuntimeError(f"unexpect error parsing JWT, caught {e}")
    return claim


def is_jwt(token):
    """If is a JWT then True."""
    try:
        jwt_decode(token)
    except jwt.exceptions.PyJWTError:
        return False
    except Exception as e:
        raise RuntimeError(f"unexpect error parsing JWT, caught {e}")

    else:
        return True


def is_uuidv4(string: str):
    """Test if string is valid UUIDv4."""
    try:
        UUID(string, version=4)
    except ValueError:
        return False
    else:
        return True


def eprint(*args, **kwargs):
    """Adapt legacy function to logging."""
    logging.debug(*args, **kwargs)


def get_resource_type_by_url(url: str):
    """Get the resource type definition from a resource URL."""
    url_parts = urlparse(url)
    url_path = url_parts.path
    resource_type = sub(r'/(core|rest|identity|auth|product-metadata)/v\d+/([^/]+)/?.*', r'\2', url_path)
    if resource_type == "download-urls.json":
        resource_type = "download-urls"
    if RESOURCES.get(resource_type):
        return RESOURCES.get(resource_type)
    else:
        raise UnknownResourceType(resource_type, RESOURCES.keys())


def get_generic_resource(url: str, headers: dict, proxies: dict = dict(), verify: bool = True, accept: str = None, **kwargs):
    """
    Get, deserialize, and return a single resource.

    :param url: the full URL to get
    :param headers: authorization and accept headers
    :param proxies: Requests proxies dict
    :param verify: Requests verify bool is off if proxies enabled in this lib
    :param kwargs: additional query params are typically logical AND if supported or ignored by the API if not
    """
    params = dict()
    for param in kwargs.keys():
        params[param] = kwargs[param]
    if accept:
        if accept in ["create", "update"]:
            headers['accept'] = f"application/json;as={accept}"
        else:
            logging.warn("ignoring invalid value for header 'accept': '{:s}'".format(accept))

    resource_type = get_resource_type_by_url(url)
    logging.debug(f"detected resource type {resource_type.name}")
    # always embed the host record if getting the base resource by ID i.e. /{resource_type}/{uuid}, not leaf operations like /session or /rotatekey
    pattern = re.compile(f".*/{resource_type.name}/"+r'[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
    if resource_type.name in HOSTABLE_NET_RESOURCES.keys() and re.match(pattern, url):
        params['embed'] = "host"
    elif resource_type.name in ["process-executions"]:
        params['beta'] = str()
    else:
        logging.debug(f"no handlers specified for url '{url}'")
    response = http.get(
        url,
        headers=headers,
        params=params,
        proxies=proxies,
        verify=verify,
    )
    # Return the HTTP response code symbol. This is useful for functions like
    # network.get_status() which will fall-back to the HTTP status if a status
    # property is not available
    status_symbol = STATUS_CODES._codes[response.status_code][0].upper()
    try:
        response.raise_for_status()
    except HTTPError:
        if resource_type.name in ["process-executions"] and status_symbol == "FORBIDDEN":  # FIXME: MOP-18095 workaround the create network process ID mismatch bug
            url_parts = urlparse(url)
            path_parts = url_parts.path.split('/')
            process_id = path_parts[-1]                                      # the UUID is the last part of the expected URL to get_generic_resource()
            url = f"https://{url_parts.netloc}{'/'.join(path_parts[:-1])}"  # everything but the id
            params['processId'] = process_id
            resources = next(find_generic_resources(url, headers=headers, embedded=RESOURCES['process-executions']._embedded, proxies=proxies, verify=verify, accept=accept, **params))
            if len(resources) == 1:
                resource = resources[0]
            else:
                resource = {
                    "status": "NEW",
                    "name": "NONAME"
                }
        elif not status_symbol == 'NOT_FOUND':  # tolerate 404 because some functions will conclude that the resource has been deleted as expected
            raise
    else:
        resource = response.json()
    return resource, status_symbol


def find_generic_resources(url: str, headers: dict, embedded: str = None, proxies: dict = dict(), verify: bool = True, accept: str = None, **kwargs):
    """
    Generate each page of a type of resource.

    :param url: the full URL to get
    :param headers: authorization and accept headers
    :param embedded: the key under '_embedded' where the list of resources for this type is found (e.g. 'networkList')
    :param proxies: Requests proxies dict
    :param verify: Requests verify bool is off if proxies enabled in this lib
    :param kwargs: additional query params are typically logical AND if supported or ignored by the API if not
    """
    # page through all pages unless a particular page or size or both are requested
    get_all_pages = True
    # parse all kwargs as query params
    params = dict()
    # validate and store the resource type
    resource_type = get_resource_type_by_url(url)
    if HOSTABLE_NET_RESOURCES.get(resource_type.name):
        params['embed'] = "host"
    elif resource_type.name in ["process-executions"]:
        params['beta'] = str()

    for k, v in kwargs.items():
        if k == 'name' and resource_type.name == 'networks':  # workaround sort param bug in MOP-17863
            params['findByName'] = v
        elif k == 'networkGroupId' and resource_type.name in ['networks', 'network-groups']:
            params['findByNetworkGroupId'] = v
        else:
            params[k] = v

    # normalize output with a default sort param
    if not params.get('sort'):
        params["sort"] = "name,asc"
    # workaround sort param bugs in MOP-18018, MOP-17863, MOP-18178
    if resource_type.name in ['identities', 'user-identities', 'api-account-identities', 'hosts', 'terminators']:
        del params['sort']

    # only get one page of the requested size, else default page size and all pages
    if params.get('size'):
        get_all_pages = False
    else:
        if resource_type.name in ['data-centers', 'roles']:
            params['size'] = 3000    # workaround last page bug in MOP-17993
        else:
            params['size'] = DEFAULT_PAGE_SIZE

    # only get requested page, else first page and all pages
    if params.get('page'):
        get_all_pages = False
    else:
        params['page'] = 0

    if accept:
        if accept in ["create"]:
            headers['accept'] = "application/hal+json;as="+accept
            embedded = accept + embedded[0].upper() + embedded[1:]  # compose "createEndpointList" from "endpointList"
        else:
            logging.warn("ignoring invalid value for header 'accept': '{:s}'".format(accept))

    response = http.get(
        url,
        headers=headers,
        params=params,
        proxies=proxies,
        verify=verify,
    )
    response.raise_for_status()
    resource_page = response.json()
    if isinstance(resource_page, dict) and resource_page.get('page'):
        try:
            total_pages = resource_page['page']['totalPages']
            total_elements = resource_page['page']['totalElements']
        except KeyError as e:
            raise RuntimeError(f"got 'page' key in HTTP response but missing expected sub-key: {e}")
        else:
            if total_elements == 0:
                yield_page = list()  # delay yielding until end of flow
            else:
                if embedded:         # function param 'embedded' specifies the reference in which the collection of resources should be found
                    try:
                        yield_page = resource_page['_embedded'][embedded]
                    except KeyError as e:
                        raise RuntimeError(f"failed to find embedded collection in valid JSON response at '_embedded.{embedded}', got: '{e}'")
                    else:
                        if accept in ["create", "update"]:
                            for i in yield_page:
                                del i['_links']
                elif resource_page.get('content'):
                    yield_page = resource_page['content']
                else:
                    yield_page = resource_page

            # yield first, only, and empty pages
            yield yield_page

            # then yield subsequent pages, if applicable
            if get_all_pages:           # this is False if param 'page' or 'size' to stop recursion or get a single page
                if resource_type.name == 'network-groups':
                    params['page'] = 1  # workaround API bug https://netfoundry.atlassian.net/browse/MOP-17890
                    next_range_lower, next_range_upper = params['page'] + 2, total_pages + 1
                else:
                    next_range_lower, next_range_upper = params['page'] + 1, total_pages
                for next_page in range(next_range_lower, next_range_upper):  # first page is 0 unless network-groups which are 1-based
                    params['page'] = next_page
                    try:
                        # recurse
                        yield from find_generic_resources(url=url, headers=headers, embedded=embedded, proxies=proxies, verify=verify, **params)
                    except Exception as e:
                        raise RuntimeError(f"failed to get page {next_page} of {total_pages}, caught {e}'")
    elif embedded:      # function param 'embedded' specifies the reference in which the collection of resources should be found
        try:
            yield_page = resource_page['_embedded'][embedded]
        except KeyError as e:
            raise RuntimeError(f"failed to find embedded collection in valid JSON response at '_embedded.{embedded}', caught: '{e}'")
        else:
            yield yield_page
    elif isinstance(resource_page, dict) and 'content' in resource_page.keys():  # has the generic embed key 'content'
        yield_page = resource_page['content']
        yield yield_page
    else:  # is a list or a flat dict
        yield resource_page


class Utility:
    """Legacy interface to utility functions."""
    def __init__(self):
        pass

    def caseless_equal(self, left, right):
        return caseless_equal(left, right)

    def snake(self, camel_str):
        return camel2snake(camel_str)

    def camel(self, snake_str):
        return snake2camel(snake_str)


NET_RESOURCES = dict()             # resources in network domain
MUTABLE_NET_RESOURCES = dict()     # network resources that can be updated
MUTABLE_RESOURCE_ABBREV = dict()   # unique abbreviations for ^
EMBED_NET_RESOURCES = dict()       # network resources that may be fetched as embedded collections
HOSTABLE_NET_RESOURCES = dict()    # network resources that may be attached to a managed host
HOSTABLE_RESOURCE_ABBREV = dict()  # unique abbreviations for ^
RESOURCE_ABBREV = dict()           # unique abbreviations for all resource types

PROCESS_STATUS_SYMBOLS = {
    "complete": ("FINISHED", "SUCCESS"),
    "progress": ("STARTED", "RUNNING", "OK"),
    "error": ("FAILED",),
    "deleting": tuple(),
    "deleted": tuple(),
}
RESOURCE_STATUS_SYMBOLS = {
    "complete": ("PROVISIONED"),
    "progress": ("NEW", "PROVISIONING", "UPDATING", "REPLACING", "OK"),
    "error": ("ERROR", "SUSPENDED", "NOT_FOUND"),
    "deleting": ("DELETING",),
    "deleted": ("DELETED", "NOT_FOUND"),
}
RESOURCE_STATUSES = set()
for k, v in RESOURCE_STATUS_SYMBOLS.items():
    for i in v:
        RESOURCE_STATUSES.add(i)


# The purpose of the parent class is to validate the type of child class
# attributes. Homing this logic in a parent class allows any number of child
# classes to use it.
@dataclass
class ResourceTypeParent:
    """Parent class for ResourceType class."""

    def __post_init__(self):
        """Enforce typed fields in resource spec."""
        for (name, field_type) in self.__annotations__.items():
            if not isinstance(self.__dict__[name], field_type):
                current_type = type(self.__dict__[name])
                raise TypeError(f"The field `{name}` was assigned by `{current_type}` instead of `{field_type}`")


# the instance's attributes can not be frozen because we're computing the
# _embedded key and assigning post-init
@dataclass(frozen=False)
class ResourceType(ResourceTypeParent):
    """Typed resource type spec.

    As close as I could get to a Go struct. This helps us to suggest possible
    operations such as all resource types in the network domain that can be
    mutated (C_UD).
    """

    name: str                                               # plural form as kebab-case e.g. edge-routers
    domain: str                                             # most are in network, identity
    mutable: bool                                           # createable, editable, or deletable
    embeddable: bool                                        # legal to request embedding in a parent resource in same domain
    parent: str = field(default=str())                      # optional parent ResourceType instance name
    status: str = field(default='status')                   # name of property where symbolic status is expressed
    _embedded: str = field(default='default')               # the key under which lists are found in the API
                                                            #  e.g. networkControllerList (computed if not provided as dromedary
                                                            #  case singular)
    create_responses: list = field(default_factory=list)    # expected HTTP response codes for create operation
    no_update_props: list = field(default_factory=list)     # expected HTTP response codes for create operation
    create_template: dict = field(default_factory=lambda: {
        'hint': "No template was found for this resource type. "
                " Replace the contents of this buffer with the "
                " request body as YAML or JSON to create a resource."
                " networkId will be added automatically."
    })                                                      # object to load when creating from scratch in nfctl
    abbreviation: str = field(default='default')
    status_symbols: dict = field(default_factory=lambda: RESOURCE_STATUS_SYMBOLS)  # dictionary with three predictable keys: complete, progress, error, each a tuple associating status symbols with a state
    host: bool = field(default=False)                       # may have a managed host in NF cloud

    def __post_init__(self):
        """Compute and assign _embedded if not supplied and then check types in parent class."""
        if self._embedded == 'default':
            singular_name = singular(self.name)
            if not singular_name:
                raise RuntimeError(f"params to singular() must be plural, got {singular_name} from singular({self.name})")
            camel_name = kebab2camel(singular_name)+'List'       # edgeRouterList
            setattr(self, '_embedded', camel_name)
        if self.abbreviation == 'default':
            setattr(self, 'abbreviation', abbreviate(self.name))
        if RESOURCE_ABBREV.get(self.abbreviation):
            raise RuntimeError(f"abbreviation collision for {self.name} ({self.abbreviation})")
        else:
            RESOURCE_ABBREV[self.abbreviation] = self
        if self.domain == 'network':
            NET_RESOURCES[self.name] = self
            if self.embeddable:
                EMBED_NET_RESOURCES[self.name] = self
            if self.mutable:
                MUTABLE_NET_RESOURCES[self.name] = self
                MUTABLE_RESOURCE_ABBREV[self.abbreviation] = self
            if self.host:
                HOSTABLE_NET_RESOURCES[self.name] = self
                HOSTABLE_RESOURCE_ABBREV[self.abbreviation] = self
        return super().__post_init__()


RESOURCES = {
    'roles': ResourceType(
        name='roles',
        domain='identity',
        mutable=False,
        embeddable=False,
        _embedded='content',
        abbreviation='rol',
    ),
    'process-executions': ResourceType(
        name='process-executions',
        domain='network',
        mutable=False,
        embeddable=False,
        status="state",
        status_symbols=PROCESS_STATUS_SYMBOLS,
    ),
    'regions': ResourceType(
        name='regions',
        domain='network',
        mutable=False,
        embeddable=False,
        abbreviation='reg',
    ),
    'network-versions': ResourceType(
        name='network-versions',
        domain='network',
        mutable=False,
        embeddable=False,
        _embedded='network-versions',
    ),
    'data-centers': ResourceType(
        name='data-centers',
        domain='network',
        _embedded='dataCenters',
        mutable=False,
        embeddable=False,
    ),
    'organizations': ResourceType(
        name='organizations',
        domain='identity',
        mutable=False,
        embeddable=False,
    ),
    'network-groups': ResourceType(
        name='network-groups',
        domain='network-group',
        _embedded='organizations',
        mutable=False,
        embeddable=False,
    ),
    'download-urls': ResourceType(
        name='download-urls',
        domain='network-group',
        mutable=False,
        embeddable=False,
    ),
    'networks': ResourceType(
        name='networks',
        domain='network',
        mutable=True,
        embeddable=False,
        create_responses=["ACCEPTED"],
        create_template={
            "name": "Name",
            "locationCode": "us-east-1",
            "networkGroupId": None
        },
    ),
    'network-controllers': ResourceType(
        name='network-controllers',
        domain="network",
        mutable=False,
        embeddable=True,
        host=True,
    ),
    'identities': ResourceType(
        name='identities',
        domain='identity',
        mutable=False,              # TODO: C_UD not yet implemented here in client for org domain
        embeddable=False,           # TODO: embedding not yet implemented in API for org domain
    ),
    'user-identities': ResourceType(
        name='user-identities',
        domain='identity',
        mutable=False,
        embeddable=False,
        parent='identities',
    ),
    'api-account-identities': ResourceType(
        name='api-account-identities',
        domain='identity',
        mutable=False,
        embeddable=False,
        parent='identities',
    ),
    'hosts': ResourceType(
        name='hosts',
        domain='network',
        mutable=False,
        embeddable=True,
        host=True,
    ),
    'endpoints': ResourceType(
        name='endpoints',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
        create_template={
            "attributes": [],
            "enrollmentMethod": {"ott": True},
            "name": "Name"
        }),
    'edge-routers': ResourceType(
        name='edge-routers',
        domain='network',
        mutable=True,
        embeddable=True,
        no_update_props=['registration'],
        create_responses=["ACCEPTED"],
        host=True,
    ),
    'edge-router-policies': ResourceType(
        name='edge-router-policies',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["OK", "ACCEPTED"],
    ),
    'services': ResourceType(
        name='services',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'service-policies': ResourceType(
        name='service-policies',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'app-wans': ResourceType(
        name='app-wans',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["OK", "ACCEPTED"],
        parent='service-policies',
    ),
    'service-edge-router-policies': ResourceType(
        name='service-edge-router-policies',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'posture-checks': ResourceType(
        name='posture-checks',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'certificate-authorities': ResourceType(
        name='certificate-authorities',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'config-types': ResourceType(
        name='config-types',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'configs': ResourceType(
        name='configs',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'terminators': ResourceType(
        name='terminators',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
}

# TODO: [MOP-13441] associate locations with a short list of major geographic regions / continents
MAJOR_REGIONS = {
    "AWS": {
        "Americas": ("Canada Central", "N. California", "N. Virginia", "Ohio", "Oregon", "Sao Paulo"),
        "EuropeMiddleEastAfrica": ("Bahrain", "Cape Town South Africa", "Frankfurt", "Ireland", "London", "Milan", "Paris", "Stockholm"),
        "AsiaPacific": ("Hong Kong", "Mumbai", "Seoul", "Singapore", "Sydney", "Tokyo")
    }
}

DC_PROVIDERS = ["AWS", "AZURE", "GCP", "OCP"]
VALID_SERVICE_PROTOCOLS = ["tcp", "udp"]
VALID_SEPARATORS = '[:-]'  # : or - will match regex pattern


def docstring_parameters(*args, **kwargs):
    """Part a method's __doc__ string with format()."""
    def decorated(ref):
        ref.__doc__ = ref.__doc__.format(*args, **kwargs)
        return ref
    return decorated


RETRY_STRATEGY = Retry(
    total=3,
    status_forcelist=[413, 429, 503],
    method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"],
    backoff_factor=1
)
DEFAULT_TIMEOUT = 31  # seconds, Gateway Service waits 30s before responding with an error code e.g. 503 and
# so waiting at least 31s is necessary to obtain that information


class TimeoutHTTPAdapter(HTTPAdapter):
    """Configure Python requests library to have retry and timeout defaults."""

    def __init__(self, *args, **kwargs):
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


http = Session()
# Mount it for both http and https usage
adapter = TimeoutHTTPAdapter(timeout=DEFAULT_TIMEOUT, max_retries=RETRY_STRATEGY)
http.mount("https://", adapter)
http.mount("http://", adapter)
STATUS_CODES = status_codes
DEFAULT_TOKEN_EXPIRY = 3600


class LookupDict(dict):
    """Helper class to create a lookup dictionary from a set."""

    def __init__(self, name=None):
        """Initialize a lookup dictionary."""
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return f"<lookup '{self.name}'>"

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


ENVIRONMENTS = ['production', 'staging', 'sandbox']
DEFAULT_PAGE_SIZE = 1000
