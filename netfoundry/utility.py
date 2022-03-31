"""Shared helper functions, constants, and classes."""

import json
from json import JSONDecodeError
import logging
import os
from stat import filemode
import re  # regex
#import sys  # open stderr
import time  # enforce a timeout; sleep
import unicodedata  # case insensitive compare in Utility
from dataclasses import dataclass, field
from lib2to3.pgen2 import token
from re import sub
from uuid import UUID  # validate UUIDv4 strings

import inflect  # singular and plural nouns
import jwt
from requests import Session  # HTTP user agent will not emit server cert warnings if verify=False
from requests import status_codes
from requests.exceptions import RequestException
from requests.adapters import HTTPAdapter
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

disable_warnings(InsecureRequestWarning)

p = inflect.engine()
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

def kebab2camel(kebab: str, case: str="lower"):          # "lower" dromedary or "upper" Pascal
    """Convert kebab case to camel case."""
    if not isinstance(kebab, str):
        raise RuntimeError(f"bad arg to kebab2camel {str(kebab)}")
    kebab_words = kebab.split('-')
    camel_words = list()
    if case in ["lower","dromedary"]:
        camel_words.append(kebab_words[0].lower())  # first word is lowercase 
    elif case in ["upper","pascal"]:
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
        raise RuntimeError(f"cache file '{path.__str__()}' not found")
    except JSONDecodeError as e:
        raise RuntimeError(f"failed to parse cache file '{path.__str__()}' as JSON, got {e}")
    except Exception as e:
        raise RuntimeError(f"failed to read cache file '{path.__str__()}', got {e}")
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
        raise RuntimeError(f"unexpect error, got {e}")
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
        raise RuntimeError(f"unexpect error, got {e}")
        
    else:
        if re.match(r'https://cognito-', iss):
            environment = re.sub(r'https://gateway\.([^.]+)\.netfoundry\.io.*',r'\1',claim['scope'])
            logging.debug(f"matched Cognito issuer URL convention, found environment '{environment}'")
        elif re.match(r'.*\.auth0\.com', iss):
            environment = re.sub(r'https://netfoundry-([^.]+)\.auth0\.com.*',r'\1',claim['iss'])
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
        raise jwt.exceptions.PyJWTError("failed to parse bearer token as JWT")
    except Exception as e:
        raise RuntimeError(f"unexpect error parsing JWT, got {e}")
    return claim

def is_jwt(token):
    """If is a JWT then True."""
    try:
        jwt_decode(token)
    except jwt.exceptions.PyJWTError:
        return False
    except Exception as e:
        raise RuntimeError(f"unexpect error parsing JWT, got {e}")
        
    else:
        return True

def is_uuidv4(string: str):
    """Test if string is valid UUIDv4."""
    try: UUID(string, version=4)
    except ValueError:
        return False
    else:
        return True

def eprint(*args, **kwargs):
    """Adapt legacy function to logging."""
    logging.debug(*args, **kwargs)

def get_generic_resource(url: str, headers: dict, proxies: dict=dict(), verify: bool=True, accept: str=None, **kwargs):
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

    try:
        response = http.get(
            url,
            headers=headers,
            params=params,
            proxies=proxies,
            verify=verify,
        )
        status_symbol = STATUS_CODES._codes[response.status_code][0].upper()
        response.raise_for_status()
    except RequestException as e:
        logging.error('unexpected HTTP response code {:s} ({:d}) and response {:s}'.format(
                status_symbol,
                response.status_code,
                response.text))
        raise e
    else:
        
        try:
            resource = response.json()
        except JSONDecodeError as e:
            logging.error("caught exception deserializing HTTP response as JSON")
            raise e
        else:
            return resource, status_symbol

def find_generic_resources(url: str, headers: dict, embedded: str=None, proxies: dict=dict(), verify: bool=True, accept: str=None, **kwargs):
    """
    Generate each page of a type of resource.

    :param url: the full URL to get
    :param headers: authorization and accept headers
    :param embedded: the key under '_embedded' where the list of resources for this type is found (e.g. 'networkList')
    :param proxies: Requests proxies dict
    :param verify: Requests verify bool is off if proxies enabled in this lib
    :param kwargs: additional query params are typically logical AND if supported or ignored by the API if not
    """
    get_all_pages = True
    params = dict()
    for param in kwargs.keys():
        params[param] = kwargs[param]
    if not params.get('sort'):
        params["sort"] = "name,asc"
    if params.get('size'):
        get_all_pages = False
    else:
        if '/data-centers' in url:
            params['size'] = 3000 # workaround last page bug in MOP-17993
        elif '/identity' in url:  # workaround sort param bug in MOP-18018
            del params['sort']
        elif '/hosts' in url:     # workaround sort param bug in MOP-17863
            del params['sort']
        elif '/networks' in url:     # workaround sort param bug in MOP-17863
            if params.get('name'):
                params['findByName'] = params.get('name')
                del params['name']
        else:
            params['size'] = DEFAULT_PAGE_SIZE
    if params.get('page'):
        get_all_pages = False
    else:
        params['page'] = 0
    if accept:
        if accept in ["create", "update"]:
            headers['accept'] = "application/json;as="+accept
        else:
            logging.warn("ignoring invalid value for header 'accept': '{:s}'".format(accept))

    try:
        response = http.get(
            url,
            headers=headers,
            params=params,
            proxies=proxies,
            verify=verify,
        )
        status_symbol = STATUS_CODES._codes[response.status_code][0].upper()
        response.raise_for_status()
    except RequestException as e:
        logging.error('unexpected HTTP response code {:s} ({:d}) and response {:s}'.format(
                status_symbol,
                response.status_code,
                response.text))
        raise e
    else:
        try:
            resource_page = response.json()
        except JSONDecodeError as e:
            logging.error("caught exception deserializing HTTP response as JSON")
            raise e
        else:
            if isinstance(resource_page, dict) and resource_page.get('page'):
                try:
                    total_pages = resource_page['page']['totalPages']
                    total_elements = resource_page['page']['totalElements']
                except KeyError as e:
                    raise RuntimeError(f"got 'page' key in HTTP response but missing expected sub-key: {e}")
                else:
                    if total_elements == 0:
                        yield_page = list() # delay yielding until end of flow
                    else:
                        if embedded: # function param 'embedded' specifies the reference in which the collection of resources should be found
                            try:
                                yield_page = resource_page['_embedded'][embedded]
                            except KeyError as e:
                                raise RuntimeError(f"failed to find embedded collection in valid JSON response at '_embedded.{embedded}', got: '{e}'")

                    # yield first, only, and empty pages
                    yield yield_page
                    
                    # then yield subsequent pages, if applicable
                    if get_all_pages: # this is False if param 'page' or 'size' to stop recursion or get a single page
                        for next_page in range(1,total_pages): # first page is 0
                            params['page'] = next_page
                            try:
                                # recurse
                                yield from find_generic_resources(url=url, headers=headers, embedded=embedded, proxies=proxies, verify=verify, **params)
                            except Exception as e:
                                raise RuntimeError(f"failed to get page {next_page} of {total_pages}, got {e}'")
            else:
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


NETWORK_RESOURCES = dict()
MUTABLE_NETWORK_RESOURCES = dict()
MUTABLE_RESOURCE_ABBREVIATIONS = dict()
EMBEDDABLE_NETWORK_RESOURCES = dict()
RESOURCE_ABBREVIATIONS = dict()
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
    domain: str                                             # most are in network, organization
    mutable: bool                                           # createable, editable, or deletable
    embeddable: bool                                        # legal to request embedding in a parent resource in same domain
    _embedded: str = field(default='default')               # the key under which lists are found in the API e.g. networkControllerList 
                                                            #   (computed if not provided as dromedary case singular)
    create_responses: list = field(default_factory=list)    # expected HTTP response codes for create operation
    no_update_props: list = field(default_factory=list)     # expected HTTP response codes for create operation    
    create_template: dict = field(default_factory=lambda: {
        'hint': "No template was found for this resource type. Replace the contents of this buffer with the request body as YAML or JSON to create a resource. networkId will be added automatically."
    })                                                      # object to load when creating from scratch in nfctl
    abbreviation: str = field(default='default')

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
        if RESOURCE_ABBREVIATIONS.get(self.abbreviation):
            raise RuntimeError(f"abbreviation collision for {self.name} ({self.abbreviation})")
        else:
            RESOURCE_ABBREVIATIONS[self.abbreviation] = self
        if self.domain == 'network':
            NETWORK_RESOURCES[self.name] = self
            if self.embeddable:
                EMBEDDABLE_NETWORK_RESOURCES[self.name] = self
            if self.mutable:
                MUTABLE_NETWORK_RESOURCES[self.name] = self
                MUTABLE_RESOURCE_ABBREVIATIONS[self.abbreviation] = self
        return super().__post_init__()

RESOURCES = {
    'data-centers': ResourceType(
        name='data-centers',
        domain='network',
        _embedded='dataCenters',      # TODO: raise a bug report because this inconcistency forces consumers to make an exception for this type
        mutable=False,
        embeddable=False,
    ),
    'organizations': ResourceType(
        name='organizations',
        domain='organization',
        mutable=False,
        embeddable=False,
    ),
    'network-groups': ResourceType(
        name='network-groups',
        domain='network-group',
        _embedded='organizations',    # TODO: prune this exception when groups migrate to the Core network domain
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
    ),
    'identities': ResourceType(
        name='identities',
        domain='organization',
        mutable=False,              # TODO: C_UD not yet implemented here in client for org domain
        embeddable=False,           # TODO: embedding not yet implemented in API for org domain
    ),
    'hosts': ResourceType(
        name='hosts',
        domain='network',
        mutable=False,
        embeddable=True,
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
    ),
    'edge-router-policies': ResourceType(
        name='edge-router-policies',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["OK", "ACCEPTED"],
    ),
    'app-wans': ResourceType(
        name='app-wans',
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
    )
}

# TODO: [MOP-13441] associate locations with a short list of major geographic regions / continents
MAJOR_REGIONS = {
    "AWS" : {
        "Americas": ("Canada Central","N. California","N. Virginia","Ohio","Oregon","Sao Paulo"),
        "EuropeMiddleEastAfrica": ("Bahrain","Cape Town South Africa","Frankfurt","Ireland","London","Milan","Paris","Stockholm"),
        "AsiaPacific": ("Hong Kong","Mumbai","Seoul","Singapore","Sydney","Tokyo")
    }
}

DC_PROVIDERS = ["AWS", "AZURE", "GCP", "OCP"]
RESOURCE_STATUSES = ["PROVISIONED", "PROVISIONING", "DELETED", "DELETING", "FINISHED", "STARTED"]
VALID_SERVICE_PROTOCOLS = ["tcp", "udp"]
VALID_SEPARATORS = '[:-]' # : or - will match regex pattern

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

DEFAULT_TIMEOUT = 31 # seconds, Gateway Service waits 30s before responding with an error code e.g. 503 and
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

ENVIRONMENTS = ['production','staging','sandbox']

DEFAULT_PAGE_SIZE = 1000