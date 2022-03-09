#!/usr/bin/env python
"""
MOP API Base class to handle API token generation from credentials.json file.
"""
import json
import sys
from base64 import b64encode
from os import R_OK, access, environ, path
from urllib import parse, request

import jwt
import keyring
from jwt import PyJWKClient


class NFAPIClient:
    """
    Helper class to fomulate NetFoundry API HTTP requests.

    :param url: An API resource URL
    :param data: Data to be sent as part of the request.
    :param token: A Bearer token used to authorize the request.
    :param auth: base64 encoded username and password for basic auth.

    .. note: The `token` and `auth` params are mutually exlusive. In
        general, we pass `auth` when we want to authenticate against the
        API to generate a bearer token for future requests. We use `token`
        to run API resource requests using a Bearer token.
    """
    def __init__(self, url, data=None, token=None, auth=None, query_string={}):
        self._url = url
        if data is not None:
            self._data = parse.urlencode(data).encode('ascii')
        else:
            self._data = data
        self._token = token
        self._auth = auth
        assert not (token is not None and auth is not None)

        if query_string:
            self._query_string = "&".join([f"{k}={query_string[k]}" for k in
                                           query_string])
        else:
            self._query_string = query_string

    def _run_request(self, page=None):
        if self._query_string:
            if page is not None:
                request_url = self._url + f'?{self._query_string}&page={page}'
            else:
                request_url = self._url + f'?{self._query_string}'
        else:
            if page is not None:
                request_url = self._url + f'?page={page}'
            else:
                request_url = self._url

        req = request.Request(request_url, data=self._data)

        if self._token is not None:
            req.add_header("Authorization", f"Bearer {self._token}")

        if self._auth is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("Authorization", f"Basic {self._auth}")

        with request.urlopen(req) as reqst:
            resp_headers = reqst.info()
            response = reqst.read()
        content_charset = resp_headers.get_content_charset() or 'utf-8'
        return json.loads(response.decode(content_charset))

    def get_response(self):
        """Run the HTTP request embodied in the class."""
        response = self._run_request()
        paging = response.get('page')
        if paging:
            r_size = paging.get('size')
            if r_size is None and not isinstance(r_size, int):
                raise RuntimeError('Unexpected API paging scheme. Aborting.')
            if not r_size > 0:
                raise ValueError(
                        'Reponse devoid of content. '
                        + 'Check API account permissions.')
        yield response
        if paging:
            page_start = paging.get('number')
            pages = paging.get('totalPages')

            if (page_start is None and not isinstance(page_start, int)) or \
                    (pages is None and not isinstance(pages, int)):
                raise RuntimeError('Unexpected API paging scheme. Aborting.')

            next_page = page_start + 1
            while next_page < pages + page_start:
                fetch_page = next_page
                next_page += 1
                yield self._run_request(page=fetch_page)

    @staticmethod
    def encode_auth(username, password):
        """
        Return a base64 encoded authentication string for use in
        the `Basic` authentication header.

        :param username: API account user
        :param password: API account password
        :return: base64 encoded string
        """
        return b64encode(bytes(f"{username}:{password}",
                         'ascii')).decode('utf-8')


class NFAPICredentials:
    """
      Helper class to handle credentials file discovery and parsing.

      :param creds_file: Path to credentials file on file system. If not
          provided, creds_file will be discovered, if possible.

      :raises FileNotFoundError: when either the supplied credentials file
          cannot be loaded or credential discovery fails.
    """
    def __init__(self, creds_file=None):
        if creds_file is not None:
            if self.test_file(creds_file):
                self._creds_file = creds_file
            else:
                raise FileNotFoundError(
                        f"'{creds_file}' is not a file or is not readable.")
        else:
            self._creds_file = self.discover_creds_file()

        self.creds = self._load_creds()
        self._password = self.creds['password']
        self.client_id = self.creds['clientId']
        self.url = self.creds['authenticationUrl']
        self.env = self.url.split('-')[1]
        self.auth = NFAPIClient.encode_auth(self.client_id, self._password)

    def _load_creds(self):
        try:
            with open(self._creds_file, 'r') as creds_file:
                creds = json.load(creds_file)
        except Exception:
            print("Unexepected error:", {sys.exc_info()[0]})
            raise
        else:
            return creds

    @staticmethod
    def discover_creds_file():
        """
        Helper function to discover credentials file from NetFoundry standard
        paths.

        :return: Path to discovered credentials file.
        """
        creds_filename = 'credentials.json'
        creds_paths = [
                './',
                path.expanduser('~') + '/.netfoundry/',
                '/netfoundry/'
            ]
        creds_files = [creds_path + creds_filename for creds_path in
                       creds_paths]
        netfoundry_api_account = ''
        try:
            creds_envar = environ["NETFOUNDRY_API_ACCOUNT"]
        except KeyError:
            for creds_file in creds_files:
                if NFAPICredentials.test_file(creds_file):
                    netfoundry_api_account = creds_file
                    break
            if not netfoundry_api_account:
                raise FileNotFoundError(
                    "No credentials file found. File search space: "
                    + str(creds_files) +
                    " Alternatively, supply path to credentials via " +
                    "NETFOUNDRY_API_ACCOUNT environment variable.") from None
        else:
            if NFAPICredentials.test_file(creds_envar):
                netfoundry_api_account = creds_envar
            else:
                raise FileNotFoundError(
                    "File from NETFOUNDRY_API_ACCOUNT not found or bad perms.")
        return netfoundry_api_account

    @staticmethod
    def test_file(file):
        """
        Helper function used to test a credentials file for existance and
        access rights.

        :param file: A file path to test

        :return: Boolean indicating whether file exists and is accessible.
        """
        return path.isfile(file) and access(file, R_OK)


class NFAPIToken:
    """
    Helper class to generate and cache API tokens.

    .. note: Credentials are only cached when the `keyring` python module can
        detect a valid backend. Currently, Windows, MacOS, and Linux are
        supported when running using this module in the context of the
        operating system. If no backend is found, a new token is generated each
        time.
    """
    keyring_service = 'nfapi'
    keyring_secret = 'token'
    leeway = -10.0

    def __init__(self, creds_file=None):
        self._keyring = self.get_keyring()
        self._creds_file = creds_file
        self.credentials = NFAPICredentials(self._creds_file)
        self.token = self.get_token()
        self.token_header = jwt.get_unverified_header(self.token)
        self.token_data = self.decode_token()

    @classmethod
    def from_creds_file(cls, creds_file):
        """
        Alternate class contructor which relies on a user supplied credentials
        file path to instantiate the `NFAPIClient` object.

        :param creds_file: Path to credentials.json file.
        """
        return cls(creds_file=creds_file)

    @property
    def keyring(self):
        """Getter method for the credentials keyring object."""
        return self._keyring

    @staticmethod
    def get_keyring():
        """Returns the current keyring"""
        return keyring.get_keyring()

    def get_token(self):
        """
        Returns the token found in the keyring, if valid, or returns a newly
        generated token.
        """
        try:
            token = self.keyring.get_password(
                    self.keyring_service, self.keyring_secret)
        except keyring.errors.NoKeyringError:
            token = self.gen_token()
            return token
        else:
            if token is not None and self.verify_token(token):
                return token
            token = self.gen_token()
            return token

    def verify_token(self, token):
        """
        Helper method to determine if a token is valid or not.

        :param token: A JWT token

        :return: True if `token` verfied, else False
        """
        jwt_header = jwt.get_unverified_header(token)
        jwt_algs = [jwt_header['alg']]

        try:
            unverified_token = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": True},
                    leeway=self.leeway, algorithms=jwt_algs)
        except jwt.ExpiredSignatureError:
            return False
        else:
            if self.credentials.client_id != unverified_token['client_id']:
                return False

            validate_result = self.validate_token_sig(
                    token, unverified_token,
                    leeway=self.leeway, algorithms=jwt_algs)
            if not validate_result:
                return False
        return True

    @staticmethod
    def validate_token_sig(token, unverified_token, leeway=0.0, algorithms=None):
        """
        Helper function which validate a JWTs signature

        :param token: A JWT token
        :param unverified_token: The `token` argument, decoded without
            verification or expiration checks.
        :param leeway: Forwaded to JWT decoder, used to give a window of time
            around when a token is considered invalid.
        :param algorithms: List of algorithms to try to decode with.

        :return: True if signature could be validated, else False
        """
        if algorithms is None:
            jwt_header = jwt.get_unverified_header(unverified_token)
            algorithms = [jwt_header['alg']]

        jwks_path = '/.well-known/jwks.json'
        jwt_iss = unverified_token['iss']
        jwks_client = PyJWKClient(jwt_iss + jwks_path)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        try:
            jwt.decode(
                    token, signing_key.key, leeway=leeway,
                    algorithms=algorithms)
        except Exception:
            return False
        else:
            return True

    def gen_token(self):
        """Helper method to generate a JWT token via the NF API."""
        auth = self.credentials.auth
        url = self.credentials.url
        env = self.credentials.env
        scope = f"https://gateway.{env}.netfoundry.io//ignore-scope"
        assertion = {
            "scope": scope,
            "grant_type": "client_credentials"
        }

        token_dict = next(NFAPIClient(url, data=assertion,
                          auth=auth).get_response())
        token = token_dict['access_token']

        if self.verify_token(token):
            try:
                self.keyring.set_password(
                        self.keyring_service, self.keyring_secret, token)
            except keyring.errors.NoKeyringError:
                pass

            return token

        raise RuntimeError("Could not validate generated token.")

    def decode_token(self):
        """Helper method to decode token"""
        return jwt.decode(
                self.token, options={"verify_signature": False},
                algorithms=[self.token_header['alg']])
