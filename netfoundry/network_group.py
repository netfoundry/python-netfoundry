import json                 # 
import requests             # HTTP user agent will not emit server cert warnings if verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from .utility import RESOURCES, eprint

class NetworkGroup:
    """use a Network Group by name or ID or the first group in the organization
    """
    def __init__(self, Organization: object, network_group_id: str=None, network_group_name: str=None):
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

        self.session = Organization
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

    def get_product_metadata(self):
        """fetch all product metadata
        """
        try:
            response = requests.get(
                self.session.audience+'product-metadata/v2/download-urls.json',
                proxies=self.session.proxies,
                verify=self.session.verify
            )
            response_code = response.status_code
        except:
            raise

        if response_code == requests.status_codes.codes.OK: # HTTP 200
            try:
                product_metadata = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR getting product metadata')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        return (product_metadata)

    def list_product_versions(self, product_metadata: dict={}):
        """find all product version from product metadata
        """
        if product_metadata:
            product_versions = product_metadata.keys()
        else:
            product_metadata = self.get_product_metadata()
            product_versions = product_metadata.keys()

        return (product_versions)

    def find_latest_product_version(self, product_versions: list=[]):
        """find the highest sorted product version number (may be experimental, not stable)
        """
        if not product_versions:
            product_versions = self.list_product_versions()

        from distutils.version import LooseVersion
        return sorted(product_versions, key=LooseVersion)[-1]

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
            product_versions = self.list_product_versions()
            if version == "latest":
                request['productVersion'] = self.find_latest_product_version(product_versions)
            elif version in product_versions:
                request['productVersion'] = version
            elif version == "default":
                pass # do not specify a value for productVersion
            else:
                raise Exception("ERROR: invalid version \"{version}\". Expected one of {product_versions}".format(
                    version=version,
                    product_versions=product_versions))

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

