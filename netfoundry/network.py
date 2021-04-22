import json                 # 
import requests             # HTTP user agent will not emit server cert warnings if verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re                   # regex
from uuid import UUID       # validate UUIDv4 strings
import time                 # enforce a timeout; sleep
import sys

from .utility import MAJOR_REGIONS, RESOURCES, eprint, plural, singular

class Network:
    """describe and use a Network
    """
    def __init__(self, NetworkGroup: object, network_id: str=None, network_name: str=None):
        """
        :param NetworkGroup: required object of the parent Network Group of this Network
        :param network_name: optional name of the network to describe and use
        :param network_id: optional UUID of the network to describe and use
        """
        self.session = NetworkGroup.session

        if network_id:
            self.describe = self.get_network_by_id(network_id)
        elif network_name:
            self.describe = self.get_network_by_name(name=network_name,group=NetworkGroup.id)
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
        for geo in MAJOR_REGIONS['AWS'].keys():
            self.aws_geo_regions[geo] = [dc for dc in self.get_edge_router_data_centers(provider="AWS") if dc['locationName'] in MAJOR_REGIONS['AWS'][geo]]

    def endpoints(self):
        return(self.get_resources("endpoints"))

    def edge_routers(self, only_hosted: bool=False, only_customer: bool=False):
        all_edge_routers = self.get_resources("edge-routers")
        if only_hosted and only_customer:
            raise Exception("ERROR: specify only one of only_hosted or only_customer")
        elif only_hosted:
#            hosted_edge_routers = [er for er in all_edge_routers if 'host' in er.keys() and 'dataCenterId' in er['host'].keys() and er['host']['dataCenterId']]
            hosted_edge_routers = [er for er in all_edge_routers if er['dataCenterId']]
            return(hosted_edge_routers)
        elif only_customer:
#            customer_edge_routers = [er for er in all_edge_routers if not 'host' in er.keys() or not 'dataCenterId' in er['host'].keys() or not er['host']['dataCenterId']]
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
            
    def get_resource(self, type: str, id: str, accept: str=None):
        """return an object describing an entity
        :param type: required string of the singular of an entity type e.g. network, endpoint, service, edge-router, edge-router-policy, posture-check
        :param id: the UUID of the entity if not a network
        :param: accept: optional modifier string specifying the form of the desired response. Choices ["create","update"] where
                "create" is useful for comparing an existing entity to a set of properties that are used to create the same type of
                entity in a POST request, and "update" may be used in the same way for a PUT update.
        """

        # to singular if plural
        if type[-1] == "s":
            type = singular(type)

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            if accept and accept in ["create", "update"]:
                headers['accept'] = "application/json;as="+accept
            elif accept:
                raise Exception("ERROR: invalid value for param \"accept\" in {}".format(accept))
            entity_url = self.session.audience+'core/v2/'+plural(type)+'/'+id
            params = dict()
            if not type == "network":
                params["networkId"] = self.id
            # if type == "service": 
            #     params["beta"] = ''

            if not plural(type) in RESOURCES.keys():
                raise Exception("ERROR: unknown type \"{singular}\" as plural \"{plural}\". Choices: {choices}".format(
                    singular=type,
                    plural=plural(type),
                    choices=RESOURCES.keys()
                ))

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

    def get_resources(self, type: str,name: str=None, accept: str=None, deleted: bool=False):
        """return the resources object
        :param: type: required string of the plural of an entity type e.g. networks, endpoints, services, posture-checks, etc...
        :param: name: optional string of the unique name of an entity to find
        :param: accept: optional modifier string specifying the form of the desired response. Choices ["create","update"] where
                "create" is useful for comparing an existing entity to a set of properties that are used to create the same type of
                entity in a POST request, and "update" may be used in the same way for a PUT update.
        :param: deleted: optional bool to include resource entities that have a non-null property deletedAt
        """

        # pluralize if singular
        if not type[-1] == "s":
            type = plural(type)

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            if accept and accept in ["create", "update"]:
                headers['accept'] = "application/json;as="+accept
            elif accept:
                raise Exception("ERROR: invalid value for param \"accept\" in {}".format(accept))
            params = {
                "networkId": self.id,
                "page": 0,
                "size": 100,
                "sort": "name,asc"
            }
            # if type == "services": 
            #     params["beta"] = ''

            if name is not None:
                params['name'] = name

            if not type in RESOURCES.keys():
                raise Exception("ERROR: unknown type \"{}\". Choices: {}".format(type, RESOURCES.keys()))

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
            all_pages = resources['_embedded'][RESOURCES[type]['embedded']]
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

        # omit deleted entities by default
        if not deleted:
            return([entity for entity in all_pages if not entity['deletedAt']])
        else:
            return(all_pages)

    def patch_resource(self,patch):
        """returns a resource
            :patch: required dictionary with changed properties and _links.self.href
        """

        headers = {
            "authorization": "Bearer " + self.session.token,
            "content-type": "application/json;as=create"
        }

        self_link = patch['_links']['self']['href']
        try:
            before_response = requests.get(
                self_link,
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

        headers = {
            "authorization": "Bearer " + self.session.token
        }

        # attempt to update if there's at least one difference between the current resource and the submitted patch
        if len(pruned_patch.keys()) > 0:
            if not "name" in pruned_patch.keys():
                pruned_patch["name"] = before_resource["name"]
            # if entity is a Service and "model" is patched then always include "modelType"
            if "/services" in self_link and not "modelType" in pruned_patch.keys() and "model" in pruned_patch.keys():
                pruned_patch["modelType"] = before_resource["modelType"]
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

    def create_endpoint(self, name: str, attributes: list=[], session_identity: str=None):
        """create an Endpoint
        :param: name is required string on which to key future operations for this Endpoint
        :param: attributes is an optional list of Endpoint roles of which this Endpoint is a member
        :param: session_identity is optional string UUID of the identity in the NF Organization for
                which a concurrent web console session is required to activate this Endpoint
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

            if session_identity:
                body['sessionIdentityId'] = session_identity

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

    def create_service(self, name: str, client_host_name: str, client_port: int, server_host_name: str=None, 
        server_port: int=None, server_protocol: str="tcp", attributes: list=[], edge_router_attributes: list=["#all"], 
        egress_router_id: str=None, endpoints: list=[], encryption_required: bool=True):
        """create a Service that is compatible with broadly-compatible Ziti config types ziti-tunneler-client.v1, ziti-tunneler-server.v1

        There are three hosting strategies for a Service: SDK, Tunneler, or Router.

        If server details are absent then the type is inferred to be SDK (Service is hosted by a Ziti SDK,
        not a Tunneler or Router). If server details are present then the Service is either hosted by a
        Tunneler or Router, depending on which value is present i.e. Tunneler Endpoint or Edge Router.

        Multiple client intercepts may be specified i.e. lists of domain names or IP addresses, ports, and protocols. If alternative 
        server details are not given they are assumed to be the same as the intercept. If server details are provided then all intercepts 
        flow to that server.

        :param: name is required string
        :param: client_host_name is required strings that is the intercept hostname (DNS) or IPv4
        :param: client_port is required integer of the ports to intercept
        :param: client_protocol is required string of the transport protocol. Choices: ["tcp","udp"]
        :param: server_host_name is optional string that is a hostname (DNS) or IPv4. If omitted Service is assumed to be SDK-hosted (not Tunneler or Router-hosted).
        :param: server_port is optional integer of the server port. If omitted the client port is used. 
        :param: server_protocol is optional string of the server protocol. If omitted the same client protocol is used.
        :param: attributes is optional list of strings of Service roles to assign. Default is [].
        :param: edge_router_attributes is optional list of strings of Router roles or Router names that can "see" this Service. Default is ["#all"].
        :param: egress_router_id is optional string of UUID or name of hosting Router. Selects Router-hosting strategy.
        :param: endpoints is optional list of strings of hosting Endpoints. Selects Endpoint-hosting strategy.
        :param: encryption_required is optional Boolean. Default is to enable edge-to-edge encryption.
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
                        "port": client_port,
                    },
                    "edgeRouterAttributes" : edge_router_attributes
                },
                "attributes" : attributes,
            }
            # resolve exit hosting params
            if not server_host_name:
                body['modelType'] = "TunnelerToSdk"
                if server_port:
                    eprint("WARN: ignoring unexpected server details for SDK-hosted Service")
            else:
                server_egress = {
                    "protocol": server_protocol.lower(),
                    "host": server_host_name,
                    "port": server_port if server_port else client_port
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
            params = dict()
            # params = {
            #     "beta": ''
            # }

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

    def create_endpoint_service(self, name: str, endpoints: list, client_host_names: list, client_port_ranges: list, client_protocols: list=["tcp"], 
        server_host_name: str=None, server_port: str=None, server_protocol: str=None, attributes: list=[], 
        edge_router_attributes: list=["#all"], encryption_required: bool=True, dry_run: bool=False):
        """create an Endpoint-hosted Service compatible with Ziti config types intercept.v1, host.v1.

        Multiple client intercepts may be specified i.e. lists of domain names or IP addresses, ports, and protocols. If alternative 
        server details are not given they are assumed to be the same as the intercept. If server details are provided then all intercepts 
        flow to that server.

        :param: name is required string
        :param: client_host_names is required list of strings that are intercept hostnames (DNS) or IPv4
        :param: client_port_ranges is required list of strings of the port ranges to intercept as ["80","5900:5999"]
        :param: client_protocols is required list of strings of the transports. Choices: ["tcp","udp", "sctp"]
        :param: server_hostname is optional string that is a hostname (DNS) or IPv4. If omitted the client hostname is used.
        :param: server_port is optional string of the server port. If omitted the same client port is used. 
        :param: server_protocol is optional string of the server protocol. If omitted the same client protocol is used.
        :param: attributes is optional list of strings of Service roles to assign. Default is [].
        :param: edge_router_attributes is optional list of strings of Router roles or Router names that can "see" this Service. Default is ["#all"].
        :param: endpoints is optional list of strings of hosting Endpoints.
        :param: encryption_required is optional Boolean. Default is to enable edge-to-edge encryption.
        :param: dry_run is optional Boolean where True returns the entity model without sending a request.
        """
        try:
            # validate roles
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception('ERROR: invalid role "{:s}". Must begin with "#"'.format(role))

            # these elements could be a single port as integer or a string with one or two ports separated by a : or -
            separators = re.compile('[:-]')
            valid_range = re.compile('^\d+[:-]\d+$')
            valid_client_port_ranges = list()
            for range in client_port_ranges:
                # if an integer or single port then use same number for low:high
                if isinstance(range, int):
                    range = str(range)+':'+str(range)
                elif not re.search(separators,range):
                    range = range+':'+range
                
                if not re.fullmatch(valid_range, range):
                    raise Exception("ERROR: failed to parse client port range: {}".format(range))

                bounds = re.split(separators, range)
                if not len(bounds) == 2 or int(bounds[0]) > int(bounds[1]):
                    raise Exception("ERROR: failed to find one lower, one higher port for range: {}".format(range))
                else:
                    valid_client_port_ranges.append({"low": bounds[0], "high": bounds[1]})

            # validate client protocols
            valid_client_protocols = list()
            for proto in client_protocols:
                if not proto in ["tcp", "udp", "sctp", "TCP", "UDP", "SCTP"]:
                    raise Exception("ERROR: client intercept protocol \"{}\" is not valid.".format(proto))
                else:
                    valid_client_protocols.append(proto.lower())

            # resolve exit hosting params
            server_egress = dict()
            if server_host_name:
                server_egress["address"] = server_host_name
                server_egress["dialInterceptAddress"] = None
            else:
                server_egress["dialInterceptAddress"] = True
                server_egress["address"] = None

            if server_port:
                server_egress["port"] = server_port
                server_egress["dialInterceptPort"] = None
            else:
                server_egress["dialInterceptPort"] = True
                server_egress["port"] = None

            if server_protocol:
                server_egress["protocol"] = server_protocol
                server_egress["dialInterceptProtocol"] = None
            else:
                server_egress["dialInterceptProtocol"] = True
                server_egress["protocol"] = None

            # parse out the elements in the list of endpoints as one of #attribute, UUID, or resolvable Endoint name
            bind_endpoints = list()
            for endpoint in endpoints:
                if endpoint[0:1] == '#':
                    bind_endpoints.append(endpoint) # is an Endpoint role attribute
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
                        else: bind_endpoints.append('@'+endpoint_name) # is an existing Endpoint's name
                    else:
                        try:
                            name_lookup = self.get_resource(type="endpoint",id=endpoint)
                            endpoint_name = name_lookup['name']
                        except Exception as e:
                            raise Exception('ERROR: Failed to find exactly one hosting Endpoint with ID "{}". Caught exception: {}'.format(endpoint, e))
                        else: bind_endpoints.append('@'+endpoint_name) # is an existing Endpoint's name resolved from UUID

            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            body = {
                "networkId": self.id,
                "name": name,
                "encryptionRequired": encryption_required,
                "modelType": "AdvancedTunnelerToEndpoint",
                "model": {
                    "bindEndpointAttributes": bind_endpoints,
                    "clientIngress" : {
                        "addresses": client_host_names, 
                        "ports": valid_client_port_ranges,
                        "protocols": valid_client_protocols
                    },
                    "serverEgress": server_egress,
                    "edgeRouterAttributes" : edge_router_attributes
                },
                "attributes" : attributes,
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

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

    def get_network_by_name(self,name: str,group: str=None):
        """return exactly one network object
        :param: name required name of the NF network may contain quoted whitespace
        :param: group optional string UUID to limit results by Network Group ID
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            params = {
                "findByName": name
            }
            if group is not None:
                params['findByNetworkGroupId'] = group

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
            # elif type == "service": 
            #     params["beta"] = ''

            entity_url = self.session.audience+'core/v2/'
            if type == 'network':
                entity_url += 'networks/'+self.id
            elif id is None:
                raise Exception("ERROR: entity UUID must be specified if not a network")
            else:
                entity_url += type+'s/'+id

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
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    requests.status_codes._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

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
            params = dict()
            # if type == "service":
            #     params["beta"] = ''

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
