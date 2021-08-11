import json
import re  # regex
import sys
import time
from unicodedata import name  # enforce a timeout; sleep
from uuid import UUID  # validate UUIDv4 strings

from .utility import (EXCLUDED_PATCH_PROPERTIES, HOST_PROPERTIES,
                      MAJOR_REGIONS, RESOURCES, STATUS_CODES, VALID_SEPARATORS,
                      VALID_SERVICE_PROTOCOLS, docstring_parameters, eprint,
                      http, plural, singular)


class Network:
    """Describe and use a Network."""

    def __init__(self, NetworkGroup: object, network_id: str=None, network_name: str=None):
        """Initialize Network.
        
        :param obj NetworkGroup: required parent Network Group of this Network
        :param str network_name: optional name of the network to describe and use
        :param str network_id: optional UUID of the network to describe and use
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

    def endpoints(self, typeId: str=None):
        if typeId is not None:
#            import epdb; epdb.serve()
            return(self.get_resources(type="endpoints", typeId=typeId))
        else:
            return(self.get_resources(type="endpoints"))

    def edge_routers(self, only_hosted: bool=False, only_customer: bool=False):
        all_edge_routers = self.get_resources("edge-routers")
        if only_hosted and only_customer:
            raise Exception("ERROR: specify only one of only_hosted or only_customer")
        elif only_hosted:
            hosted_edge_routers = [er for er in all_edge_routers if 'dataCenterId' in er.keys() and er['dataCenterId']]
            return(hosted_edge_routers)
        elif only_customer:
            customer_edge_routers = [er for er in all_edge_routers if not 'dataCenterId' in er.keys() or not er['dataCenterId']]
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

    @docstring_parameters(valid_separators=VALID_SEPARATORS)
    def validate_port_ranges(self, ports: list):
        """
        return a validated list of low, high ranges matching the expected format when supplied a list of candidate ports and ranges
        like [80, "8000:8002", "8443-8444"]

        :param list ports: required list of integers or strings that are each a single port (int or str) or low:high range of ports separated by a character matching regex /{valid_separators}/

        """

        # these elements could be a single port as integer or a string with one or two ports separated by a valid separator character
        separators = re.compile(VALID_SEPARATORS)
        valid_range = re.compile('^\d+'+VALID_SEPARATORS+'\d+$')
        valid_port_ranges = list()
        for range in ports:
            if isinstance(range, int): # if an integer or single port then use same number for low:high
                range = str(range)+':'+str(range)
            elif not re.search(separators,range): # if a string of a single port (no separator) then cat with separator :
                range = range+':'+range
            
            if not re.fullmatch(valid_range, range):
                raise Exception("ERROR: failed to parse client port range: {}".format(range))

            bounds = re.split(separators, range)
            if not len(bounds) == 2 or int(bounds[0]) > int(bounds[1]):
                raise Exception("ERROR: failed to find one lower, one higher port for range: {}".format(range))
            else:
                valid_port_ranges.append({"low": int(bounds[0]), "high": int(bounds[1])})

        return(valid_port_ranges)

    @docstring_parameters(resource_entity_types=str(RESOURCES.keys()))
    def validate_entity_roles(self, entities: list, type: str):
        """
        return a list of valid, existing entities and hashtag role attributes when supplied a list of candidate hashtag role attributes or existing entity identitifiers 
        and use the validated list anywhere that Ziti entity roles are used e.g. list of endpoints in an AppWAN, list of routers in an ERP

        :param list entities: required hashtag role attributes, existing entity @names, or existing entity UUIDs
        :param str type: required type of entity: one of {resource_entity_types}

        """
        valid_entities = list()
        for entity in entities:
            if entity[0:1] == '#':
                valid_entities.append(entity) # is a hashtag role attribute
            else:
                # strip leading @ if present and re-add later after verifying the named entity exists
                if entity[0:1] == '@':
                    entity = entity[1:]

                # if UUIDv4 then resolve to name, else verify the named entity exists 
                try:
                    UUID(entity, version=4) # assigned below under "else" if already a UUID
                except ValueError:
                    # else assume is a name and resolve to ID
                    try: 
                        name_lookup = self.get_resources(type=plural(type),name=entity)[0]
                        entity_name = name_lookup['name']
                    except Exception as e:
                        raise Exception('ERROR: Failed to find exactly one {type} named "{name}". Caught exception: {e}'.format(type=singular(type), name=entity, e=e))
                    # append to list after successfully resolving name to ID
                    else: valid_entities.append('@'+entity_name) # is an existing entity's name
                else:
                    try:
                        name_lookup = self.get_resource(type=singular(type),id=entity)
                        entity_name = name_lookup['name']
                    except Exception as e:
                        raise Exception('ERROR: Failed to find exactly one {type} with ID "{id}". Caught exception: {e}'.format(type=singular(type), id=entity, e=e))
                    else: valid_entities.append('@'+entity_name) # is an existing endpoint's name resolved from UUID
        return(valid_entities)

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
            response = http.get(
                self.session.audience+'core/v2/data-centers',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                data_centers = json.loads(response.text)['_embedded']['dataCenters']
            except ValueError as e:
                eprint('ERROR getting data centers')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )
        if location_code:
            matching_data_centers = [dc for dc in data_centers if dc['locationCode'] == location_code]
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
            response = http.post(
                self.session.audience+'core/v2/endpoints/share',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except:
            raise

        if not response_code == STATUS_CODES.codes['ACCEPTED']:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
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
            # if singular(type) == "service": 
            #     params["beta"] = ''

            if not plural(type) in RESOURCES.keys():
                raise Exception("ERROR: unknown type \"{singular}\" as plural \"{plural}\". Choices: {choices}".format(
                    singular=type,
                    plural=plural(type),
                    choices=RESOURCES.keys()
                ))
            elif plural(type) == "edge-routers":
                params['embed'] = "host"

            response = http.get(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK:
            try:
                entity = json.loads(response.text)
            except:
                raise Exception('ERROR parsing response as object, got:\n{}'.format(response.text))

        # routers are a special case because the value of entity._embedded.host.dataCenterId is expected by
        # downstream consumers of this method to be found at entity.dataCenterId
        if plural(type) == "edge-routers":
            if (entity["hostId"]
                    and "_embedded" in entity.keys()
                    and "host" in entity['_embedded'].keys()
                ):
                for prop in HOST_PROPERTIES:
                    entity[prop] = entity['_embedded']['host'][prop]
        return(entity)

    def get_resources(self, type: str,name: str=None, accept: str=None, deleted: bool=False, typeId: str=None):
        """return the resources object
        :param str type: plural of an entity type e.g. networks, endpoints, services, posture-checks, etc...
        :param str name: filter results by name
        :param str accept: specifying the form of the desired response. Choices ["create","update"] where
                "create" is useful for comparing an existing entity to a set of properties that are used to create the same type of
                entity in a POST request, and "update" may be used in the same way for a PUT update.
        :param bool deleted: include resource entities that have a non-null property deletedAt
        :param str typeId: filter results by typeId
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
            if typeId is not None:
                params['typeId'] = typeId

            if not type in RESOURCES.keys():
                raise Exception("ERROR: unknown type \"{}\". Choices: {}".format(type, RESOURCES.keys()))
            elif type == "edge-routers":
                params['embed'] = "host"

            response = http.get(
                self.session.audience+'core/v2/'+type,
                proxies=self.session.proxies,
                verify=self.session.verify,
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
            all_entities = resources['_embedded'][RESOURCES[type]['embedded']]
        # if there are multiple pages of resources
        else:
            # initialize the list with the first page of resources
            all_entities = resources['_embedded'][RESOURCES[type]['embedded']]
            # append the remaining pages of resources
            for page in range(1,total_pages):
                try:
                    params["page"] = page
                    response = http.get(
                        self.session.audience+'core/v2/'+type,
                        proxies=self.session.proxies,
                        verify=self.session.verify,
                        headers=headers,
                        params=params
                    )
                    response_code = response.status_code
                except:
                    raise

                if response_code == STATUS_CODES.codes.OK: # HTTP 200
                    try:
                        resources = json.loads(response.text)
                        all_entities.extend(resources['_embedded'][RESOURCES[type]['embedded']])
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

        # omit deleted entities by default
        if not deleted:
            all_entities = [entity for entity in all_entities if not entity['deletedAt']]

        # routers are a special case because the value of entity._embedded.host.dataCenterId is expected by
        # downstream consumers of this method to be found at entity.dataCenterId
        if type == "edge-routers":
            all_routers = list()
            for entity in all_entities:
                if (entity["hostId"]
                        and "_embedded" in entity.keys()
                        and "host" in entity['_embedded'].keys()
                    ):
                    for prop in HOST_PROPERTIES:
                        entity[prop] = entity['_embedded']['host'][prop]
                all_routers.extend([entity])
            return(all_routers)
        else:
            return(all_entities)

    def patch_resource(self,patch):
        """returns a resource
            :patch: required dictionary with changed properties and _links.self.href
        """

        headers = {
            "authorization": "Bearer " + self.session.token,
            "content-type": "application/json"
        }

        self_link = patch['_links']['self']['href']
        type = self_link.split('/')[5]
        if not type in EXCLUDED_PATCH_PROPERTIES.keys():
            raise Exception("ERROR: got unexpected type {:s} for patch request from self URL {:s}".format(
                type, 
                self_link))
        try:
            before_response = http.get(
                self_link,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
            )
            before_response_code = before_response.status_code
        except:
            raise

        if before_response_code in [STATUS_CODES.codes.OK]: # HTTP 200
            try:
                before_resource = json.loads(before_response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from GET response'.format(r = type))
                raise(e)
        else:
            json_formatted = json.dumps(patch, indent=2)
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s} for GET {:s}'.format(
                    STATUS_CODES._codes[before_response_code][0].upper(),
                    before_response_code,
                    before_response.text,
                    json_formatted
                )
            )
        # compare the patch to the discovered, current state, adding new or updated keys to pruned_patch
        pruned_patch = dict()
        for k in patch.keys():
            if k not in EXCLUDED_PATCH_PROPERTIES[type] and k in before_resource.keys() and not before_resource[k] == patch[k]:
                pruned_patch[k] = patch[k]

        headers = {
            "authorization": "Bearer " + self.session.token
        }

        # attempt to update if there's at least one difference between the current resource and the submitted patch
        if len(pruned_patch.keys()) > 0:
            if not "name" in pruned_patch.keys():
                pruned_patch["name"] = before_resource["name"]
            # if entity is a service and "model" is patched then always include "modelType"
            if type == "services" and not "modelType" in pruned_patch.keys() and "model" in pruned_patch.keys():
                pruned_patch["modelType"] = before_resource["modelType"]
            try:
                after_response = http.patch(
                    patch['_links']['self']['href'],
                    proxies=self.session.proxies,
                    verify=self.session.verify,
                    headers=headers,
                    json=pruned_patch
                )
                after_response_code = after_response.status_code
            except:
                raise
            if after_response_code in [STATUS_CODES.codes.OK, STATUS_CODES.codes.ACCEPTED]: # HTTP 202
                try:
                    after_resource = json.loads(after_response.text)
                except ValueError as e:
                    eprint('ERROR: failed to load {r} object from PATCH response'.format(r = type))
                    raise(e)
            else:
                json_formatted = json.dumps(patch, indent=2)
                raise Exception(
                    'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s} for PATCH update {:s}'.format(
                        STATUS_CODES._codes[after_response_code][0].upper(),
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
            response = http.put(
                put['_links']['self']['href'],
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=put
            )
            response_code = response.status_code
        except:
            raise

        if response_code in [STATUS_CODES.codes.OK, STATUS_CODES.codes.ACCEPTED]: # HTTP 202
            try:
                resource = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {r} object from PUT response'.format(r = type))
                raise(e)
        else:
            json_formatted = json.dumps(put, indent=2)
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s} for PUT update {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text,
                    json_formatted
                )
            )
        return(resource)

    def create_endpoint(self, name: str, attributes: list=[], session_identity: str=None, wait: int=30, sleep: int=2, progress: bool=False):
        """create an endpoint
        :param: name is required string on which to key future operations for this endpoint
        :param: attributes is an optional list of endpoint roles of which this endpoint is a member
        :param: session_identity is optional string UUID of the identity in the NF Organization for
                which a concurrent web console session is required to activate this endpoint
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception("ERROR: hashtag role attributes on an endpoint must begin with #")
            body = {
                "networkId": self.id,
                "name": name,
                "attributes": attributes,
                "enrollmentMethod": { "ott": True }
            }

            if session_identity:
                body['sessionIdentityId'] = session_identity

            response = http.post(
                self.session.audience+'core/v2/endpoints',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except:
            raise

        endpoint = None
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['endpoints']['create_responses']):
            try:
                endpoint = json.loads(response.text)
            except ValueError as e:
                raise e('ERROR: failed to load endpoint JSON, got HTTP code {:s} ({:d}) with body {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text)
                )
                    
        else:
            raise Exception('ERROR: got unexpected HTTP code {:s} ({:d}) with body {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text)
            )

        if wait:
            endpoint = self.wait_for_property_defined(property_name="jwt", property_type=str, entity_type="endpoint", id=endpoint['id'], wait=wait, sleep=sleep, progress=progress)
        return(endpoint)

    def create_edge_router(self, name: str, attributes: list=[], link_listener: bool=False, data_center_id: str=None, tunneler_enabled: bool=False, wait: int=30):
        """create an Edge Router
        """
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception("ERROR: hashtag role attributes on an endpoint must begin with #")
            body = {
                "networkId": self.id,
                "name": name,
                "attributes": attributes,
                "linkListener": link_listener,
                "tunnelerEnabled": tunneler_enabled
            }
            if data_center_id:
                body['dataCenterId'] = data_center_id
                body['linkListener'] = True
            response = http.post(
                self.session.audience+'core/v2/edge-routers',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except:
            raise
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['edge-routers']['create_responses']):
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
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        if wait:
            router_complete = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="edge-router", id=router['id'], wait=wait)
            if tunneler_enabled:
                router_endpoint = self.wait_for_entity_name_exists(entity_name=name, entity_type="endpoint", wait=wait)
            return(router_complete)
        else:
            return(router)

    def create_edge_router_policy(self, name: str, endpoint_attributes: list=[], edge_router_attributes: list=[], wait: int=30):
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
            response = http.post(
                self.session.audience+'core/v2/edge-router-policies',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except:
            raise
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['edge-router-policies']['create_responses']):
            try:
                policy = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("Edge Router Policy"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        if wait:
            policy_complete = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="edge-router-policy", id=policy['id'], wait=wait)
            return(policy_complete)
        else:
            return(policy)

    @docstring_parameters(valid_service_protocols=VALID_SERVICE_PROTOCOLS)
    def create_service_simple(self, name: str, client_host_name: str, client_port: int, server_host_name: str=None, 
        server_port: int=None, server_protocol: str="tcp", attributes: list=[], edge_router_attributes: list=["#all"], 
        egress_router_id: str=None, endpoints: list=[], encryption_required: bool=True, wait: int=30):
        """create a service that is compatible with broadly-compatible Ziti config types ziti-tunneler-client.v1, ziti-tunneler-server.v1

        There are three hosting strategies for a service: SDK, Tunneler, or Router.

        If server details are absent then the type is inferred to be SDK (service is hosted by a Ziti SDK,
        not a Tunneler or Router). If server details are present then the service is either hosted by a
        Tunneler or Router, depending on which value is present i.e. Tunneler endpoint or Edge Router.

        Multiple client intercepts may be specified i.e. lists of domain names or IP addresses, ports, and protocols. If alternative 
        server details are not given they are assumed to be the same as the intercept. If server details are provided then all intercepts 
        flow to that server.

        :param: name is required string
        :param: client_host_name is required strings that is the intercept hostname (DNS) or IPv4
        :param: client_port is required integer of the ports to intercept
        :param: client_protocol is required string of the transport protocol. Choices: {valid_service_protocols}
        :param: server_host_name is optional string that is a hostname (DNS) or IPv4. If omitted service is assumed to be SDK-hosted (not Tunneler or Router-hosted).
        :param: server_port is optional integer of the server port. If omitted the client port is used. 
        :param: server_protocol is optional string of the server protocol. If omitted the same client protocol is used.
        :param: attributes is optional list of strings of service roles to assign. Default is [].
        :param: edge_router_attributes is optional list of strings of Router roles or Router names that can "see" this service. Default is ["#all"].
        :param: egress_router_id is optional string of UUID or name of hosting Router. Selects Router-hosting strategy.
        :param: endpoints is optional list of strings of hosting endpoints. Selects endpoint-hosting strategy.
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
                    eprint("WARN: ignoring unexpected server details for SDK-hosted service")
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
                            # strip leading @ if present and re-add later after verifying the named endpoint exists
                            if endpoint[0:1] == '@':
                                endpoint = endpoint[1:]

                            # if UUIDv4 then resolve to name, else verify the named endpoint exists 
                            try:
                                UUID(endpoint, version=4) # assigned below under "else" if already a UUID
                            except ValueError:
                                # else assume is a name and resolve to ID
                                try: 
                                    name_lookup = self.get_resources(type="endpoints",name=endpoint)[0]
                                    endpoint_name = name_lookup['name']
                                except Exception as e:
                                    raise Exception('ERROR: Failed to find exactly one hosting endpoint named "{}". Caught exception: {}'.format(endpoint, e))
                                # append to list after successfully resolving name to ID
                                else: bind_endpoints += ['@'+endpoint_name] 
                            else:
                                try:
                                    name_lookup = self.get_resource(type="endpoint",id=endpoint)
                                    endpoint_name = name_lookup['name']
                                except Exception as e:
                                    raise Exception('ERROR: Failed to find exactly one hosting endpoint with ID "{}". Caught exception: {}'.format(endpoint, e))
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
                    raise Exception('ERROR: invalid service model: need only one of binding "endpoints" or hosting "egress_router_id" if "server_host_name" is specified')
                
            # resolve Edge Router param
            if edge_router_attributes and not edge_router_attributes == ['#all']:
                eprint("WARN: overriding default service Edge Router Policy #all for new service {:s}".format(name))
                body['edgeRouterAttributes'] = edge_router_attributes
            params = dict()
            # params = {
            #     "beta": ''
            # }

            response = http.post(
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
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['services']['create_responses']):
            try:
                service = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("service"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        if wait:
            service_complete = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service", id=service['id'], wait=wait)
            return(service_complete)
        else:
            return(service)

    # the above method was renamed to follow the development of PSM-based services (platform service models)
    create_service = create_service_simple

    def create_service_policy(self, name: str, services: list, endpoints: list, type: str="Bind", semantic: str="AnyOf", posture_checks: list=[], dry_run: bool=False, wait: int=30):
        """
        Create a generic Ziti service policy. AppWANs are Dial-type service policies.

        :param str name: display name of service policy
        :param list services: service @names, UUIDs, or #hashtag service attributes
        :param list endpoints: endpoint @names, UUIDs, or #hashtag endpoint attributes
        :param str type: the policy type, one of Bind, Dial. Default is "Bind".
        :param str semantic: policy semantic, one of AnyOf, AllOf. Default is "AnyOf".
        :param list posture_checks: posture check @names, UUIDs, or #hashtag posture check attributes
        :param bool dry_run: True returns only the entity model without sending a request.
        """
        # parse out the elements in the list of endpoints as one of #attribute, UUID, or resolvable Endoint name
        bind_endpoints = self.validate_entity_roles(endpoints, type="endpoints")
        valid_services = self.validate_entity_roles(services, type="services")
        valid_postures = self.validate_entity_roles(posture_checks, type="posture-checks")
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            body = {
                "networkId": self.id,
                "name":  name,
                "type": type,
                "semantic": semantic,
                "postureCheckAttributes": valid_postures,
                "serviceAttributes": valid_services,
                "endpointAttributes": bind_endpoints
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

            response = http.post(
                self.session.audience+'core/v2/service-policies',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['service-policies']['create_responses']):
            try:
                service_policy = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("service policy"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        if wait:
            service_policy_complete = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service-policy", id=service_policy['id'], wait=wait)
            return(service_policy_complete)
        else:
            return(service_policy)


    def create_service_edge_router_policy(self, name: str, services: list, edge_routers: list, semantic: str="AnyOf", dry_run: bool=False, wait: int=30):
        """
        Create a generic Ziti service edge router policy (SERP). Model-based services auto-create a SERP.

        :param str name: display name of service policy
        :param list services: service @names, UUIDs, or #hashtag service attributes
        :param list edge_routers: router @names, UUIDs, or #hashtag router attributes
        :param str semantic: policy semantic, one of AnyOf, AllOf. Default is "AnyOf".
        :param bool dry_run: True returns only the entity model without sending a request.
        """
        valid_services = self.validate_entity_roles(services, type="services")
        valid_routers = self.validate_entity_roles(edge_routers, type="edge-routers")
        try:
            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            body = {
                "networkId": self.id,
                "name":  name,
                "semantic": semantic,
                "serviceAttributes": valid_services,
                "edgeRouterAttributes": valid_routers
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

            response = http.post(
                self.session.audience+'core/v2/service-edge-router-policies',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['service-edge-router-policies']['create_responses']):
            try:
                service_edge_router_policy = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("service edge router policy"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        if wait:
            service_edge_router_policy_complete = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service-edge-router-policy", id=service_edge_router_policy['id'], wait=wait)
            return(service_edge_router_policy_complete)
        else:
            return(service_edge_router_policy)

    def create_service_with_configs(self, name: str, intercept_config_data: dict, host_config_data: dict, attributes: list=[],
        encryption_required: bool=True, dry_run: bool=False, wait: int=30):
        """create an endpoint-hosted service by providing the raw config data for intercept.v1, host.v1.

        :param: name is required string
        :param: intercept_config_data is a required dict that is the value of the 'data' property for the intercept.v1 config
        :param: host_config_data is a required dict that is the value of the 'data' property for the host.v1 config
        :param: attributes is optional list of strings of service roles to assign, associating the service with a matching AppWAN. Default is [].
        :param: encryption_required is optional Boolean. Default is to enable edge-to-edge encryption.
        :param: dry_run is optional Boolean where True returns only the entity model without sending a request.
        """
        try:
            # validate roles
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception('ERROR: invalid role "{:s}". Must begin with "#"'.format(role))

            headers = { 
                "authorization": "Bearer " + self.session.token 
            }
            body = {
                "networkId": self.id,
                "name": name,
                "encryptionRequired": encryption_required,
                "configs": [
                    {
                        "networkId": self.id,
                        "name": name+"-config-intercept.v1",
                        "configTypeName": "intercept.v1",
                        "data": intercept_config_data
                    },
                    {
                        "networkId": self.id,
                        "name": name+"-config-host.v1",
                        "configTypeName": "host.v1",
                        "data": host_config_data
                    }
                ],
                "attributes" : attributes,
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

            response = http.post(
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

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['services']['create_responses']):
            try:
                service = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("service"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        if wait:
            service_complete = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service", id=service['id'], wait=wait)
            return(service_complete)
        else:
            return(service)

    @docstring_parameters(valid_service_protocols=VALID_SERVICE_PROTOCOLS)
    def create_service_transparent(self, name: str, client_hosts: list, client_ports: list, transparent_hosts: list, client_protocols: list=["tcp"], attributes: list=[],
        endpoints: list=[], edge_routers: list=["#all"], encryption_required: bool=True, dry_run: bool=False):
        """create an endpoint-hosted service where intercepted packets' source and destination are preserved by the terminator when communicating with the server at egress.

        :param str name: name of service
        :param list client_hosts: IPv4/CIDR to intercept.
        :param list client_ports: ports and ranges to intercept as singleton (int or str) or range [22, "80","5900:5999"].
        :param list transparent_hosts: allowed source IPs for terminator to use when masquerading to the server.
        :param list client_protocols: transports to intercept. Choices: {valid_service_protocols}. Default is ["tcp"].
        :param list attributes: service roles to assign, associating the service with a matching AppWAN or service policy. Default is [].
        :param list endpoints: endpoint #hashtag role attributes, @names, and UUIDs that may host this service.
        :param: list edge_routers: edge router #hashtag role attributes, @names, and UUIDs that can "see" this service. Default is ["#all"].
        :param bool encryption_required: Default is to enable edge-to-edge encryption.
        :param bool dry_run: True returns only the entity model without sending a request to create. This is useful for comparing states.
        """
        
        try:


            # validate client protocols
            valid_client_protocols = list()
            for proto in client_protocols:
                if not proto.lower() in VALID_SERVICE_PROTOCOLS:
                    raise Exception("ERROR: transparent protocol \"{}\" is not valid.".format(proto.lower()))
                else:
                    valid_client_protocols.append(proto.lower())

            valid_ports = self.validate_port_ranges(client_ports)
            intercept_config_data = {
                "addresses": client_hosts,
                "portRanges": valid_ports,
                "protocols": client_protocols,
                "sourceIp": "$src_ip:$src_port"
            }

            host_config_data = {
                "forwardProtocol": True,
                "forwardAddress": True,
                "forwardPort": True,
                "allowedAddresses": client_hosts,
                "allowedPortRanges": valid_ports,
                "allowedProtocols": client_protocols,
                "allowedSourceAddresses": transparent_hosts
            }

            service = self.create_service_with_configs(
                name=name, 
                intercept_config_data=intercept_config_data, 
                host_config_data=host_config_data, 
                attributes=attributes, 
                encryption_required=encryption_required, 
                dry_run=dry_run
            )
            service_policy = self.create_service_policy(
                name=name+"-BindServicePolicy", 
                services=["@"+name], 
                endpoints=endpoints, 
                type="Bind", 
                semantic="AnyOf", 
                dry_run=dry_run
            )
            service_edge_router_policy = self.create_service_edge_router_policy(
                name=name+"-ServiceEdgeRouterPolicy", 
                services=["@"+name], 
                edge_routers=edge_routers, 
                semantic="AnyOf", 
                dry_run=dry_run
            )

        except:
            raise

        transparent_service = {
            "service": service,
            "service_policy": service_policy,
            "service_edge_router_policy": service_edge_router_policy
        }

        return(transparent_service)

    def delete_service_transparent(self, name: str):
        """delete a transparent service and its associated bind service policy and service edge router policy.

        :param str name: name of transparent service to delete
        """
        
        try:

            service_policy_name = name+"-BindServicePolicy"
            service_policies = self.get_resources(name=service_policy_name, type="service-policies")
            if len(service_policies) == 1:
                service_policy_result = self.delete_resource(type="service-policy", id=service_policies[0]['id'])
            elif len(service_policies) > 1:
                raise Exception("ERROR: found more than one service policy with name \"{}\"".format(service_policy_name))
            else:
                service_policy_result = "NOT FOUND"

            service_edge_router_policy_name = name+"-ServiceEdgeRouterPolicy"
            service_edge_router_policies = self.get_resources(name=service_edge_router_policy_name, type="service-edge-router-policies")
            if len(service_edge_router_policies) == 1:
                service_edge_router_policy_result = self.delete_resource(type="service-edge-router-policy", id=service_edge_router_policies[0]['id'])
            elif len(service_edge_router_policies) > 1:
                raise Exception("ERROR: found more than one service with name \"{}\"".format(service_edge_router_policy_name))
            else:
                service_edge_router_policy_result = "NOT FOUND"

            services = self.get_resources(name=name, type="services")
            if len(services) == 1:
                service_result = self.delete_resource(type="service", id=services[0]['id'])
            elif len(services) > 1:
                raise Exception("ERROR: found more than one service with name \"{}\"".format(name))
            else:
                service_result = "NOT FOUND"

        except:
            raise

        transparent_service = {
            "service": service_result,
            "service_policy": service_policy_result,
            "service_edge_router_policy": service_edge_router_policy_result
        }

        return(transparent_service)

    @docstring_parameters(valid_service_protocols=VALID_SERVICE_PROTOCOLS)
    def create_service_advanced(self, name: str, endpoints: list, client_hosts: list, client_ports: list, client_protocols: list=["tcp"], 
        server_hosts: list=[], server_ports: list=[], server_protocols: list=[], attributes: list=[], 
        edge_router_attributes: list=["#all"], encryption_required: bool=True, dry_run: bool=False, wait: int=30):
        """create an "advanced" PSM-based (platform service model) endpoint-hosted service.

        Multiple client intercepts may be specified i.e. lists of domain names or IP addresses, ports, and protocols. If alternative 
        server details are not given they are assumed to be the same as the intercept. If server details are provided then all intercepts 
        flow to that server. You may constrain the list of allowed server hosts, ports, and protocols
        that may be forwarded.

        :param: name is required string
        :param: client_hosts is required list of strings that are intercept domain name or IPv4.
        :param: client_ports is required list of strings of the port ranges to intercept as ["80","5900:5999"].
        :param: client_protocols is optional list of strings of the transports to intercept. Choices: {valid_service_protocols}. Default is ["tcp"].
        :param: server_hosts is optional list of strings that are a domain name, IPv4, or IPv6. If omitted the client host is used.
        :param: server_ports is optional list of strings of the port ranges to forward as ["80","5900:5999"]. If omitted same client port is used.
        :param: server_protocols is optional list of strings of the server protocols to forward. Choices: {valid_service_protocols}. If omitted the client protocol is used.
        :param: attributes is optional list of strings of service roles to assign, associating the service with a matching AppWAN. Default is [].
        :param: edge_router_attributes is optional list of strings of Router roles or Router names that can "see" this service. Default is ["#all"].
        :param: endpoints is optional list of strings of endpoints' #hashtag or @name that will host this service.
        :param: encryption_required is optional Boolean. Default is to enable edge-to-edge encryption.
        :param: dry_run is optional Boolean where True returns only the entity model without sending a request.
        """
        
        try:
            # validate roles
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception('ERROR: invalid role "{:s}". Must begin with "#"'.format(role))

            # these elements could be a single port as integer or a string with one or two ports separated by a : or -
            valid_client_ports = self.validate_port_ranges(client_ports)
            valid_server_ports = self.validate_port_ranges(server_ports)

            # validate client protocols
            valid_client_protocols = list()
            for proto in client_protocols:
                if not proto.lower() in VALID_SERVICE_PROTOCOLS:
                    raise Exception("ERROR: client intercept protocol \"{}\" is not valid.".format(proto.lower()))
                else:
                    valid_client_protocols.append(proto.lower())

            # validate server protocols
            valid_server_protocols = list()
            for proto in server_protocols:
                if not proto.lower() in VALID_SERVICE_PROTOCOLS:
                    raise Exception("ERROR: server protocol \"{}\" is not valid.".format(proto.lower()))
                else:
                    valid_server_protocols.append(proto.lower())

            # resolve exit hosting params
            server_egress = dict()
            if server_hosts and len(server_hosts) == 1:
                server_egress["host"] = server_hosts[0]
            elif server_hosts and len(server_hosts) > 1:
                server_egress["forwardHost"] = True
                server_egress["allowedHosts"] = server_hosts
            else:
                server_egress["forwardHost"] = True
                server_egress["allowedHosts"] = client_hosts

            if valid_server_ports and len(valid_server_ports) == 1 and valid_server_ports[0]['low'] == valid_server_ports[0]['high']:
                server_egress["port"] = valid_server_ports[0]['low']
            elif valid_server_ports:
                server_egress["forwardPort"] = True
                server_egress["allowedPortRanges"] = valid_server_ports
            else:
                server_egress["forwardPort"] = True
                server_egress["allowedPortRanges"] = valid_client_ports

            if server_protocols and len(server_protocols) == 1:
                server_egress["protocol"] = server_protocols[0]
            elif server_protocols and len(server_protocols) > 1:
                server_egress["forwardProtocol"] = True
                server_egress["allowedProtocols"] = server_protocols
            else:
                server_egress["forwardProtocol"] = True
                server_egress["allowedProtocols"] = client_protocols


            # parse out the elements in the list of endpoints as one of #attribute, UUID, or resolvable Endoint name
            bind_endpoints = list()
            for endpoint in endpoints:
                if endpoint[0:1] == '#':
                    bind_endpoints.append(endpoint) # is an endpoint role attribute
                else:
                    # strip leading @ if present and re-add later after verifying the named endpoint exists
                    if endpoint[0:1] == '@':
                        endpoint = endpoint[1:]

                    # if UUIDv4 then resolve to name, else verify the named endpoint exists 
                    try:
                        UUID(endpoint, version=4) # assigned below under "else" if already a UUID
                    except ValueError:
                        # else assume is a name and resolve to ID
                        try: 
                            name_lookup = self.get_resources(type="endpoints",name=endpoint)[0]
                            endpoint_name = name_lookup['name']
                        except Exception as e:
                            raise Exception('ERROR: Failed to find exactly one hosting endpoint named "{}". Caught exception: {}'.format(endpoint, e))
                        # append to list after successfully resolving name to ID
                        else: bind_endpoints.append('@'+endpoint_name) # is an existing endpoint's name
                    else:
                        try:
                            name_lookup = self.get_resource(type="endpoint",id=endpoint)
                            endpoint_name = name_lookup['name']
                        except Exception as e:
                            raise Exception('ERROR: Failed to find exactly one hosting endpoint with ID "{}". Caught exception: {}'.format(endpoint, e))
                        else: bind_endpoints.append('@'+endpoint_name) # is an existing endpoint's name resolved from UUID

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
                        "addresses": client_hosts, 
                        "ports": valid_client_ports,
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

            response = http.post(
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

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['services']['create_responses']):
            try:
                service = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("service"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        if wait:
            service_complete = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service", id=service['id'], wait=wait)
            return(service_complete)
        else:
            return(service)

    # the above method was renamed to follow the development of PSM-based services (platform service models)
    create_endpoint_service = create_service_advanced

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

            response = http.post(
                self.session.audience+'core/v2/app-wans',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except:
            raise
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['app-wans']['create_responses']):
            try:
                app_wan = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load {:s} object from POST response'.format("AppWAN"))
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
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

            response = http.get(
                self.session.audience+'core/v2/networks',
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK: # HTTP 200
            try:
                networks = json.loads(response.text)
            except ValueError as e:
                eprint('ERROR: failed to load endpoints object from GET response')
                raise(e)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
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
            response = http.get(
                self.session.audience+'core/v2/networks/'+network_id,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers
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

    def wait_for_property_defined(self, property_name: str, property_type: object=str, entity_type: str="network", wait: int=60, sleep: int=3, id: str=None, progress: bool=False):
        """continuously poll until expiry for the expected property to become defined with the any value of the expected type
        :param: property_name a top-level property to wait for e.g. `zitiId`
        :param: property_type optional Python instance type to expect for the value of property_name
        :param: id the UUID of the entity having a status if entity is not a network
        :param: entity_type optional type of entity e.g. network (default), endpoint, service, edge-router
        :param: wait optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param: sleep SECONDS polling interval
        """

        # use the id of this instance's Network unless another one is specified
        if entity_type == "network" and not id:
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
                '\twaiting for property {:s} ({:s}) or until {:s}.'.format(
                    property_name,
                    str(property_type),
                    time.ctime(now+wait)
                )
            )

#        response_code = int()
        property_value = None
        while time.time() < now+wait:
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                entity = self.get_resource(type=entity_type, id=id)
            except:
                raise

            # if expected property value is not null then evaluate type, else sleep
            if property_name in entity.keys() and entity[property_name]:
                property_value = entity[property_name]
                # if expected type then return, else sleep
                if isinstance(property_value, property_type):
                    if progress:
                        print() # newline terminates progress meter
                    return(entity)
                else:
                    if progress:
                        sys.stdout.write('\n{:^19s}:{:^19s} ({:s}):'.format(entity['name'],property_name, str(property_type)))
                    time.sleep(sleep)
            else:
                if progress:
                    sys.stdout.write('\n{:^19s}:{:^19s} ({:s}):'.format("fetching",property_name, str(property_type)))
                time.sleep(sleep)

        # 
        if progress:
            print() # newline terminates progress meter

        if not property_value:
            raise Exception('ERROR: failed to find any value for property "{:s}"'.format(
                    property_name
                )
            )
        else:
            raise Exception('ERROR: timed out waiting for property {:s} to have expected type: {:s}'.format(
                    property_name,
                    str(property_type),
                )
            )

    @docstring_parameters(resource_entity_types=str(RESOURCES.keys()))
    def wait_for_entity_name_exists(self, entity_name: str, entity_type: str, wait: int=60, sleep: int=3, progress: bool=False):
        """Continuously poll until expiry for the expected entity name to exist.

        :param: entity_name
        :param: entity_type is singular or plural form, any of {resource_entity_types}
        :param: wait optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param: sleep SECONDS polling interval
        :param: progress print a horizontal progress meter as dots, default false
        """

        now = time.time()

        if not wait >= sleep:
            raise Exception(
                "ERROR: wait duration ({:d}) must be greater than or equal to polling interval ({:d})".format(
                    wait, sleep
                )
            )

        if not plural(entity_type) in RESOURCES.keys():
            raise Exception("ERROR: unknown type \"{type}\". Choices: {choices}".format(
                type=entity_type,
                choices=str(RESOURCES.keys())
            ))

        # poll for status until expiry
        if progress:
            sys.stdout.write(
                '\twaiting for entity {:s} ({:s}) or until {:s}.'.format(
                    entity_name,
                    str(entity_type),
                    time.ctime(now+wait)
                )
            )

        found_entities = []
        while time.time() < now+wait:
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                found_entities = self.get_resources(type=plural(entity_type), name=entity_name)
            except:
                raise

            # if expected entity exists then verify name, else sleep
            if len(found_entities) > 1:
                if progress:
                    print() # newline terminates progress meter
                raise Exception(
                    'ERROR: Found more than one {type} named "{name}".'.format(
                        type=singular(entity_type), name=entity_name
                    )
                )
            elif len(found_entities) == 1:
                if progress:
                    print() # newline terminates progress meter
                return(found_entities[0])
            else:
                if progress:
                    sys.stdout.write('\n{:^19s}:{:^19s} ({:s}):'.format("fetching",entity_name, singular(entity_type)))
                time.sleep(sleep)

        if progress:
            print() # newline terminates progress meter

        raise Exception('ERROR: failed to find one {type} named "{name}".'.format(
                type=singular(entity_type), name=entity_name
            )
        )

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

            response = http.get(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK:
            try:
                status = json.loads(response.text)['status']
                name = json.loads(response.text)['name']
            except:
                eprint('ERROR parsing entity object in response')
                raise
            else:
                return {
                    'http_status': STATUS_CODES._codes[response_code][0].upper(),
                    'response_code': response_code,
                    'status': status,
                    'name': name
                }
        else:
            return {
                'http_status': STATUS_CODES._codes[response_code][0].upper(),
                'response_code': response_code
            }

    def rotate_edge_router_registration(self, id: str):
        """rotate and return the registration key like {"registrationKey": str, "expiresAt": date}
        :param id: the UUID of the edge router
        """

        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/edge-routers/'+id+'/registration-key'
            response = http.post(
                entity_url,
                proxies=self.session.proxies,
                verify=self.session.verify,
                headers=headers,
            )
            response_code = response.status_code
        except:
            raise

        if response_code == STATUS_CODES.codes.OK:
            try:
                registration_object = json.loads(response.text)
            except:
                raise Exception('ERROR parsing response as object, got:\n{}'.format(response.text))
            else:
                return(registration_object)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

    get_edge_router_registration = rotate_edge_router_registration

    def delete_resource(self, type, id=None, wait=int(0), progress=False):
        """
        delete a resource
        :param type: required entity type to delete i.e. network, endpoint, service, edge-router
        :param id: required entity UUID to delete
        :param wait: optional seconds to wait for entity destruction
        """
        try:
            headers = { "authorization": "Bearer " + self.session.token }
            entity_url = self.session.audience+'core/v2/networks/'+self.id
            expected_responses = [
                STATUS_CODES.codes.ACCEPTED,
                STATUS_CODES.codes.OK
            ]
            if not type == 'network':
                if id is None:
                    raise Exception("ERROR: need entity UUID to delete")
                entity_url = self.session.audience+'core/v2/'+plural(type)+'/'+id
            eprint("WARN: deleting {:s}".format(entity_url))
            params = dict()
            # if type == "service":
            #     params["beta"] = ''

            response = http.delete(
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
                    STATUS_CODES._codes[response_code][0].upper(),
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
