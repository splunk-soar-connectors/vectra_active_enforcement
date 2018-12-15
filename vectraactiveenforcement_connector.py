# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------
import json
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from time import gmtime
from time import strftime

# Usage of the consts file is recommended
from vectraactiveenforcement_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class VectraActiveEnforcementConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(VectraActiveEnforcementConnector, self).__init__()

        self._state = None
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            auth=(self.username, self.password),
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _process_hosts(self, search_type, action_result, request_params, host_dict):
        """
        Returns dictionary of hosts retrieved and appends quest type to reason field for host
        """
        ret_val, response = self._make_rest_call('/hosts', action_result, params=request_params)

        if phantom.is_fail(ret_val):
            self.save_progress("Atttempt to retrive host failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        # Fix invalid response for when page_size is provided as a parameter and count == 0
        if response == []:
            response = {
                'count': 0,
                'results': []
            }

        if search_type in ['tags', 'scores', 'detections']:
            for host in response['results']:
                if host['name'] in host_dict.keys():
                    host_dict[host['name']].add_reason(search_type)
                else:
                    host_dict.update({host['name']: VectraHost(host)})
                    host_dict[host['name']].add_reason(search_type)
            self.save_progress("Saved hosts: " + search_type)
            return
        else:
            for host in response['results']:
                host_dict.update({host['name']: VectraHost(host)})
            self.save_progress("Saved retrieved hosts")
            return

    def _process_detections(self, action_result, request_params):
        """
        Returns dict of detections and set of ips associated with detections
        """

        ret_val, response = self._make_rest_call('/detections', action_result, params=request_params)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Atttempt to retrive host failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        # Fix invalid response for when page_size is provided as a parameter and count == 0
        if response == []:
            response = {
                'count': 0,
                'results': []
            }

        detection_dict = {}
        ip_list = []
        for detection in response['results']:
            detection_dict.update({detection['id']: VectraDetection(detection)})
            ip_list.append(detection['src_ip'])
        self.save_progress("Saved detections: " + request_params['type_vname'])
        return detection_dict, ip_list

    def _converts_object_to_json(self, json_dict):
        converted_objects = {}
        for key in json_dict:
            converted_objects.update({key: json_dict[key].summary()})
        return converted_objects

    def _manage_containers(self, action_result, host_dict, unblock_list):

        phantom_base_url = self.get_phantom_base_url()

        try:
            blocked_hosts = requests.get(
                url=phantom_base_url + '/rest/decided_list/blocked_hosts',
                verify=False
            ).json()
        except requests.RequestException:
            action_result.set_status(phantom.APP_ERROR, 'Unable to retrieve list of currently blocked hosts')

        if blocked_hosts.get('failed'):
            try:
                requests.post(
                    url=phantom_base_url + '/rest/decided_list',
                    verify=False,
                    data=json.dumps({
                        "name": "blocked_hosts",
                        "content": [["empty"]]
                    })
                )

                blocked_hosts = requests.get(
                    url=phantom_base_url + '/rest/decided_list/blocked_hosts',
                    verify=False
                ).json()
            except requests.RequestException:
                action_result.set_status(phantom.APP_ERROR, 'Unable to retrieve list of currently blocked hosts')

        if blocked_hosts['content'][0][0] == "empty" and len(host_dict) == 0:
            return self.save_progress('No hosts requested to (un)block')
        elif blocked_hosts['content'][0][0] == "empty" and len(host_dict) >= 1:
            for host in host_dict:
                self._block_host(host_dict[host])
            return self.save_progress("Successfully created containers for {} hosts".format(len(host_dict)))
        elif blocked_hosts['content'][0][0] != "empty" and len(host_dict) == 0:
            for host in blocked_hosts['content']:
                self._unblock_host(host)
                unblock_list.append(host[0])

            # id = requests.get(
            #     url=phantom_base_url + '/rest/decided_list',
            #     verify=False
            # ).json()['data'][0]['id']
            try:
                requests.post(
                    url=phantom_base_url + '/rest/decided_list/blocked_hosts',
                    verify=False,
                    data=json.dumps({
                        "name": "blocked_hosts",
                        "content": [["empty"]]
                    })
                )
            except requests.RequestException:
                action_result.set_status(phantom.APP_ERROR, 'Unable to delete list of currently blocked hosts')

            return self.save_progress("Successfully created containers for {} hosts".format(len(blocked_hosts[
                                                                                                        'content'])))
        elif blocked_hosts['content'][0][0] != "empty" and len(host_dict) >= 1:
            for host in blocked_hosts['content']:
                # Unblock hosts
                if host[1] not in host_dict.keys():
                    self._unblock_host(host)
                    unblock_list.append(host[0])

                # Block hosts
            for host in host_dict:
                if not any(list_host[1] == host for list_host in blocked_hosts['content']):
                    self._block_host(host_dict[host])

    def _block_host(self, host):
        config = self.get_config()
        name = "Block request: {ip} [{name}]".format(ip=host.ip, name=host.name)
        identifier = "vectra_block_request {ip} {time}".format(ip=host.ip, time=strftime("%m/%d/%Y %H:%M", gmtime()))
        artifact = create_artifact(host, 'block', config['severity'])

        container_ret_val, message, self._block_container_id = self.save_container(
            create_container(name, identifier, artifact, config['severity'])
        )
        self.save_progress("Successfully saved container: {}".format(self._block_container_id))
        return

    def _unblock_host(self, host):
        config = self.get_config()
        name = "Unblock request: {ip} [{name}]".format(ip=host[0], name=host[1])
        identifier = "vectra_unblock_request {ip} {time}".format(ip=host[0], time=strftime("%m/%d/%Y %H:%M", gmtime()))

        artifact = {
            "name": host[1],
            "cef": {
                "act": "unblock",
                "dvc": host[0],
                "dvchost": host[1]
            },
            "run_automation": False,
            "label": "incident",
            "severity": config['severity'],
            "source_data_identifier": "vectra"
        }

        container_ret_val, message, self._block_container_id = self.save_container(
            create_container(name, identifier, artifact, config['severity'])
        )

        self.save_progress("Successfully unblocked {}".format(host[0]))
        return

    def _update_lists(self, action_result, host_dict):

        phantom_base_url = self.get_phantom_base_url()
        content = []
        for host in host_dict:
            content.append([host_dict[host].ip, host])

        if len(content) >= 1:
            try:
                requests.post(
                    url=phantom_base_url + '/rest/decided_list/blocked_hosts',
                    verify=False,
                    data=json.dumps({
                        "name": "blocked_hosts",
                        "content": content
                    })
                )
            except requests.RequestException:
                action_result.set_status(phantom.APP_ERROR, 'Unable to retrieve list of currently blocked hosts')

        return self.save_progress('Successfully updated block list')

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        ret_val, response = self._make_rest_call('', action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        # Initial setup
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Retrieve hosts
        retrieved_hosts = {}
        request_params = {
            'last_source': param['ip']
        }
        self._process_hosts(None, action_result, request_params, retrieved_hosts)

        # Convert objects to dicts
        summary_dict = self._converts_object_to_json(retrieved_hosts)
        action_result.add_data(summary_dict)

        # Create summary objects
        summary = action_result.update_summary({})
        summary['retrieved_hosts'] = len(summary_dict)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved {0} hosts".format(len(
            retrieved_hosts)))

    def _handle_get_detections(self, param):

        # TODO Add option to get pcaps and add to vault

        # Initial setup
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        all_detections = {}
        all_ips = set()

        # Retrieve detections
        for detection in param['dettypes'].split(','):
            request_params = {
                'src_ip': param.get('src_ip', ''),
                'dst_port': param.get('dst_port', None),
                'type_vname': detection.strip(),
                'state': param['state'],
                'page_size': 'all'
            }
            retrieved_detections, retrieved_ips = self._process_detections(action_result, request_params)
            all_detections.update(retrieved_detections)
            all_ips.update(retrieved_ips)

        # Convert objects to dict
        summary_detections = self._converts_object_to_json(all_detections)
        action_result.add_data(summary_detections)

        # Create summary objects
        summary = action_result.update_summary({})
        summary['retrieved_detections'] = len(summary_detections)
        summary['ip_list'] = list(all_ips)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved {0} detections".format(len(
            summary_detections)))

    def _handle_get_scored_hosts(self, param):

        # Initial setup
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Retieve hosts
        retrieved_hosts = {}
        request_params = {
            'c_score_gte': param['cscore'],
            't_score_gte': param['tscore'],
            'page_size': "all"
        }
        self._process_hosts(None, action_result, request_params, retrieved_hosts)

        # Convert objects to dicts
        summary_dict = self._converts_object_to_json(retrieved_hosts)
        action_result.add_data(summary_dict)

        # Create summary objects
        summary = action_result.update_summary({})
        summary['retrieved_hosts'] = len(summary_dict)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved {0} hosts".format(len(
            retrieved_hosts)))

    def _handle_get_tagged_hosts(self, param):

        # Initial setup
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Retrieve hosts
        retrieved_hosts = {}
        request_params = {
            'tags': param['dtags'],
            'page_size': "all",
        }
        self._process_hosts(None, action_result, request_params, retrieved_hosts)

        # Convert objects to dicts
        summary_dict = self._converts_object_to_json(retrieved_hosts)
        action_result.add_data(summary_dict)

        # Create summary objects
        summary = action_result.update_summary({})
        summary['retrieved_hosts'] = len(summary_dict)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved {0} hosts".format(len(
            retrieved_hosts)))

    def _handle_on_poll(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        retrieved_hosts = {}  # dict to manage hosts retrieved from Vectra using VectraHost Class
        retrieved_detections = {}  # dict to manage detections retrieved from Vectra using VectraDetection Class
        unblocked_hosts = []

        if config['tags']:
            request_params = {
                'tags': config.get('dtags', 'block'),
                'page_size': "all",
            }
            self._process_hosts('tags', action_result, request_params, retrieved_hosts)

        if config['scores']:
            request_params = {
                'c_score_gte': config.get('cscore', 50),
                't_score_gte': config.get('tscore', 50),
                'page_size': "all"
            }
            self._process_hosts('scores', action_result, request_params, retrieved_hosts)

        if config['detections'] and len(config.get('dettypes')) >= 1:
            for dettype in config.get('dettypes').split(','):

                request_params = {
                    'type_vname': dettype.strip(),
                    'state': 'active',
                    'page_size': 'all'
                }
                detections, detection_ips = self._process_detections(action_result, request_params)
                retrieved_detections.update(detections)

                # TODO Implement threads
                # Convert detection to host and add to retrieved_hosts dict
                for ip in set(detection_ips):
                    request_params = {
                        'last_source': ip,
                        'state': 'active',
                        'page_size': 'all'
                    }
                    self._process_hosts('detections', action_result, request_params, retrieved_hosts)
        elif config['detections'] and len(config.get('dettypes')) == 0:
            action_result.set_status(phantom.APP_ERROR, "Detections enabled. No detection types defined")

        summary_host_dict = self._converts_object_to_json(retrieved_hosts)
        summary_detection_dict = self._converts_object_to_json(retrieved_detections)
        action_result.add_data(summary_host_dict)
        action_result.add_data(summary_detection_dict)

        # Compare list and create artifacts
        self._manage_containers(action_result, retrieved_hosts, unblocked_hosts)
        self._update_lists(action_result, retrieved_hosts)

        # # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['retrieved_hosts'] = len(retrieved_hosts)
        summary['retrieved_detections'] = len(retrieved_detections)
        summary['unblocked_hosts'] = len(unblocked_hosts)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'get_detections':
            ret_val = self._handle_get_detections(param)

        elif action_id == 'get_scored_hosts':
            ret_val = self._handle_get_scored_hosts(param)

        elif action_id == 'get_tagged_hosts':
            ret_val = self._handle_get_tagged_hosts(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        """
        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        config = self.get_config()
        self._base_url = "https://" + config['device'] + "/api"
        self.username = config['username']
        self.password = config['password']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    phantom_base_url = BaseConnector._get_phantom_base_url()

    r = requests.get(phantom_base_url + "/login", verify=False)
    csrftoken = r.cookies['csrftoken']
    data = {'username': 'admin', 'password': 'password', 'csrfmiddlewaretoken': csrftoken}
    headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': phantom_base_url + '/login'}
    r2 = requests.post(phantom_base_url + "/login", verify=False, data=data, headers=headers)
    sessionid = r2.cookies['sessionid']

    if len(sys.argv) < 2:
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VectraActiveEnforcementConnector()
        connector.print_progress_message = True
        in_json['user_session_token'] = sessionid
        result = connector._handle_action(json.dumps(in_json), None)
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
