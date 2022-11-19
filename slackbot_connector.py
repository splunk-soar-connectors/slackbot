# File: slackbot_connector.py
#
# Copyright (c) 2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import os
import shlex
import subprocess
import sys
from pathlib import Path

import encryption_helper
import phantom.app as phantom
import requests
import sh
import simplejson as json
from bs4 import BeautifulSoup, UnicodeDammit
from django.http import HttpResponse
from phantom.base_connector import APPS_STATE_PATH

from slackbot_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)
    real_state_file_path = os.path.realpath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Exception: {0}'.format(str(e)))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)

    return state


def _save_app_state(state, asset_id, app_connector=None):
    """ This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)

    real_state_file_path = os.path.realpath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(real_state_file_path, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        if app_connector:
            app_connector.debug_print('Unable to save state file: {0}'.format(str(e)))

    return phantom.APP_SUCCESS


def _is_safe_path(basedir, path, follow_symlinks=True):
    """
    This function checks the given file path against the actual app directory
    path to combat path traversal attacks
    """
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))


def rest_log(msg):
    state_dir = "{0}/{1}".format(APPS_STATE_PATH, SLACK_APP_ID)
    path.unlink()
    path = Path(state_dir) / "resthandler.log"
    path.touch()  # default exists_ok=True
    with path.open('a') as highscore:
        highscore.write(msg + "\n")


def handle_request(request, path):
    try:
        payload = request.POST.get('payload')
        payload = json.loads(payload)
        state_dir = "{0}/{1}".format(APPS_STATE_PATH, SLACK_APP_ID)

        if not payload:
            return HttpResponse(SLACK_ERROR_PAYLOAD_NOT_FOUND, content_type="text/plain", status=400)

        callback_id = payload.get('callback_id')
        # rest_log(f"Callback_id: {callback_id}")
        if not callback_id:
            return HttpResponse(SLACK_ERROR_CALLBACK_ID_NOT_FOUND, content_type="text/plain", status=400)

        try:
            callback_json = json.loads(UnicodeDammit(callback_id).unicode_markup)
        except Exception as e:
            # rest_log(f"Callback parse error")
            return HttpResponse(SLACK_ERROR_PARSE_JSON_FROM_CALLBACK_ID.format(error=e), content_type="text/plain", status=400)

        asset_id = callback_json.get('asset_id')
        # rest_log(f"Asset retrieved: {asset_id}")
        try:
            int(asset_id)
        except ValueError:
            return HttpResponse(SLACK_ERROR_STATE_FILE_NOT_FOUND, content_type="text/plain", status=400)

        state_filename = "{0}_state.json".format(asset_id)
        state_dir = "{0}/{1}".format(APPS_STATE_PATH, SLACK_APP_ID)
        state_path = "{0}/{1}".format(state_dir, state_filename)

        try:
            with open(state_path, 'r') as state_file_obj:  # nosemgrep
                state_file_data = state_file_obj.read()
                state = json.loads(state_file_data)
        except Exception as e:
            return HttpResponse(SLACK_ERROR_UNABLE_TO_READ_STATE_FILE.format(error=e), content_type="text/plain", status=400)

        my_token = state.get('token')
        if my_token:
            try:
                my_token = encryption_helper.decrypt(my_token, asset_id)
            except Exception:
                return RetVal(phantom.APP_ERROR, SLACK_DECRYPTION_ERROR)

        their_token = payload.get('token')
        # rest_log(f"My token: {my_token}, Their token: {their_token}")

        if not my_token or not their_token or my_token != their_token:
            return HttpResponse(SLACK_ERROR_AUTH_FAILED, content_type="text/plain", status=400)

        qid = callback_json.get('qid')
        # rest_log(f"Question ID: {qid}")

        if not qid:
            return HttpResponse(SLACK_ERROR_ANSWER_FILE_NOT_FOUND, content_type="text/plain", status=400)

        answer_filename = '{0}.json'.format(qid)
        answer_path = "{0}/{1}".format(state_dir, answer_filename)
        if not _is_safe_path(state_dir, answer_path):
            return HttpResponse(SLACK_ERROR_INVALID_FILE_PATH, content_type="text/plain", status=400)

        try:
            answer_file = open(answer_path, 'w')  # nosemgrep
        except Exception as e:
            return HttpResponse(SLACK_ERROR_COULD_NOT_OPEN_ANSWER_FILE.format(error=e), content_type="text/plain", status=400)

        try:
            answer_file.write(json.dumps(payload))
            answer_file.close()
        except Exception as e:
            return HttpResponse(SLACK_ERROR_WHILE_WRITING_ANSWER_FILE.format(error=e), content_type="text/plain", status=400)

        confirmation = callback_json.get('confirmation', "Received response")
        return HttpResponse(f"Response: {confirmation}", content_type="text/plain", status=200)

    except Exception as e:
        return HttpResponse(SLACK_ERROR_PROCESS_RESPONSE.format(error=e), content_type="text/plain", status=500)


# Define the App Class
class SlackConnector(phantom.BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SlackConnector, self).__init__()

        self._base_url = None
        self._state = {}
        self._slack_client = None
        self._interval = None
        self._timeout = None
        self._socket_token = None
        self._verification_token = None

    def encrypt_state(self, encrypt_var, token_name):
        """ Handle encryption of token.
        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        self.debug_print(SLACK_ENCRYPT_TOKEN.format(token_name))   # nosemgrep
        return encryption_helper.encrypt(encrypt_var, self.get_asset_id())

    def decrypt_state(self, decrypt_var, token_name):
        """ Handle decryption of token.
        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        self.debug_print(SLACK_DECRYPT_TOKEN.format(token_name))    # nosemgrep
        return encryption_helper.decrypt(decrypt_var, self.get_asset_id())

    def initialize(self):

        config = self.get_config()
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        self._bot_token = config.get(SLACK_JSON_BOT_TOKEN)
        self._socket_token = config.get(SLACK_JSON_SOCKET_TOKEN)
        self._ph_auth_token = config.get(SLACK_JSON_PH_AUTH_TOKEN)
        self._base_url = SLACK_BASE_URL

        self._verification_token = self._state.get('token')
        self._interval = self._validate_integers(self, config.get("response_poll_interval", 30), SLACK_RESP_POLL_INTERVAL_KEY)
        if self._interval is None:
            return self.get_status()

        self._timeout = self._validate_integers(self, config.get("timeout", 30), SLACK_TIMEOUT_KEY)
        if self._timeout is None:
            return self.get_status()

        ret_val, ph_base_url = self._get_phantom_base_url_slack(self)
        if phantom.is_fail(ret_val):
            return ret_val
        ph_base_url += '/' if not ph_base_url.endswith('/') else ''

        # Storing Bot file required data in state file
        self._state['ph_base_url'] = ph_base_url
        self._state[SLACK_JSON_PH_AUTH_TOKEN] = self._ph_auth_token
        self._state[SLACK_JSON_BOT_TOKEN] = self._bot_token
        self._state[SLACK_JSON_SOCKET_TOKEN] = self._socket_token

        # Decrypting data from state file
        if self._state.get(SLACK_STATE_IS_ENCRYPTED):
            try:
                if self._verification_token:
                    self._verification_token = self.decrypt_state(self._verification_token, "verification")
            except Exception as e:
                self.debug_print("{}: {}".format(SLACK_DECRYPTION_ERROR, self._get_error_message_from_exception(e)))
                return self.set_status(phantom.APP_ERROR, SLACK_DECRYPTION_ERROR)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Encrypting tokens
        try:
            if self._verification_token:
                self._state['token'] = self.encrypt_state(self._verification_token, "verification")

            if self._bot_token:
                self._state[SLACK_JSON_BOT_TOKEN] = self.encrypt_state(self._bot_token, "bot")

            if self._socket_token:
                self._state[SLACK_JSON_SOCKET_TOKEN] = self.encrypt_state(self._socket_token, "socket")

            if self._ph_auth_token:
                self._state[SLACK_JSON_PH_AUTH_TOKEN] = self.encrypt_state(self._ph_auth_token, "ph_auth")

        except Exception as e:
            self.debug_print("{}: {}".format(SLACK_ENCRYPTION_ERROR, self._get_error_message_from_exception(e)))
            return self.set_status(phantom.APP_ERROR, SLACK_ENCRYPTION_ERROR)

        self._state[SLACK_STATE_IS_ENCRYPTED] = True
        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)

        return phantom.APP_SUCCESS

    def _get_phantom_base_url_slack(self, action_result):

        rest_url = SLACK_PHANTOM_SYS_INFO_URL.format(url=self.get_phantom_base_url())
        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False)

        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        phantom_base_url = resp_json.get('base_url')

        if not phantom_base_url:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_BASE_URL_NOT_FOUND))

        return RetVal(phantom.APP_SUCCESS, phantom_base_url)

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_EMPTY_RESPONSE.format(code=response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = SLACK_UNABLE_TO_PARSE_ERROR_DETAILS

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_UNABLE_TO_PARSE_JSON_RESPONSE.format(
                error=self._get_error_message_from_exception(e))), None)

        # The 'ok' parameter in a response from slack says if the call passed or failed
        if resp_json.get('ok', '') is not False:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        action_result.add_data(resp_json)

        error = resp_json.get('error', '')
        if error == 'invalid_auth':
            error = SLACK_ERROR_BOT_TOKEN_INVALID
        elif error == 'not_in_channel':
            error = SLACK_ERROR_NOT_IN_CHANNEL
        elif not error:
            error = SLACK_ERROR_FROM_SERVER

        return RetVal(action_result.set_status(phantom.APP_ERROR, error), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if r is not None:
                action_result.add_debug_data({'r_status_code': r.status_code})
                action_result.add_debug_data({'r_text': r.text})
                action_result.add_debug_data({'r_headers': r.headers})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})
                return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_NO_RESPONSE_FROM_SERVER), None)

        # There are just too many differences in the response to handle all of them in the same function
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successfull empty reponse
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = SLACK_ERROR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
            else:
                error_code = SLACK_ERROR_CODE_UNAVAILABLE
                error_msg = SLACK_ERROR_MESSAGE_UNKNOWN
        except Exception:
            error_code = SLACK_ERROR_CODE_UNAVAILABLE
            error_msg = SLACK_ERROR_MESSAGE_UNKNOWN

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _make_rest_call(self, action_result, rest_url, verify, method=requests.get, headers={}, body={}):

        try:
            r = method(rest_url, verify=verify, headers=headers, data=json.dumps(body))
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "{0}. {1}".format(
                SLACK_ERROR_REST_CALL_FAILED, self._get_error_message_from_exception(e))), None)

        try:
            resp_json = r.json()
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_UNABLE_TO_DECODE_JSON_RESPONSE), None)

        if 'failed' in resp_json:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "{0}. Message: {1}".format(
                SLACK_ERROR_REST_CALL_FAILED, resp_json.get('message', 'NA'))), None)

        if 200 <= r.status_code <= 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        details = 'NA'

        if resp_json:
            details = json.dumps(resp_json).replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Error from server: Status code: {0} Details: {1}".format(
            r.status_code, details)), None)

    def _make_slack_rest_call(self, action_result, endpoint, body, headers={}, files={}):

        body.update({'token': self._bot_token})

        # send api call to slack
        try:
            response = requests.post("{}{}".format(self._base_url, endpoint),
                                     data=body,
                                     headers=headers,
                                     files=files,
                                     timeout=SLACK_DEFAULT_TIMEOUT)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "{}. {}".format(
                SLACK_ERROR_SERVER_CONNECTION, self._get_error_message_from_exception(e))), None)

        return self._process_response(response, action_result)

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """Validate the provided input parameter value is a non-zero positive integer and returns the integer value of the parameter itself.

        Parameters:
            :param action_result: object of ActionResult class
            :param parameter: input parameter
            :param key: input parameter message key
            :allow_zero: whether zero should be considered as valid value or not
            :return: integer value of the parameter or None in case of failure

        Returns:
            :return: integer value of the parameter
        """
        try:
            if not float(parameter).is_integer():
                action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_INVALID_INT.format(key=key))
                return None

            parameter = int(parameter)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_INVALID_INT.format(key=key))
            return None

        if parameter < 0:
            action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_NEGATIVE_INT.format(key=key))
            return None
        if not allow_zero and parameter == 0:
            action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_NEGATIVE_AND_ZERO_INT.format(key=key))
            return None

        return parameter

    def _test_connectivity(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_AUTH_TEST, {})

        if not ret_val:
            self.save_progress(SLACK_ERROR_TEST_CONNECTION_FAILED)
            return ret_val

        action_result.add_data(resp_json)

        self.save_progress("Auth check to Slack passed. Configuring app for team, {}".format(resp_json.get('team', 'Unknown Team')))

        bot_username = resp_json.get('user')
        bot_user_id = resp_json.get('user_id')

        self.save_progress("Got username, {0}, and user ID, {1}, for the bot".format(bot_username, bot_user_id))

        self._state['bot_name'] = bot_username
        self._state['bot_id'] = bot_user_id

        self.save_progress(SLACK_SUCCESS_TEST_CONNECTION_PASSED)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _stop_bot(self, param):

        self.debug_print("Inside stop bot action")
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        pid = self._state.get('pid')
        self.debug_print("PID of Bot : {}".format(pid))
        if pid:
            self._state.pop('pid')
            try:
                if 'slack_bot.py' in sh.ps('ww', pid):  # pylint: disable=E1101
                    try:
                        sh.kill(pid)  # pylint: disable=E1101
                        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCCESS_SLACKBOT_STOPPED)
                    except Exception:
                        return action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_COUDNT_STOP_SLACKBOT)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_SLACKBOT_NOT_RUNNING)
        else:
            try:
                ps_out = sh.grep(sh.ps('ww', 'aux'), 'slack_bot.py')
                pid = shlex.split(str(ps_out))[1]
                try:
                    sh.kill(pid)  # pylint: disable=E1101
                    return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCCESS_SLACKBOT_STOPPED)
                except Exception:
                    return action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_COUDNT_STOP_SLACKBOT)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_SLACKBOT_NOT_RUNNING)

    def _start_bot(self, param):
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_AUTH_TEST, {})
        if not ret_val:
            self.save_progress("Could not authenticate with Slack. {}".format(resp_json))
            return ret_val

        bot_id = resp_json.get('user_id')
        self.save_progress("Bot ID: {}".format(bot_id))
        if not bot_id:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERROR_COULD_NOT_GET_BOT_ID)

        pid = self._state.get('pid')
        if pid:
            try:
                if 'slack_bot.py' in sh.ps('ww', pid):  # pylint: disable=E1101
                    self.save_progress("Detected SlackBot running with pid {0}".format(pid))
                    return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCCESS_SLACKBOT_RUNNING)
            except Exception:
                pass

        asset_id = self.get_asset_id()
        app_version = self.get_app_json().get('app_version', '')

        try:
            ps_out = sh.grep(sh.ps('ww', 'aux'), 'slack_bot.py')  # pylint: disable=E1101
            old_pid = shlex.split(str(ps_out))[1]
            if app_version not in ps_out:
                self.save_progress("Found an old version of slackbot running with pid {}, going to kill it".format(old_pid))
                sh.kill(old_pid)  # pylint: disable=E1101
            elif asset_id in ps_out:  # pylint: disable=E1101
                self._state['pid'] = int(old_pid)
                return action_result.set_status(phantom.APP_SUCCESS, SLACK_ERROR_SLACKBOT_RUNNING_WITH_SAME_BOT_TOKEN)
        except Exception:
            pass

        slack_bot_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'slack_bot.py')

        # check if the socket token is valid
        headers = {
            'Authorization': 'Bearer {}'.format(self._socket_token)
        }
        url = "{}apps.connections.open".format(SLACK_BASE_URL)
        resp = requests.post(url, headers=headers, timeout=30)
        resp = resp.json()

        if not resp.get('ok'):
            self.save_progress("Failed to start Slack Bot")
            return action_result.set_status(phantom.APP_ERROR, SLACK_SOCKET_TOKEN_ERROR)

        self.save_progress("Starting SlackBot")
        proc = subprocess.Popen(['phenv', 'python3', slack_bot_filename, asset_id, app_version])
        self._state['pid'] = proc.pid
        self.save_progress("Started SlackBot with pid: {0}".format(proc.pid))

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCCESS_SLACKBOT_STARTED)

    def _on_poll(self, param):

        return self._start_bot(param)

    def handle_action(self, param):

        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))
        self.save_progress("action_id: {}".format(self.get_action_identifier()))

        if action_id == ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == ACTION_ID_STOP_BOT:
            ret_val = self._stop_bot(param)
        elif action_id == ACTION_ID_START_BOT:
            ret_val = self._start_bot(param)
        elif action_id == ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)

        return ret_val


if __name__ == '__main__':

    # import pudb
    # pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SlackConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
