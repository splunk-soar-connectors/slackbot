# File: slack_bot_connector.py
#
# Copyright (c) 2023-2025 Splunk Inc.
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
import socket
import subprocess
import sys
from os.path import exists
from pathlib import Path
from urllib.parse import urlparse

import encryption_helper
import phantom.app as phantom
import requests
import sh
import simplejson as json
from bs4 import BeautifulSoup, UnicodeDammit
from django.http import HttpResponse
from phantom.base_connector import APPS_STATE_PATH

from slack_bot_consts import *
from slack_bot_enums import CommandPermission, SoarRestEndpoint


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


def _load_app_state(asset_id, app_connector=None):
    """This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print("In _load_app_state: Invalid asset_id")
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = f"{app_dir}/{asset_id}_state.json"
    real_state_file_path = os.path.realpath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print("In _load_app_state: Invalid asset_id")
        return {}

    state = {}
    try:
        with open(real_state_file_path) as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.debug_print(f"In _load_app_state: Exception: {e!s}")

    if app_connector:
        app_connector.debug_print("Loaded state: ", state)

    return state


def _save_app_state(state, asset_id, app_connector=None):
    """This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print("In _save_app_state: Invalid asset_id")
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = f"{app_dir}/{asset_id}_state.json"

    real_state_file_path = os.path.realpath(state_file)
    if os.path.dirname(real_state_file_path) != app_dir:
        if app_connector:
            app_connector.debug_print("In _save_app_state: Invalid asset_id")
        return {}

    if app_connector:
        app_connector.debug_print("Saving state: ", state)

    try:
        with open(real_state_file_path, "w+") as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        if app_connector:
            app_connector.debug_print(f"Unable to save state file: {e!s}")

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


def rest_log(message):
    state_dir = f"{APPS_STATE_PATH}/{SLACK_BOT_APP_ID}"
    path.unlink()
    path = Path(state_dir) / "resthandler.log"
    path.touch()  # default exists_ok=True
    with path.open("a") as highscore:
        highscore.write(message + "\n")


def process_payload(payload, answer_path):
    if not exists(answer_path):
        final_payload = {"payloads": [payload], "replies_from": [payload.get("user").get("id")]}
        return final_payload
    else:
        old_payload = dict()
        try:
            with open(answer_path) as read_old_file:
                old_payload = json.loads(read_old_file.read())
        except Exception as e:
            return HttpResponse(f"Error while reading data from file: {e}", content_type="text/plain", status=400)
        current_user_id = payload.get("user").get("id")
        if current_user_id not in old_payload.get("replies_from"):
            old_payload["payloads"].append(payload)
            old_payload["replies_from"].append(payload.get("user").get("id"))
        else:
            user_payloads = old_payload.get("payloads")
            for data in user_payloads:
                if data.get("user").get("id") == current_user_id:
                    data["actions"] = payload.get("actions")

        return old_payload


def handle_request(request, path):
    try:
        payload = request.POST.get("payload")
        payload = json.loads(payload)
        state_dir = f"{APPS_STATE_PATH}/{SLACK_BOT_APP_ID}"

        if not payload:
            return HttpResponse(SLACK_BOT_ERROR_PAYLOAD_NOT_FOUND, content_type="text/plain", status=400)

        callback_id = payload.get("callback_id")
        # rest_log(f'Callback_id: {callback_id}')
        if not callback_id:
            return HttpResponse(SLACK_BOT_ERROR_CALLBACK_ID_NOT_FOUND, content_type="text/plain", status=400)

        try:
            callback_json = json.loads(UnicodeDammit(callback_id).unicode_markup)
        except Exception as e:
            # rest_log(f'Callback parse error')
            return HttpResponse(SLACK_BOT_ERROR_PARSE_JSON_FROM_CALLBACK_ID.format(error=e), content_type="text/plain", status=400)

        asset_id = callback_json.get("asset_id")
        # rest_log(f'Asset retrieved: {asset_id}')
        try:
            int(asset_id)
        except ValueError:
            return HttpResponse(SLACK_BOT_ERROR_STATE_FILE_NOT_FOUND, content_type="text/plain", status=400)

        state_filename = f"{asset_id}_state.json"
        state_dir = f"{APPS_STATE_PATH}/{SLACK_BOT_APP_ID}"
        state_path = f"{state_dir}/{state_filename}"

        try:
            with open(state_path) as state_file_obj:  # nosemgrep
                state_file_data = state_file_obj.read()
                state = json.loads(state_file_data)
        except Exception as e:
            return HttpResponse(SLACK_BOT_ERROR_UNABLE_TO_READ_STATE_FILE.format(error=e), content_type="text/plain", status=400)

        my_token = state.get("token")
        if my_token:
            try:
                my_token = encryption_helper.decrypt(my_token, asset_id)
            except Exception:
                return RetVal(phantom.APP_ERROR, SLACK_BOT_DECRYPTION_ERROR)

        their_token = payload.get("token")
        # rest_log(f'My token: {my_token}, Their token: {their_token}')

        if not my_token or not their_token or my_token != their_token:
            return HttpResponse(SLACK_BOT_ERROR_AUTH_FAILED, content_type="text/plain", status=400)

        qid = callback_json.get("qid")
        # rest_log(f'Question ID: {qid}')

        if not qid:
            return HttpResponse(SLACK_BOT_ERROR_ANSWER_FILE_NOT_FOUND, content_type="text/plain", status=400)

        answer_filename = f"{qid}.json"
        answer_path = f"{state_dir}/{answer_filename}"
        if not _is_safe_path(state_dir, answer_path):
            return HttpResponse(SLACK_BOT_ERROR_INVALID_FILE_PATH, content_type="text/plain", status=400)

        final_payload = process_payload(payload, answer_path)

        try:
            with open(answer_path, "w") as answer_file:  # nosemgrep
                answer_file.write(json.dumps(final_payload))
        except Exception as e:
            return HttpResponse(SLACK_BOT_ERROR_WHILE_WRITING_ANSWER_FILE.format(error=e), content_type="text/plain", status=400)

        confirmation = callback_json.get("confirmation", "Received response")
        return HttpResponse(f"Response: {confirmation}", content_type="text/plain", status=200)

    except Exception as e:
        return HttpResponse(SLACK_BOT_ERROR_PROCESS_RESPONSE.format(error=e), content_type="text/plain", status=500)


# Define the App Class
class SlackBotConnector(phantom.BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._base_url = None
        self._state = {}
        self._timeout = None
        self._socket_token = None
        self._command_permissions = {}
        self._permitted_users = None
        self._log_level = None

    def encrypt_state(self, encrypt_var, token_name):
        """Handle encryption of token.
        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        self.debug_print(SLACK_BOT_ENCRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.encrypt(encrypt_var, self.get_asset_id())

    def decrypt_state(self, decrypt_var, token_name):
        """Handle decryption of token.
        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        self.debug_print(SLACK_BOT_DECRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.decrypt(decrypt_var, self.get_asset_id())

    def initialize(self):
        config = self.get_config()
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        self._bot_token = config.get(SLACK_BOT_JSON_BOT_TOKEN)
        self._socket_token = config.get(SLACK_BOT_JSON_SOCKET_TOKEN)
        self._soar_auth_token = config.get(SLACK_BOT_JSON_SOAR_AUTH_TOKEN)
        self._command_permissions = {permission: config.get(permission.value, False) for permission in CommandPermission}
        self._permitted_users = config.get(SLACK_BOT_JSON_PERMITTED_USERS, False)
        self._log_level = config.get(SLACK_BOT_JSON_LOG_LEVEL)
        self._base_url = SLACK_BASE_URL

        ret_val, ph_base_url = self._get_phantom_base_url_slack(self)
        if phantom.is_fail(ret_val):
            return ret_val
        ph_base_url += "/" if not ph_base_url.endswith("/") else ""

        # Storing Bot file required data in state file
        self._state["ph_base_url"] = ph_base_url
        self._state[SLACK_BOT_JSON_SOAR_AUTH_TOKEN] = self._soar_auth_token
        self._state[SLACK_BOT_JSON_BOT_TOKEN] = self._bot_token
        self._state[SLACK_BOT_JSON_SOCKET_TOKEN] = self._socket_token
        for permission, is_granted in self._command_permissions.items():
            self._state[permission.value] = is_granted
        self._state[SLACK_BOT_JSON_PERMITTED_USERS] = self._permitted_users
        self._state[SLACK_BOT_JSON_LOG_LEVEL] = self._log_level

        return phantom.APP_SUCCESS

    def finalize(self):
        # Encrypting tokens
        try:
            if self._bot_token:
                self._state[SLACK_BOT_JSON_BOT_TOKEN] = self.encrypt_state(self._bot_token, "bot")

            if self._socket_token:
                self._state[SLACK_BOT_JSON_SOCKET_TOKEN] = self.encrypt_state(self._socket_token, "socket")

            if self._soar_auth_token:
                self._state[SLACK_BOT_JSON_SOAR_AUTH_TOKEN] = self.encrypt_state(self._soar_auth_token, "soar_auth")

        except Exception as e:
            self.debug_print(f"{SLACK_BOT_ENCRYPTION_ERROR}: {self._get_error_message_from_exception(e)}")
            return self.set_status(phantom.APP_ERROR, SLACK_BOT_ENCRYPTION_ERROR)

        self._state[SLACK_BOT_STATE_IS_ENCRYPTED] = True
        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)

        return phantom.APP_SUCCESS

    @staticmethod
    def _is_port_in_use(host, port):
        """
        True if the port is in use on the host.

        Source: https://stackoverflow.com/a/52872579
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            return sock.connect_ex((host, port)) == 0

    def _get_phantom_base_url_slack(self, action_result):
        base_url = self.get_phantom_base_url()
        rest_url = SoarRestEndpoint.SYSTEM_INFO.url(base_url)

        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False)

        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        phantom_base_url = resp_json.get("base_url")

        if not phantom_base_url:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_BASE_URL_NOT_FOUND))

        def replace_port(parsed_url, new_port):
            return parsed_url._replace(netloc=f"{parsed_url.hostname}:{new_port}")

        # For on-prem instances 443 does not necessarily work when querying the
        # real instance URL outside of an app context if it is NRI.
        parsed_base_url = urlparse(phantom_base_url)
        soar_hostname = parsed_base_url.hostname
        soar_port = parsed_base_url.port or 443
        if not self._is_port_in_use(soar_hostname, soar_port):
            if self._is_port_in_use(soar_hostname, SOAR_NRI_HTTPS_PORT):
                phantom_base_url = replace_port(parsed_base_url, SOAR_NRI_HTTPS_PORT).geturl()
            else:
                return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_BASE_URL_UNREACHABLE))

        self.debug_print(f"Set SOAR base URL for Slack Bot to {phantom_base_url}")
        return RetVal(phantom.APP_SUCCESS, phantom_base_url)

    def _process_empty_reponse(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_EMPTY_RESPONSE.format(code=response.status_code)), None)

    def _process_html_response(self, response, action_result):
        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = SLACK_BOT_UNABLE_TO_PARSE_ERROR_DETAILS

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, SLACK_BOT_ERROR_UNABLE_TO_PARSE_JSON_RESPONSE.format(error=self._get_error_message_from_exception(e))
                ),
                None,
            )

        # The 'ok' parameter in a response from slack says if the call passed or failed
        if resp_json.get("ok", "") is not False:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        action_result.add_data(resp_json)

        error = resp_json.get("error", "")
        if error == "invalid_auth":
            error = SLACK_BOT_ERROR_BOT_TOKEN_INVALID
        elif error == "not_in_channel":
            error = SLACK_BOT_ERROR_NOT_IN_CHANNEL
        elif not error:
            error = SLACK_BOT_ERROR_FROM_SERVER

        return RetVal(action_result.set_status(phantom.APP_ERROR, error), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, "add_debug_data"):
            if r is not None:
                action_result.add_debug_data({"r_status_code": r.status_code})
                action_result.add_debug_data({"r_text": r.text})
                action_result.add_debug_data({"r_headers": r.headers})
            else:
                action_result.add_debug_data({"r_text": "r is None"})
                return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_NO_RESPONSE_FROM_SERVER), None)

        # There are just too many differences in the response to handle all of them in the same function
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successfull empty reponse
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {} Data from server: {}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_message = SLACK_BOT_ERROR_MESSAGE_UNAVAILABLE

        self.error_print("Error occurred.", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            self.error_print(f"Error occurred while fetching exception information. Details: {e!s}")

        if not error_code:
            error_text = f"Error Message: {error_message}"
        else:
            error_text = f"Error Code: {error_code}. Error Message: {error_message}"

        return error_text

    def _make_rest_call(self, action_result, rest_url, verify, method=requests.get, headers={}, body={}):
        try:
            r = method(rest_url, verify=verify, headers=headers, data=json.dumps(body))
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"{SLACK_BOT_ERROR_REST_CALL_FAILED}. {self._get_error_message_from_exception(e)}"),
                None,
            )

        try:
            resp_json = r.json()
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_UNABLE_TO_DECODE_JSON_RESPONSE), None)

        if "failed" in resp_json:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "{}. Message: {}".format(SLACK_BOT_ERROR_REST_CALL_FAILED, resp_json.get("message", "NA"))
                ),
                None,
            )

        if 200 <= r.status_code <= 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        details = "NA"

        if resp_json:
            details = json.dumps(resp_json).replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, f"Error from server: Status code: {r.status_code} Details: {details}"), None)

    def _make_slack_rest_call(self, action_result, endpoint, body, headers={}, files={}):
        body.update({"token": self._bot_token})

        # send api call to slack
        try:
            response = requests.post(f"{self._base_url}{endpoint}", data=body, headers=headers, files=files, timeout=SLACK_BOT_DEFAULT_TIMEOUT)
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"{SLACK_BOT_ERROR_SERVER_CONNECTION}. {self._get_error_message_from_exception(e)}"),
                None,
            )

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
                action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_INVALID_INT.format(key=key))
                return None

            parameter = int(parameter)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_INVALID_INT.format(key=key))
            return None

        if parameter < 0:
            action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_NEGATIVE_INT.format(key=key))
            return None
        if not allow_zero and parameter == 0:
            action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_NEGATIVE_AND_ZERO_INT.format(key=key))
            return None

        return parameter

    def _test_connectivity(self, param):
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_BOT_AUTH_TEST, {})

        if not ret_val:
            self.save_progress(SLACK_BOT_ERROR_TEST_CONNECTIVITY_FAILED)
            return ret_val

        action_result.add_data(resp_json)

        self.save_progress("Auth check to Slack passed. Configuring app for team, {}".format(resp_json.get("team", "Unknown Team")))

        bot_username = resp_json.get("user")
        bot_user_id = resp_json.get("user_id")

        self.save_progress(f"Got username, {bot_username}, and user ID, {bot_user_id}, for the bot")

        self._state["bot_name"] = bot_username
        self._state["bot_id"] = bot_user_id

        self.save_progress(SLACK_BOT_SUCCESS_TEST_CONNECTIVITY_PASSED)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _set_bot_id(self, action_result):
        """
        Get the current bot ID and set it in the state file.

        We need to save the bot username and bot id to state file in case test connectivity has not been run.
        Otherwise, certain bot actions will fail if these values do not exist in the state file loaded when
        starting the bot.
        """
        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_BOT_AUTH_TEST, {})
        if not ret_val:
            return ret_val

        bot_id = resp_json.get("user_id")
        bot_username = resp_json.get("user")

        if not bot_id:
            return action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_COULD_NOT_GET_BOT_ID)

        self._state["bot_name"] = bot_username
        self._state["bot_id"] = bot_id
        self.save_state(self._state)

    def _start_bot(self, param):
        self.debug_print("Inside start bot action")
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        set_bot_id_failure_result = self._set_bot_id(action_result)
        if set_bot_id_failure_result:
            return set_bot_id_failure_result

        pid = self._state.get("pid")
        self.debug_print(f"PID of Bot : {pid}")
        if pid:
            try:
                if SLACK_BOT_PROCESS_NAME in sh.ps("ww", pid):  # pylint: disable=E1101
                    self.save_progress(f"Detected Slack Bot running with pid {pid}")
                    return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_SUCCESS_SLACK_BOT_RUNNING)
            except Exception:
                pass

        asset_id = self.get_asset_id()
        app_version = self.get_app_json().get("app_version", "")

        try:
            ps_out = sh.grep(sh.ps("ww", "aux"), SLACK_BOT_PROCESS_NAME)  # pylint: disable=E1101
            old_pid = shlex.split(str(ps_out))[1]
            if app_version not in ps_out:
                self.save_progress(
                    f"Found an old version of {SLACK_BOT_PROCESS_NAME} running with PID {old_pid}. "
                    "Please stop it before trying to start a new bot."
                )
                return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_ERROR_OLD_SLACK_BOT_VERSION_RUNNING)
            elif asset_id in ps_out:  # pylint: disable=E1101
                self._state["pid"] = int(old_pid)
                return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_ERROR_SLACK_BOT_RUNNING_WITH_SAME_BOT_TOKEN)
        except Exception:
            pass

        slack_bot_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), SLACK_BOT_PROCESS_NAME)

        # check if the socket token is valid
        headers = {"Authorization": f"Bearer {self._socket_token}"}
        url = f"{SLACK_BASE_URL}apps.connections.open"
        resp = requests.post(url, headers=headers, timeout=30)
        resp = resp.json()

        if not resp.get("ok"):
            self.save_progress("Failed to start Slack Bot")
            return action_result.set_status(phantom.APP_ERROR, SLACK_BOT_SOCKET_TOKEN_ERROR)

        self.save_progress("Starting Slack Bot")
        proc = subprocess.Popen([sys.executable, slack_bot_filename, asset_id, app_version])
        self._state["pid"] = proc.pid
        self.save_progress(f"Started Slack Bot with pid: {proc.pid}")

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_SUCCESS_SLACK_BOT_STARTED)

    def _stop_bot(self, param):
        self.debug_print("Inside stop bot action")
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        pid = self._state.get("pid")
        self.debug_print(f"PID of Bot : {pid}")
        if pid:
            self._state.pop("pid")
            try:
                if SLACK_BOT_PROCESS_NAME in sh.ps("ww", pid):  # pylint: disable=E1101
                    try:
                        sh.kill(pid)  # pylint: disable=E1101
                        return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_SUCCESS_SLACK_BOT_STOPPED)
                    except Exception:
                        return action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_COUDNT_STOP_SLACK_BOT)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_SLACK_BOT_NOT_RUNNING)
        else:
            try:
                ps_out = sh.grep(sh.ps("ww", "aux"), SLACK_BOT_PROCESS_NAME)
                pid = shlex.split(str(ps_out))[1]
                try:
                    sh.kill(pid)  # pylint: disable=E1101
                    return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_SUCCESS_SLACK_BOT_STOPPED)
                except Exception:
                    return action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_COUDNT_STOP_SLACK_BOT)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, SLACK_BOT_ERROR_SLACK_BOT_NOT_RUNNING)

    def _on_poll(self, param):
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        set_bot_id_failure_result = self._set_bot_id(action_result)
        if set_bot_id_failure_result:
            return set_bot_id_failure_result

        # we are using container count to decide if we will restart the bot or not
        container_count = int(param.get("container_count"))

        pid = self._state.get("pid")
        if pid:
            try:
                # use manual on poll action to 'reload' state file into slack_bot_standalone.py
                if self.is_poll_now():
                    self.save_progress(f"Container Count: {container_count}")
                    if container_count == 1234:
                        sh.kill(pid)
                        self.save_progress(f"Container count set to 1234, stopping {SLACK_BOT_PROCESS_NAME} at pid {pid}")
                    elif container_count == int(pid):
                        sh.kill(pid)
                        self.save_progress("pid passed in as container count, stopping bot")
                        return action_result.set_status(phantom.APP_SUCCESS, "bot has been stopped")
                    else:
                        self.save_progress("HINT: Set Maximum Containers to 1234 to restart slack_bot, or set to PID to stop slack_bot")

                if SLACK_BOT_PROCESS_NAME in sh.ps("ww", pid):  # pylint: disable=E1101
                    self.save_progress(f"Detected Slack Bot running with pid {pid}")
                    return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_SUCCESS_SLACK_BOT_RUNNING)
            except Exception:
                pass

        asset_id = self.get_asset_id()
        app_version = self.get_app_json().get("app_version", "")

        try:
            ps_out = sh.grep(sh.ps("ww", "aux"), SLACK_BOT_PROCESS_NAME)  # pylint: disable=E1101
            old_pid = shlex.split(str(ps_out))[1]
            if app_version not in ps_out:
                self.save_progress(f"Found an old version of slack_bot running with pid {old_pid}, going to kill it")
                sh.kill(old_pid)  # pylint: disable=E1101
            elif asset_id in ps_out:  # pylint: disable=E1101
                self._state["pid"] = int(old_pid)
                return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_ERROR_SLACK_BOT_RUNNING_WITH_SAME_BOT_TOKEN)
        except Exception:
            pass

        slack_bot_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), SLACK_BOT_PROCESS_NAME)

        # check if the socket token is valid
        headers = {"Authorization": f"Bearer {self._socket_token}"}
        url = f"{SLACK_BASE_URL}apps.connections.open"
        resp = requests.post(url, headers=headers, timeout=30)
        resp = resp.json()

        if not resp.get("ok"):
            self.save_progress("Failed to start Slack Bot")
            return action_result.set_status(phantom.APP_ERROR, SLACK_BOT_SOCKET_TOKEN_ERROR)

        self.save_progress("Starting Slack Bot")
        proc = subprocess.Popen([sys.executable, slack_bot_filename, asset_id, app_version])
        self._state["pid"] = proc.pid
        self.save_progress(f"Started Slack Bot with pid: {proc.pid}")

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_BOT_SUCCESS_SLACK_BOT_STARTED)

    def handle_action(self, param):
        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print(f"action_id: {self.get_action_identifier()}")

        if action_id == ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == ACTION_ID_START_BOT:
            ret_val = self._start_bot(param)
        elif action_id == ACTION_ID_STOP_BOT:
            ret_val = self._stop_bot(param)
        elif action_id == ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)

        return ret_val


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SlackBotConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
