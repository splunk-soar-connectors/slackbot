# File: slack_bot_consts.py
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

# Action IDs
ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
ACTION_ID_START_BOT = "start_bot"
ACTION_ID_STOP_BOT = "stop_bot"
ACTION_ID_ON_POLL = "on_poll"

SOAR_NRI_HTTPS_PORT = 9999

SLACK_BASE_URL = "https://slack.com/api/"

# This value should match the filename for the standalone process
SLACK_BOT_PROCESS_NAME = "slack_bot_standalone.py"

SLACK_BOT_JSON_BOT_TOKEN = "bot_token"
SLACK_BOT_JSON_SOAR_AUTH_TOKEN = "soar_auth_token"
SLACK_BOT_JSON_SOCKET_TOKEN = "socket_token"
SLACK_BOT_JSON_PERMITTED_USERS = "permitted_bot_users"
SLACK_BOT_JSON_LOG_LEVEL = "log_level"
SLACK_BOT_JSON_MESSAGE_LIMIT = 4000

SLACK_BOT_APP_ID = "2591bdbc-21e1-4aa1-bf64-e2aa5c733a4a"

SLACK_BOT_AUTH_TEST = "auth.test"

SLACK_BOT_ERROR_FROM_SERVER = "Got unknown error from the Slack server"
SLACK_BOT_ERROR_INVALID_FILE_PATH = "The file path is invalid"
SLACK_BOT_ERROR_INVALID_INT = "Please provide a valid integer value in the {key} parameter"
SLACK_BOT_ERROR_NEGATIVE_AND_ZERO_INT = "Please provide a valid non-zero positive integer value in the {key} parameter"
SLACK_BOT_ERROR_NEGATIVE_INT = "Please provide a valid non-negative integer value in the {key} parameter"
SLACK_BOT_ERROR_PAYLOAD_NOT_FOUND = "Found no payload field in rest post body"
SLACK_BOT_ERROR_CALLBACK_ID_NOT_FOUND = "Found no callback_id field in payload"
SLACK_BOT_ERROR_PARSE_JSON_FROM_CALLBACK_ID = "Could not parse JSON from callback_id field in payload: {error}"
SLACK_BOT_ERROR_STATE_FILE_NOT_FOUND = "Found no state filename in callback"
SLACK_BOT_ERROR_UNABLE_TO_READ_STATE_FILE = "Could not properly read state file: {error}"
SLACK_BOT_ERROR_AUTH_FAILED = "Authorization failed. Tokens do not match."
SLACK_BOT_ERROR_ANSWER_FILE_NOT_FOUND = "Found no answer filename in callback"
SLACK_BOT_ERROR_WHILE_WRITING_ANSWER_FILE = "Error occurred while writing in answer file: {error}"
SLACK_BOT_ERROR_PROCESS_RESPONSE = "There was an error processing the response: {error}"
SLACK_BOT_ERROR_BASE_URL_NOT_FOUND = "SOAR Base URL not found. Please specify this value in System Settings"
SLACK_BOT_ERROR_BASE_URL_UNREACHABLE = "SOAR Base URL is not reachable. Please verify the value in System Settings"
SLACK_BOT_ERROR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header"
SLACK_BOT_UNABLE_TO_PARSE_ERROR_DETAILS = "Cannot parse error details"
SLACK_BOT_ERROR_UNABLE_TO_PARSE_JSON_RESPONSE = "Unable to parse response as JSON. {error}"
SLACK_BOT_ERROR_BOT_TOKEN_INVALID = "The configured bot token is invalid"
SLACK_BOT_ERROR_NOT_IN_CHANNEL = "The configured bot is not in the specified channel. Invite the bot to that channel to send messages there."
SLACK_BOT_ERROR_UNABLE_TO_DECODE_JSON_RESPONSE = "Unable to decode the response as JSON"
SLACK_BOT_ERROR_REST_CALL_FAILED = "REST call failed"
SLACK_BOT_ERROR_TEST_CONNECTIVITY_FAILED = "Test Connectivity Failed"
SLACK_BOT_SUCCESS_TEST_CONNECTIVITY_PASSED = "Test Connectivity Passed"
SLACK_BOT_SUCCESS_SLACK_BOT_STOPPED = "Slack Bot has been stopped."
SLACK_BOT_ERROR_SLACK_BOT_NOT_RUNNING = "Slack Bot isn't running, not going to stop it."
SLACK_BOT_ERROR_COUDNT_STOP_SLACK_BOT = "Something went wrong, wasn't able to stop the BOT. Please rerun the stop bot action"
SLACK_BOT_ERROR_COULD_NOT_GET_BOT_ID = "Could not get bot ID from Slack"
SLACK_BOT_SUCCESS_SLACK_BOT_RUNNING = "Slack Bot already running"
SLACK_BOT_ERROR_SLACK_BOT_RUNNING_WITH_SAME_BOT_TOKEN = (
    "Detected an instance of Slack Bot running with the same bot token. Not going to start new instance."
)
SLACK_BOT_ERROR_OLD_SLACK_BOT_VERSION_RUNNING = "Detected a different version of Slack Bot already running. Not going to start new instance."
SLACK_BOT_SUCCESS_SLACK_BOT_STARTED = "Slack Bot started"

SLACK_BOT_ERROR_NO_RESPONSE_FROM_SERVER = "Got no response from the Slack server"
SLACK_BOT_ERROR_COMMAND_NOT_PERMITTED = "This command is not permitted to be run on this asset"

SLACK_BOT_RESP_POLL_INTERVAL_KEY = '"How often to poll for a response (in seconds)" configuration'
SLACK_BOT_TIMEOUT_KEY = '"Question timeout (in minutes)" configuration'

SLACK_BOT_DEFAULT_TIMEOUT = 30

SLACK_BOT_SOCKET_TOKEN_ERROR = "Invalid Socket Token please update the configuration file and rerun test connectivity"

SLACK_BOT_STATE_IS_ENCRYPTED = "is_encrypted"

# For encryption and decryption
SLACK_BOT_ENCRYPT_TOKEN = "Encrypting the {} token"
SLACK_BOT_DECRYPT_TOKEN = "Decrypting the {} token"
SLACK_BOT_ENCRYPTION_ERROR = "Error occurred while encrypting the state file"
SLACK_BOT_DECRYPTION_ERROR = "Error occurred while decrypting the state file"

SLACK_BOT_ERROR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
