# File: run_action.py
#
# Copyright (c) 2023 Splunk Inc.
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

SLACK_BOT_ACTION_HELP_MESSAGE = """
usage:

act ACTION_NAME [--container CONTAINER_ID] [--asset ASSET] [--name NAME]
    [--TYPE TYPE] [--parameters PARAMETER:VALUE [PARAMETER:VALUE]*]

required arguments:
  ACTION_NAME               Name of the action to run
  --container CONTAINER_ID  ID of the container to run the action on

optional arguments:
  --help                    show this help message or show information about the specified action
  --name NAME               Set a name for the action (defaults to 'Slack generated action')
  --type TYPE               Set the type of the action (defaults to 'phantombot')
  --asset ASSET             Name or ID of the asset to run the action on
                            If no asset is specified, the given action will run on all possible assets
  --parameters PARAMETER:VALUE [PARAMETER:VALUE]*]
                            List of parameter/value pairs in the format
                            param1:value1 param2:value2...

For example:
    @<bot_username> act "geolocate ip" --parameters ip:1.1.1.1 --container 1291
"""
