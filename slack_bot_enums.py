# File: slack_bot_consts.py
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

from enum import Enum


class SoarRestEndpoint(str, Enum):
    """ SOAR v1 endpoints. """

    ACTION_RUN = 'action_run'
    APP = 'app'
    APP_ACTION = 'app_action'
    APP_RUN = 'app_run'
    APP_RUNS = 'action_run/{}/app_runs'
    ASSET = 'asset'
    BUILD_ACTION = 'build_action'
    CONTAINER = 'container'
    PLAYBOOK = 'playbook'
    PLAYBOOK_RUN = 'playbook_run'
    SYSTEM_INFO = 'system_info'

    @property
    def path(self):
        """ Return the full path for the endpoint. """
        return f'rest/{self.value}'

    def url(self, base_url):
        """ Create a full URL including the path and specified base URL. """
        base_url = base_url.rstrip('/')
        return f'{base_url}/{self.path}'


class CommandPermission(Enum):
    """
    Slack Bot Command Permissions.

    The name should match the command names (besides case).
    The value should match the asset configuration name of the permission.
    """
    GET_ACTION = 'permit_bot_get_action'
    RUN_ACTION = 'permit_bot_run_action'
    GET_PLAYBOOK = 'permit_bot_get_playbook'
    RUN_PLAYBOOK = 'permit_bot_run_playbook'
    GET_CONTAINER = 'permit_bot_get_container'
