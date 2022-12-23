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

from argparse import ArgumentParser

import slack_bot_consts as constants
from commands.command import Command

HELP_MESSAGE = """
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


class RunActionCommand(Command):
    """ Run Action Command. """

    HELP_MESSAGE = HELP_MESSAGE

    def _create_parser(self):
        action_parser = ArgumentParser(add_help=False, exit_on_error=False)
        action_parser.add_argument('action')
        action_parser.add_argument('--help', dest='aid', action='store_true')
        action_parser.add_argument('--container')
        action_parser.add_argument('--name', default='Slack generated action')
        action_parser.add_argument('--type', dest='typ', default='phantombot')
        action_parser.add_argument('--asset')
        action_parser.add_argument('--parameters', nargs='+')
        return action_parser

    def parse(self, command):
        """ Parse the specified command string. """
        parse_success, result = self._get_parsed_args(command)

        if not parse_success:
            return False, result

        parsed_args = result

        request_body = {}
        request_body['targets'] = []

        asset = parsed_args.asset
        action = parsed_args.action
        params = parsed_args.parameters
        container = parsed_args.container

        action_list = self.slack_bot.get_action_list_from_name(action)
        if not action_list:
            return False, f'Could not find action, {action}'

        if asset:
            message, result_asset, result_action = self.slack_bot._parse_asset(asset, action, action_list)

            if not (result_asset and result_action):
                return False, message

            asset_object = result_asset
            action_object = result_action

        if parsed_args.aid or not container:

            if asset:
                total_message = f'Info on {action} action on {asset} asset:\n'
            else:
                total_message = f'List of available "{action}" actions:\n'

            for action_object in action_list:

                if not action_object.assets:
                    continue

                if asset and asset_object.asset_id not in action_object.assets:
                    continue

                try:

                    message = f'ID: {action_object.action_id}\n'
                    message += f'App: {self.slack_bot.app_dict[action_object.app].name}\n'

                    message += 'Assets: '

                    for ass in action_object.assets:

                        message += f'{self.slack_bot.asset_dict[ass].name}, '

                    message = message[:-2]
                    message += '\nParameters:\n'

                    for param in list(action_object.parameters.values()):

                        message += f'  {param.name}:\n'
                        message += f'    Data Type: {param.data_type}\n'
                        message += f'    Required: {param.required}\n'

                    total_message += f'\n{message}'

                except Exception:
                    continue

            if not container:
                total_message += ('\nThis help message was printed because no container ID was provided.'
                                  '\nPlease specify a container if you would like to run this action.')

            return False, total_message

        request_body['action'] = action
        request_body['type'] = parsed_args.typ
        request_body['name'] = parsed_args.name
        request_body['container_id'] = container

        # If an asset was passed as an argument, we only want to run one action
        if asset:

            target = {}
            target['app_id'] = asset_object.apps[0]
            target['assets'] = [asset_object.asset_id]

            ret_val, message = self.slack_bot._parse_params(params, action_object.parameters, target)

            if not ret_val:
                return False, message

            request_body['targets'].append(target)

        # If no asset argument was passed, we need to find all actions that have the name given
        else:

            for action_object in action_list:

                if not action_object.assets:
                    continue

                target = {}
                target['app_id'] = action_object.app
                target['assets'] = action_object.assets

                ret_val, message = self.slack_bot._parse_params(params, action_object.parameters, target)

                if not ret_val:
                    return False, message

                request_body['targets'].append(target)

            if not request_body['targets']:
                return False, 'There are no valid assets to run this action on.'

        return True, request_body

    def execute(self, request_body, channel):
        """ Execute the specified request body for the command and post the result on the specified channel. """

        try:
            action_run_request = self.slack_bot._soar_post(constants.SoarRestEndpoint.ACTION_RUN,
                                                           body=request_body)
            response = action_run_request.json()
        except Exception as e:
            return f'Failed to run action: Could not connect to Phantom REST endpoint: {e}'

        if response.get('failed'):
            error = response.get('message', 'unknown error')

            if '"Container.owner" must be a "PhUser" instance' in error:
                return 'Failed to run action: A container must have an owner to run an action on it.\n\n'

            return f'Failed to run action: {error}\n\n'

        run_id = response.get('action_run_id')

        if not run_id:
            return 'Failed to run action: Could not get action run ID'

        self.slack_bot.action_queue.append((run_id, channel))

        action_url = f'{self.slack_bot.phantom_url}action/{run_id}'

        self.slack_bot._post_message(f'Action run URL: {action_url}', channel, code_block=False)

        return f'Message: {response["message"]}\nAction run ID: {run_id}'
