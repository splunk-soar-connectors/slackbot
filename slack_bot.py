# File: slack_bot.py
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
import logging
import os
import shlex
import sys
import tempfile
from pathlib import Path

import encryption_helper
import requests
import simplejson as json
import urllib3
from slack_bolt import App as slack_app
from slack_bolt.adapter.socket_mode import SocketModeHandler

from commands.get_container import GetContainerCommand
from commands.list import ListCommand
from commands.run_action import RunActionCommand
from commands.run_playbook import RunPlaybookCommand
from slack_bot_consts import *

urllib3.disable_warnings()

app_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(f'{app_dir}/dependencies'):
    os.sys.path.insert(0, f'{app_dir}/dependencies/websocket-client')
    os.sys.path.insert(0, f'{app_dir}/dependencies')


SLACK_BOT_HELP_MESSAGE = """
usage:

@<bot_username> act|run_playbook|get_container|list

For more information on a specific command, try @<bot_username> <command> --help
"""


def create_query_string():
    """ Create a query URL string from a query parameters dictionary. """
    if not query_parameters:
        return ''

    return '?' + '&'.join(f'{key}={value}' for key, value in query_parameters.items())


def _load_app_state(asset_id):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :return: state: Current state file as a dictionary
    """
    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        logging.info('In _load_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))

    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)
    real_state_file_path = os.path.realpath(state_file)

    if os.path.dirname(real_state_file_path) != app_dir:
        logging.info('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)

    except Exception:
        logging.exception('In _load_app_state: Exception encountered.')

    logging.info('Loaded state: ', state)

    return state


def decrypt_state(asset_id, decrypt_var, token_name):
    """ Handle decryption of token.
    :param decrypt_var: Variable needs to be decrypted
    :return: decrypted variable
    """
    logging.debug(SLACK_BOT_DECRYPT_TOKEN.format(token_name))    # nosemgrep
    return encryption_helper.decrypt(decrypt_var, asset_id)


class Action():

    def __init__(self, name, action_id, app):

        self.name = name
        self.action_id = action_id
        self.app = app
        self.assets = []
        self.parameters = {}

    def add_parameters(self, params):

        for param_name, param_dict in params.items():

            required = param_dict.get('required', False)
            data_type = param_dict['data_type']

            self.parameters[param_name] = Parameter(param_name, required, data_type)


class Parameter():

    def __init__(self, name, required, data_type):

        self.name = name
        self.required = required
        self.data_type = data_type


class Asset():

    def __init__(self, name, asset_id, apps):

        self.name = name
        self.asset_id = asset_id
        self.apps = apps


class App():

    def __init__(self, name, app_id):

        self.name = name
        self.app_id = app_id


class SlackBot(object):

    def __init__(self, bot_token, socket_token, bot_id, base_url='https://127.0.0.1/', verify=False, auth_token='',
                 permit_act=False, permit_playbook=False, permit_container=False, permit_list=False, permitted_users='', auth_basic=()):
        """ This should be changed to some kind of load config thing """
        self.bot_token = bot_token
        self.socket_token = socket_token
        self.permit_act = permit_act
        self.permit_playbook = permit_playbook
        self.permit_container = permit_container
        self.permit_list = permit_list
        self.permitted_users = permitted_users
        self.headers = {} if not auth_token else {'ph-auth-token': auth_token}
        self.cmd_start = '<@{}>'.format(bot_id)
        self.auth = auth_basic
        self.verify = verify
        base_url += '/' if not base_url.endswith('/') else ''
        self.base_url = base_url
        self.phantom_url = base_url
        self.verification_token = None
        self._generate_dicts()

    def _soar_get(self, endpoint: SoarRestEndpoint, query_parameters: dict, path_postfix=''):
        """ Make a SOAR GET request. """
        return requests.get(
            f'{endpoint.full_path(self.base_url)}{path_postfix}{create_query_string(query_parameters)}',
            headers=self.headers,
            auth=self.auth,
            verify=self.verify,
            timeout=SLACK_BOT_DEFAULT_TIMEOUT,
        )

    def _soar_post(self, endpoint: SoarRestEndpoint, body: dict):
        """ Make a SOAR POST request. """
        return requests.post(
            endpoint.full_path(self.base_url),
            json=body,
            headers=self.headers,
            auth=self.auth,
            verify=self.verify,
            timeout=SLACK_BOT_DEFAULT_TIMEOUT,
        )

    def _generate_dicts(self):
        """
        In order to easily keep track of and verify actions
        phantom.bot creates a couple of dictionaries
        """
        self.app_dict = {}
        self.asset_dict = {}
        self.action_dict = {}
        self.app_to_asset_dict = {}

        self._create_app_dict()
        self._create_asset_dict()

    def _create_app_dict(self):
        """ Maps app IDs and names to app objects """

        try:
            query_parameters = {}
            query_parameters['page_size'] = 0
            query_parameters['pretty'] = True
            r = requests.get(f'{SoarRestEndpoint.APP.full_path(self.base_url)}{create_query_string(query_parameters)}',
                             headers=self.headers,
                             auth=self.auth,
                             verify=self.verify,
                             timeout=SLACK_BOT_DEFAULT_TIMEOUT)
        except Exception:
            return

        if r.status_code != 200:
            return

        for app in r.json().get('data', []):

            app_name = app.get('name', '')
            app_id = app.get('id')

            if not (app_id and app_name):
                continue

            app_object = App(app_name, app_id)

            self.app_dict[app_id] = app_object
            self.app_dict[app_name] = app_object

    def _create_asset_dict(self):
        """
        Maps asset IDs and names to asset objects
        Also maps app IDs to lists of associated asset IDs
        """

        try:
            r = requests.get(SoarRestEndpoint.BUILD_ACTION.full_path(self.base_url),
                             headers=self.headers,
                             auth=self.auth,
                             verify=self.verify,
                             timeout=SLACK_BOT_DEFAULT_TIMEOUT)
        except Exception:
            return

        if r.status_code != 200:
            return

        for asset in r.json().get('assets', []):

            asset_name = asset.get('name', '')
            asset_id = asset.get('id')
            asset_apps = asset.get('apps', [])

            if len(asset_apps) > 1:

                for app_id in asset_apps:

                    app = self.app_dict.get(app_id)

                    if not app:
                        asset_apps.remove(app_id)

            if not (asset_id and asset_name):
                continue

            for app in asset_apps:

                if app not in self.app_to_asset_dict:
                    self.app_to_asset_dict[app] = []

                self.app_to_asset_dict[app] += [asset_id]

            asset_object = Asset(asset_name, asset_id, asset_apps)

            self.asset_dict[asset_id] = asset_object
            self.asset_dict[asset_name] = asset_object

    def get_action_list_from_name(self, action_name):
        """ Return a list of available action objects with the given action_name. """
        try:
            query_parameters = {}
            query_parameters['page_size'] = 0
            query_parameters['_filter_action'] = f'"{action_name}"'
            action_request = requests.get(
                f'{SoarRestEndpoint.APP_ACTION.full_path(self.base_url)}{create_query_string(query_parameters)}',
                headers=self.headers,
                auth=self.auth,
                verify=self.verify,
                timeout=SLACK_BOT_DEFAULT_TIMEOUT
            )
            action_request.raise_for_status()
        except Exception:
            logging.exception('Failed to query for action name "%s"', action_name)
            return []

        action_list = []
        for action in action_request.json().get('data', []):
            action_name = action.get('action')
            action_id = action.get('id')
            action_app = action.get('app')

            if not (action_name and action_id and action_app):
                continue

            action_object = Action(action_name, action_id, action_app)
            action_object.add_parameters(action['parameters'])
            action_object.assets = self.app_to_asset_dict.get(action_app, [])
            action_list.append(action_object)

        return action_list

    def _create_container_dict(self):
        """ Maps container IDs to container objects """

        try:
            query_parameters = {}
            query_parameters['page_size'] = 0
            r = requests.get(f'{SoarRestEndpoint.CONTAINER.full_path(self.base_url)}{create_query_string(query_parameters)}',
                             headers=self.headers,
                             auth=self.auth,
                             verify=self.verify,
                             timeout=SLACK_BOT_DEFAULT_TIMEOUT)
        except Exception:
            return None

        if r.status_code != 200:
            return None

        container_dict = {}

        for container in r.json().get('data', []):

            container_id = container.get('id')

            if not container_id:
                continue

            tags = container['tags']

            for tag in tags:

                if tag not in container_dict:
                    container_dict[tag] = []

                container_dict[tag].append(container_id)

        return container_dict

    def _sanitize(self, string):
        """ Slack quotes use those fancy UTF-8 ones that flip based on what side they are on
          " Unforunately, those cause problems, so we replace them with normal quotes
          " I'm sure there are other UTF-8 characters that will need to be replaced like this,
          " but I haven't run into those yet
          " Emdashes (u2014) are another of those characters.
          " Slack also formats URLs annoyingly. A message containing a domain (eg google.com) will get changed to
          " <http://google.com/|google.com>. While a full URL (eg http://google.com) will get changed to
          " <http://google.com>. Need to look for both cases and get rid of the carrots and pipe (<|>).
          " And in the domain case, get rid of the URL.
        """

        string = (
            string.replace('\xe2\x80\x9c', '"')
            .replace('\xe2\x80\x9d', '"')
            .replace('\xe2\x80\x94', '--')
            .replace('\xe2\x80\x98', "'")
            .replace('\xe2\x80\x99', "'")
        )

        while string.find('<') > -1 and string.find('>') > -1:

            left_index = string.find('<')
            right_index = string.find('>')
            pipe_index = string.find('|')

            if pipe_index > left_index and pipe_index < right_index:

                url = string[pipe_index + 1: right_index]

            else:

                url = string[left_index + 1: right_index]

            string = string.replace(string[left_index: right_index + 1], url, 1)

        return string

    def _post_message(self, message, channel, code_block=True):

        url = SLACK_BASE_URL + 'chat.postMessage'

        body = {}
        body['channel'] = channel
        body['token'] = self.bot_token
        body['as_user'] = True

        if message:

            if len(message) <= SLACK_BOT_JSON_MESSAGE_LIMIT:

                body['text'] = '```{}```'.format(message) if code_block else message

                requests.post(url, data=body, timeout=SLACK_BOT_DEFAULT_TIMEOUT)

                return

            last_newline = message[:SLACK_BOT_JSON_MESSAGE_LIMIT - 1].rfind('\n')

            to_send = message[:last_newline]

            body['text'] = '```{}```'.format(to_send) if code_block else to_send

            requests.post(url, data=body, timeout=SLACK_BOT_DEFAULT_TIMEOUT)

            self._post_message(message[last_newline + 1:], channel, code_block=code_block)

    def _parse_asset(self, asset, action, action_list):

        found1 = True

        if asset not in self.asset_dict:
            found1 = False

        else:

            asset_object = self.asset_dict[asset]

            if len(asset_object.apps) == 0:
                return ('Invalid asset: {}'.format(asset), None, None)

            if len(asset_object.apps) > 1:
                return ('Invalid asset: {} (Temporarily), too many apps to choose from'.format(asset), None, None)

            found2 = False

            for action_object in action_list:

                if asset_object.asset_id in action_object.assets:
                    found2 = True
                    break

        if not found1 or not found2:

            message = 'Asset "{0}" is not valid for action "{1}"\n\nList of valid assets for {1}:\n'.format(asset, action)

            for action_object in action_list:

                for asset_id in action_object.assets:

                    if asset_id in self.asset_dict:
                        message += '\n{}'.format(self.asset_dict[asset_id].name)

            return message, None, None

        return None, asset_object, action_object

    def _parse_params(self, params, param_dict, target):

        if not params and param_dict:

            for param in list(param_dict.values()):

                if param.required:
                    return False, 'Specified action requires parameters, none given'

        if not params:
            return True, None

        parameter_dict = {}

        for param in params:

            spl_param = param.split(':', 1)

            if len(spl_param) < 2:
                return False, 'Action parameters not formatted correctly'

            param_name = spl_param[0]

            if param_name not in param_dict:
                return False, 'Invalid parameter: {}'.format(param_name)

            parameter_dict[param_name] = spl_param[1]

        target['parameters'] = [parameter_dict]

        # Make sure all required parameters are present
        for key, value in param_dict.items():

            if value.required:

                for params in target['parameters']:

                    if key not in params:
                        return False, 'Missing required parameter: {}'.format(key)

        return True, None

    def _from_on_poll(self):
        """
        On poll method helps to establish the web socket connection with slack bot app on you slack
        using the slack-bolt sdk.
        """
        app = slack_app(token=self.bot_token)

        @app.event('app_mention')
        def mention_handler(body, say):
            """
            mention handler function uses a app_mention event decorator to response to the events whenever the bot
            is mentioned in the cat. It receives a json body which contains the data of the event. The command and
            channel name are parsed from the body and passed to command handler to further process the command.
            """
            logging.info('**app_mention handler hit')
            if body:
                user = body.get('event', {}).get('user')
                logging.info('**user that spawned bot command is %s', user)
                if not self._check_user_authorization(user):
                    say('`User {} is not authorized to use this bot`'.format(user))
                    return

                out_text = body.get('event', {}).get('text')
                logging.info('**body exists, app_mention text: %s', out_text)

                if out_text and out_text.startswith(self.cmd_start):
                    if out_text.strip() == self.cmd_start:
                        self._post_message(
                            SLACK_BOT_HELP_MESSAGE,
                            body.get('event', {}).get('channel', '#general'),
                        )

                    channel = body.get('event', {}).get('channel', '#general')
                    command = out_text[len(self.cmd_start):].strip()

                    if command and channel:
                        command = self._sanitize(command)
                        try:
                            self._handle_command(command, channel)
                        except Exception as e:
                            logging.exception('Exception while running command: %s', command)
                            try:
                                self._post_message(
                                    'Could not run command:\n\n{0}\n\n{1}'.format(command, e),
                                    channel,
                                )
                            except Exception as e:
                                self._post_message(
                                    'Could not run command:\n\n{0}'.format(e), channel
                                )

        @app.event('message')
        def handle_message_events(body, logger):
            """
            Ignore handling any general messages. Messages with a mention will be handled by the mention handler.

            Without this no-op handler definition a warning log will get printed every time a message comes in.
            """
            pass

        handler = SocketModeHandler(app, self.socket_token)
        handler.start()

    def _check_user_authorization(self, user):
        logging.info('**Checking authorization for user "%s"', user)
        permitted_users = self.permitted_users

        if not permitted_users:
            logging.info('**No permitted users specified. Falling back to allow all.')
            return True

        else:
            user_list = permitted_users.split(',')
            logging.info('**Permitted_users: %s', user_list)
            if user in user_list:
                logging.info('**User "%s" is permitted to use bot', user)
                return True
            else:
                logging.info('**User "%s" is not permitted to use bot', user)
                return False

    def _check_command_authorization(self, cmd_type):
        if cmd_type == 'act':
            if self.permit_act:
                logging.debug('**Command: "%s" is permitted', cmd_type)
                return True
            else:
                logging.debug('**Command:"%s" is not permitted', cmd_type)
                return False

        if cmd_type == 'run_playbook':
            if self.permit_playbook:
                logging.debug('**Command: "%s" is permitted', cmd_type)
                return True
            else:
                logging.debug('**Command: "%s" is not permitted', cmd_type)
                return False

        if cmd_type == 'get_container':
            if self.permit_container:
                logging.debug('**Command: "%s" is permitted, %s', cmd_type)
                return True
            else:
                logging.debug('**Command: "%s" is not permitted', cmd_type)
                return False

        if cmd_type == 'list':
            if self.permit_list:
                logging.debug('**Command: "%s" is permitted', cmd_type)
                return True
            else:
                logging.debug('**Command: "%s" is not permitted', cmd_type)
                return False
        else:
            return False

    def _handle_command(self, command, channel):

        try:
            args = shlex.split(command)
        except Exception as e:
            self._post_message('Could not parse arguments:\n\n{}'.format(e), channel)
            return

        cmd_type = args[0]
        if cmd_type not in ['act', 'run_playbook', 'get_container', 'list']:
            message = 'Unknown Command\n\n {}'.format(SLACK_BOT_HELP_MESSAGE)
            self._post_message(message, channel)
            return

        if not self._check_command_authorization(cmd_type):
            message = SLACK_BOT_ERROR_COMMAND_NOT_PERMITTED
            self._post_message(message, channel)
            return

        if cmd_type == 'act':
            logging.info('**permit_bot_act: %s', self.permit_act)
            command = RunActionCommand(self)
        elif cmd_type == 'run_playbook':
            logging.info('**permit_bot_playbook: %s', self.permit_playbook)
            command = RunPlaybookCommand(self)
        elif cmd_type == 'get_container':
            logging.info('**permit_bot_container: %s', self.permit_container)
            command = GetContainerCommand(self)
        elif cmd_type == 'list':
            logging.info('**permit_bot_list: %s', self.permit_list)
            command = ListCommand(self)
        else:
            command = None
            message = SLACK_BOT_HELP_MESSAGE

        if command:
            status, result = command.parse(args[1:])
            if status:
                message = command.execute(result, channel)
            else:
                message = result

        self._post_message(message, channel)


def main():  # noqa
    logging.info('**Spawning slack_bot.py...')
    if not os.path.exists('./bot_config.py'):
        if len(sys.argv) != 3:
            logging.error('Please create a bot_config.py file, and place it in this directory')
            sys.exit(1)

        asset_id = sys.argv[1]
        state = _load_app_state(asset_id)
        bot_id = state.get('bot_id')
        ph_base_url = state.get('ph_base_url')
        bot_token = state.get(SLACK_BOT_JSON_BOT_TOKEN)
        socket_token = state.get(SLACK_BOT_JSON_SOCKET_TOKEN)
        ph_auth_token = state.get(SLACK_BOT_JSON_PH_AUTH_TOKEN)
        permit_act = state.get(SLACK_BOT_JSON_PERMIT_BOT_ACT)
        permit_playbook = state.get(SLACK_BOT_JSON_PERMIT_BOT_PLAYBOOK)
        permit_container = state.get(SLACK_BOT_JSON_PERMIT_BOT_CONTAINER)
        permit_list = state.get(SLACK_BOT_JSON_PERMIT_BOT_LIST)
        permitted_users = state.get(SLACK_BOT_JSON_PERMITTED_USERS)

        try:
            if bot_token:
                bot_token = decrypt_state(asset_id, bot_token, 'bot')
        except Exception:
            logging.exception(SLACK_BOT_DECRYPTION_ERROR)
            sys.exit(1)

        try:
            if socket_token:
                socket_token = decrypt_state(asset_id, socket_token, 'socket')
        except Exception:
            logging.exception(SLACK_BOT_DECRYPTION_ERROR)
            sys.exit(1)

        try:
            if ph_auth_token:
                ph_auth_token = decrypt_state(asset_id, ph_auth_token, 'ph_auth')
        except Exception:
            logging.exception(SLACK_BOT_DECRYPTION_ERROR)
            sys.exit(1)

        sb = SlackBot(
            bot_token=bot_token,
            socket_token=socket_token,
            bot_id=bot_id,
            base_url=ph_base_url,
            auth_token=ph_auth_token,
            permit_act=permit_act,
            permit_playbook=permit_playbook,
            permit_container=permit_container,
            permit_list=permit_list,
            permitted_users=permitted_users
        )
        sb._from_on_poll()
        sys.exit(0)

    import bot_config

    fail = False

    try:

        bt = bot_config.BOT_TOKEN

        if not isinstance(bt, str):
            logging.error('The BOT_TOKEN entry in the bot_config file appears to not be a string')
            fail = True

    except Exception:
        logging.exception('Could not find a BOT_TOKEN entry in bot_config file')
        fail = True

    try:
        sat = bot_config.SOCKET_TOKEN
        if not isinstance(sat, str):
            logging.error(
                'The SOCKET_TOKEN entry in the bot_config file appears to not be a string'
            )
            fail = True

    except Exception:
        logging.exception('Could not find a SOCKET_TOKEN entry in bot_config file')
        fail = True

    try:

        pu = bot_config.PHANTOM_URL

        if not isinstance(pu, str):
            logging.error('The PHANTOM_URL entry in the bot_config file appears to not be a string')
            fail = True

    except Exception:
        logging.exception('Could not find a PHANTOM_URL entry in bot_config file')
        fail = True

    try:

        vc = bot_config.VERIFY_CERT

        if not isinstance(vc, bool):
            logging.error('The VERIFY_CERT entry in the bot_config file appears to not be a boolean')
            fail = True

    except Exception:
        logging.exception('Could not find a VERIFY_CERT entry in bot_config file')
        fail = True

    try:

        pt = bot_config.PHANTOM_TOKEN

        has_token = True

        if not isinstance(pt, str):
            logging.error('The PHANTOM_TOKEN entry in the bot_config file appears to not be a string')
            fail = True

    except Exception:
        pt = ''
        has_token = False

    try:
        pn = bot_config.PHANTOM_USERNAME
        pp = bot_config.PHANTOM_PASSWORD

        auth = (pn, pp)
        has_basic = True

        if not isinstance(pn, str):
            logging.error('The PHANTOM_USERNAME entry in the bot_config file appears to not be a string')
            fail = True
        if not isinstance(pp, str):
            logging.error('The PHANTOM_PASSWORD entry in the bot_config file appears to not be a string')
            fail = True

    except Exception:
        auth = ()
        has_basic = False

    if not (has_token or has_basic):
        logging.error('Please specify a form of authorization. '
              'Either PHANTOM_TOKEN or PHANTOM_USERNAME and PHANTOM_PASSWORD need to be included in the bot_config file.')
        fail = True

    try:
        resp = requests.post('https://slack.com/api/auth.test', data={'token': bot_config.BOT_TOKEN}, timeout=SLACK_BOT_DEFAULT_TIMEOUT)
        resp_json = resp.json()
    except Exception:
        logging.exception('Could not connect to Slack REST endpoint for auth check')
        sys.exit(1)

    if not resp_json.get('ok', False):
        logging.error('Given BOT_TOKEN failed authentication with Slack')
        fail = True

    bot_username = resp_json.get('user_id')

    if not bot_username:
        logging.error('Could not get bot username from Slack')
        fail = True

    if fail:
        logging.error('Config file failed verification, exiting')
        sys.exit(1)

    sb = SlackBot(
        bot_token=bot_config.BOT_TOKEN,
        socket_token=bot_config.SOCKET_TOKEN,
        bot_id=bot_username,
        base_url=bot_config.PHANTOM_URL,
        verify=bot_config.VERIFY_CERT,
        auth_token=pt,
        auth_basic=auth)
    sb._from_on_poll()


if __name__ == '__main__':
    log_file_path = Path(tempfile.gettempdir()) / 'slack_bot.log'
    logging.basicConfig(filename=log_file_path,
                        filemode='a',
                        format='[%(process)d][%(asctime)s][%(levelname)s] %(message)s',
                        level=logging.DEBUG)

    try:
        main()
    except Exception:
        logging.exception('Encountered an unhandled exception!')
        raise
