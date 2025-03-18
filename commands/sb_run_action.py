# File: sb_run_action.py
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
import logging

from commands.sb_command import Command
from slack_bot_enums import SoarRestEndpoint
from utils.sb_result import FailureResult, Result, SuccessResult


class RunActionCommand(Command):
    """Run Action Command."""

    COMMAND_NAME = "run_action"
    COMMAND_DESCRIPTION = "Run an app action"

    def configure_parser(self, parser) -> None:
        """Configure the parser for this command."""
        no_asset_message = "If no asset is specified, the given action will run on all possible assets"

        parser.add_argument("container", type=int, help="ID of the container to run the action on")
        parser.add_argument("action_name", help="Name of the action to run")

        app_group = parser.add_mutually_exclusive_group(required=False)
        app_group.add_argument("-a", "--app-id", type=int, help="The app ID to which the action belongs")
        app_group.add_argument("-p", "--app-name", help="The app name to which the action belongs. Case-insensitive")

        asset_group = parser.add_mutually_exclusive_group(required=False)
        asset_group.add_argument("-n", "--asset-name", help=f"Name of the asset to run the action on. {no_asset_message}")
        asset_group.add_argument("-i", "--asset-id", type=int, help=f"ID of the asset to run the action on. {no_asset_message}")

        parser.add_argument("--name", default="Slack generated action", help="Name for the action run")
        parser.add_argument("--type", dest="action_type", default="soarbot", help="Type of action run")
        parser.add_argument("--parameters", nargs="*", help="List of parameter/value pairs in the format param1:value1 param2:value2")

    def _query_actions(self, parsed_args) -> Result:
        query_parameters = {
            "page_size": 10,
            "_filter_action__iexact": self.slack_bot._create_query_string(getattr(parsed_args, "action_name", None)),
            "_filter_app__name__iexact": self.slack_bot._create_query_string(getattr(parsed_args, "app_name", None)),
            "_filter_app": getattr(parsed_args, "app_id", None),
        }
        # Remove empty filters
        query_parameters = {key: value for key, value in query_parameters.items() if value is not None}

        try:
            get_action_request = self.slack_bot._soar_get(SoarRestEndpoint.APP_ACTION, query_parameters=query_parameters)
            get_action_request.raise_for_status()
            action_info = get_action_request.json()
        except Exception as e:
            return FailureResult(f"Failed to query for actions: {e}")

        return SuccessResult(action_info)

    def _query_asset(self, parsed_args) -> Result:
        query_parameters = {
            "page_size": 10,
            "_filter_name__iexact": self.slack_bot._create_query_string(getattr(parsed_args, "asset_name", None)),
            "_filter_id": getattr(parsed_args, "asset_id", None),
            "_filter_app": getattr(parsed_args, "app_id", None),
            "_filter_app__name__iexact": self.slack_bot._create_query_string(getattr(parsed_args, "app_name", None)),
        }
        # Remove empty filters
        query_parameters = {key: value for key, value in query_parameters.items() if value is not None}

        try:
            get_asset_request = self.slack_bot._soar_get(SoarRestEndpoint.ASSET, query_parameters=query_parameters)
            get_asset_request.raise_for_status()
            asset_info = get_asset_request.json()
        except Exception as e:
            return FailureResult(f"Failed to query for asset: {e}")

        if asset_info.get("count", 0) > 1:
            logging.warning("Found multiple assets for query parameters: %s", query_parameters)

        return SuccessResult(asset_info)

    def _create_target(self, action, app_id, asset_ids, parameters) -> Result:
        """Create an action run target from the specified parameters."""
        target = {}
        target["app_id"] = app_id
        target["assets"] = asset_ids
        expected_parameters = action.get("parameters", {})
        return self.slack_bot._parse_action_parameters(parameters, expected_parameters, target)

    def _process_args(self, parsed_args) -> Result:
        """Parse the specified command string."""
        action_name = parsed_args.action_name
        container = parsed_args.container
        parameters = getattr(parsed_args, "parameters", [])

        request_body = {
            "action": action_name,
            "type": parsed_args.action_type,
            "name": parsed_args.name,
            "container_id": container,
        }
        action_query_result = self._query_actions(parsed_args)
        if not action_query_result.success:
            return action_query_result
        action_query = action_query_result.result

        if action_query.get("count", 0) < 1:
            if hasattr(parsed_args, "app_name"):
                app_filter_message = f' for app "{parsed_args.app_name}"'
            elif hasattr(parsed_args, "app_id"):
                app_filter_message = f" for app ID {parsed_args.app_id}"
            else:
                app_filter_message = ""
            return FailureResult(f'Could not find action "{action_name}"{app_filter_message}')

        action_list = action_query["data"]
        if hasattr(parsed_args, "asset_name") or hasattr(parsed_args, "asset_id"):
            asset_result = self._query_asset(parsed_args)
            if not asset_result.success:
                return asset_result
            assets = asset_result.result

            if assets.get("count", 0) < 1:
                if hasattr(parsed_args, "asset_name"):
                    asset_filter_message = f' for asset "{parsed_args.asset_name}"'
                elif hasattr(parsed_args, "asset_id"):
                    asset_filter_message = f" for asset ID {parsed_args.asset_id}"
                else:
                    asset_filter_message = ""
                return FailureResult(f"Failed to find asset{asset_filter_message}")

            asset = assets["data"][0]
        else:
            asset = None

        targets = []
        # If an asset was passed as an argument, we only want to run one action
        if asset:
            app_id = asset["app"]
            action_info = next((action for action in action_list if action["app"] == app_id), None)

            if action_info is None:
                return FailureResult(f'Failed to find action "{action_name}" for app ID {app_id}')

            create_target_result = self._create_target(action=action_info, app_id=app_id, asset_ids=[asset["id"]], parameters=parameters)
            if not create_target_result.success:
                return create_target_result
            targets.append(create_target_result.result)

        # If no asset argument was passed, we need to find all actions that have the given name
        else:
            app_ids = [action["app"] for action in action_list]
            assets_by_app_id_result = self.slack_bot._get_assets_by_app_ids(app_ids)
            if not assets_by_app_id_result.success:
                return assets_by_app_id_result
            assets_by_app_id = assets_by_app_id_result.result
            for action in action_list:
                app_id = action["app"]
                if app_id not in assets_by_app_id:
                    continue

                asset_ids = [asset["id"] for asset in assets_by_app_id[app_id]]
                create_target_result = self._create_target(action=action, app_id=app_id, asset_ids=asset_ids, parameters=parameters)
                if not create_target_result.success:
                    return create_target_result
                targets.append(create_target_result.result)

            if not targets:
                return FailureResult("There are no valid assets to run this action on.")

        request_body["targets"] = targets

        return SuccessResult(request_body)

    def execute(self, parsed_args) -> str:
        """Execute the command with the specified arguments and return a message of the result."""
        result = self._process_args(parsed_args)
        if not result.success:
            return result.message

        request_body = result.result
        try:
            action_run_request = self.slack_bot._soar_post(SoarRestEndpoint.ACTION_RUN, body=request_body)
            response = action_run_request.json()
        except Exception as e:
            return f"Failed to run action: Could not connect to Phantom REST endpoint: {e}"

        if response.get("failed"):
            error = response.get("message", "unknown error")

            if '"Container.owner" must be a "PhUser" instance' in error:
                return "Failed to run action: A container must have an owner to run an action on it.\n\n"

            return f"Failed to run action: {error}\n\n"

        run_id = response.get("action_run_id")

        if not run_id:
            return "Failed to run action: Could not get action run ID"

        action_url = f"{self.slack_bot.phantom_url}mission/{parsed_args.container}/analyst/action_run/{run_id}"

        self.slack_bot._post_message(f"Action run URL: {action_url}", self.channel, code_block=False)

        return f"Message: {response['message']}\nAction run ID: {run_id}"
