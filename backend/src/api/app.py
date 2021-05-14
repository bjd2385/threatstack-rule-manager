"""
Provide a slightly-higher level interface between tsctl's state methods and calls and what will be the front end.
"""

from typing import Dict, Union

import tsctl
import os
import json

from http import HTTPStatus
from flask import Flask, redirect, url_for, request, abort
from functools import lru_cache


here = os.path.dirname(os.path.realpath(__file__)) + '/'

app = Flask(__name__)

state_directory_path, state_file_path, credentials = tsctl.tsctl.config_parse()

cached_read_json = lru_cache(maxsize=32)(tsctl.tsctl.read_json)


@app.route('/workspace', methods=['GET', 'POST'])
def workspace() -> Dict:
    """
    Set the workspace and return a list of rulesets as they appear on-disk.

    Returns:
        A list of ruleset dictionaries.
    """
    request_data = request.get_json()
    if request_data and 'workspace' in request_data and request_data['workspace'] and request.method == 'POST':
        ws = request_data['workspace']
        tsctl.tsctl.workspace(state_directory_path, state_file_path, ws, credentials)
        ret = tsctl.tsctl.plan(state_file_path, show=False)
        ret.pop('organizations')
        return ret
    elif request.method == 'GET':
        ret = tsctl.tsctl.plan(state_file_path, show=False)
        ret.pop('organizations')
        return ret
    else:
        abort(HTTPStatus.BAD_REQUEST)


@app.route('/templates/ruleset', methods=['GET'])
def template_ruleset() -> Dict:
    """
    Get an empty ruleset template.

    Returns:
        The read template from disk.
    """
    return cached_read_json(f'{here}templates/ruleset.json')


@app.route('/templates/tags', methods=['GET'])
def template_tags() -> Dict:
    """
    Get a skeleton tags JSON template.

    Returns:
        The read template from disk.
    """
    return cached_read_json(f'{here}templates/tags.json')


@app.route('/templates/rules/audit', methods=['GET'])
def template_rules_audit() -> Dict:
    """
    Get a skeleton audit rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json(f'{here}templates/rules/audit.json')


@app.route('/templates/rules/cloudtrail', methods=['GET'])
def template_rules_cloudtrail() -> Dict:
    """
    Get a skeleton cloudtrail rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json(f'{here}templates/rules/cloudtrail.json')


@app.route('/templates/rules/file', methods=['GET'])
def template_rules_file() -> Dict:
    """
    Get a skeleton FIM rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json(f'{here}templates/rules/file.json')


@app.route('/templates/rules/threatintel', methods=['GET'])
def template_threatintel_file() -> Dict:
    """
    Get a skeleton FIM rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json(f'{here}templates/rules/threat_intel.json')


@app.route('/templates/tags', methods=['GET'])
def template_tags_file() -> Dict:
    """
    Get a skeleton FIM rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json(f'{here}templates/tags.json')


@app.route('/plan', methods=['GET'])
def plan() -> Dict:
    """
    Get the current state file via tsctl.

    Returns:
        The state file, parsed as JSON.
    """
    return tsctl.tsctl.plan(state_file_path, show=False)


@app.route('/refresh', methods=['POST'])
def refresh() -> Dict:
    """
    Refresh an organization's local state copy (or pull it down preemptively). Expects a similar payload as other
    endpoints:

    {
        "organizations": [
            "<org_ids>",
            ...
        ]
    }

    Returns:
        The state file, and if the refresh was successful, the organization's state will be cleared (hence not present).
    """
    request_data = request.get_json()
    if request_data and 'organizations' in request_data and request_data['organizations']:
        for org_id in request_data['organizations']:
            organization = tsctl.tsctl.State(state_directory_path, state_file_path, org_id=org_id, **credentials)
            organization.refresh()
        return tsctl.tsctl.plan(state_file_path, show=False)
    else:
        abort(HTTPStatus.BAD_REQUEST)


@app.route('/push', methods=['POST'])
def push() -> Dict:
    """
    Push organizations' local state changes onto the (remote) Threat Stack platform. Expects a similar payload as other
    endpoints:

    {
        "organizations": [
            "<org_ids>",
            ...
        ]
    }

    Returns:
        The state file, and if the push was successful, the organization's state will be cleared (hence not present).
    """
    request_data = request.get_json()
    if request_data and 'organizations' in request_data and request_data['organizations']:
        for org_id in request_data['organizations']:
            organization = tsctl.tsctl.State(state_directory_path, state_file_path, org_id=org_id, **credentials)
            organization.push()
        return tsctl.tsctl.plan(state_file_path, show=False)
    else:
        abort(HTTPStatus.BAD_REQUEST)


@app.route('/list', methods=['GET', 'POST'])
def lst() -> Union[Dict[str, Dict[str, Dict[str, str]]], Dict[str, str]]:
    """
    Get a list of rulesets and rules under an organization. This method expects a payload that looks like

    {
        "organization": "<optional_org_ID>",
        "tags": false  # Not optional.
    }

    in order to perform the lookup if a POST request is made. It also does not update the state file. If tags are
    requested, then return that data as well, not just the rule names.

    Returns:
        A JSON object containing this organization's layout.
    """
    if request.method == 'GET':
        org_id = tsctl.tsctl.plan(state_file_path, show=False)['workspace']
        if not org_id:
            return {
                "error": "must set workspace before you can post new rules, or try a POST request on this endpoint."
            }
        request_args = request.args.to_dict()
        if 'tags' not in request_args:
            return {
                "error": "'list' endpoint expected a boolean value ('true' or 'false') for 'tags' arg."
            }

        tags = request_args['tags']

        # Make a silly conversion, since I don't see any way to make this cleaner.
        if tags == 'true':
            tags = True
        elif tags == 'false':
            tags = False
        else:
            abort(HTTPStatus.BAD_REQUEST)

        organization = tsctl.tsctl.State(state_directory_path, state_file_path, org_id=org_id, **credentials)
        return organization.lst_api(tags=tags)

    elif request.method == 'POST':
        request_data = request.get_json()
        if request_data and 'organization' in request_data:
            org_id = request_data['organization']
            organization = tsctl.tsctl.State(state_directory_path, state_file_path, org_id=org_id, **credentials)
            if 'tags' in request_data:
                if request_data['tags'] is bool:
                    return organization.lst_api(tags=request_data['tags'])
            else:
                return organization.lst_api()

    abort(HTTPStatus.BAD_REQUEST)


@app.route('/create-rules', methods=['POST'])
def create_rules() -> Dict:
    """
    Create a rule with a POST request to the platform. The payload should look like

    {
        "ruleset_id": "some_ruleset_id",
        "data": {
            [
                "rule": {
                    <rule fields>
                },
                "tags": {
                    <optional tags data>
                }
            ]
        }
    }

    Note that tags are optional, since this is the rule creation endpoint.

    Returns:
        The updated state file, minus workspace, to show the update that took place.
    """
    request_data = request.get_json()
    if request_data and 'ruleset_id' in request_data and request_data['ruleset_id'] and 'data' in request_data and request_data['ruleset_id']:
        ruleset_id = request_data['ruleset_id']
        data = request_data['data']
        org_id = tsctl.tsctl.plan(state_file_path, show=False)['workspace']
        if not org_id:
            return {
                "error": "must set workspace before you can post new rules."
            }
        organization = tsctl.tsctl.State(state_directory_path, state_file_path, org_id=org_id, **credentials)
        for update in data:
            rule = update['rule']
            if 'tags' in update:
                tags = update['tags']
            else:
                tags = None
            organization.create_rule(ruleset_id, rule, tags)
        return tsctl.tsctl.plan(state_file_path, show=False)['organizations'][org_id]
    else:
        abort(HTTPStatus.BAD_REQUEST)


@app.route('/copy-rule', methods=['POST'])
def copy_rule() -> Dict:
    """
    Copy a rule that already exists to another ruleset within this organization, or another altogether. The payload
    should look like

    {
        "destination_organization": "<optional_organization_ID>",
        "rule_id": "<rule_ID>",
        "rule_postfix": "<optional_postfix>"
    }

    where rule_postfix is the postfix to apply to the rule title (defaults to " - COPY"), since rule and ruleset titles
    must be unique in the TS platform.

    Returns:
        The updated state file, minus workspace, to show the update that took place.
    """
    request_data = request.get_json()
    if request_data and all(field in request_data for field in ['destination_organization', 'rule_id', 'rule_postfix']):
        ...


@app.route('/update-rule', methods=['PUT'])
def update_rule() -> Dict:
    """
    Update an existing rule in this workspace.

    Returns:

    """


@app.route('/update-tags', methods=['POST'])
def update_tags() -> Dict:
    """
    Update the tags on a rule in this workspace.

    Returns:

    """


@app.route('/delete-rule', methods=['POST'])
def delete_rule() -> Dict:
    """
    Delete a rule in this workspace.

    Returns:

    """


@app.route('/get-rules', methods=['POST'])
def get_rules() -> Dict:
    """
    Get the locally cached rules on a ruleset.

    Returns:

    """


@app.route('/laziness', methods=['POST'])
def set_lazy() -> Dict:
    """
    Set the laziness factor of the backend.

    Returns:

    """


@app.route('/get-rulesets', methods=['GET'])
def get_rulesets() -> Dict:
    """
    Get a list of locally cached rulesets on a ruleset.

    Returns:

    """


@app.route('/create-ruleset', methods=['POST'])
def create_ruleset() -> Dict:
    """
    Create a ruleset.

    Returns:

    """


@app.route('/copy-ruleset', methods=['POST'])
def copy_ruleset() -> Dict:
    """
    Copy a ruleset that already exists in the current workspace.

    Returns:

    """


@app.route('/copy-ruleset-out', methods=['POST'])
def copy_ruleset_out() -> Dict:
    """
    Copy a ruleset from this workspace to the next.

    Returns:

    """


@app.route('/update-ruleset', methods=['POST'])
def update_ruleset() -> Dict:
    """
    Update a ruleset with new data.

    Returns:

    """


@app.route('/delete-ruleset', methods=['POST'])
def delete_ruleset() -> Dict:
    """
    Delete a ruleset from the current workspace.

    Returns:

    """



if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8000
    )
