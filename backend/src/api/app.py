"""
Provide a slightly-higher level interface between tsctl's state methods and calls and what will be the front end.
"""

from typing import Dict, Optional

import tsctl
import os

from http import HTTPStatus
from flask import Flask, redirect, url_for, request, abort
from functools import lru_cache
from repo.actions import initialize_repo


here = os.path.dirname(os.path.realpath(__file__)) + '/'
app = Flask(__name__)
state_directory_path, state_file_path, credentials = tsctl.tsctl.config_parse()
cached_read_json = lru_cache(maxsize=32)(tsctl.tsctl.read_json)


def is_workspace_set() -> bool:
    """
    Determine if the user has set a workspace.

    Returns:
        Whether or not, upon reading the state file, the workspace has been set.
    """
    return bool(tsctl.tsctl.plan(state_file_path)['workspace'])


def new_state(org_id: Optional[str] =None) -> Optional[tsctl.tsctl.State]:
    """
    Create a new State instance.

    Args:
        org_id: if not set, create a new State instance from the current workspace.

    Returns:
        A new State instance.
    """
    if org_id:
        return tsctl.tsctl.State(
            state_directory_path,
            state_file_path,
            **credentials,
            org_id=org_id
        )
    else:
        if is_workspace_set():
            # Create a State instance based on the default read creds.
            org_id = tsctl.tsctl.plan(state_file_path)['workspace']
            return tsctl.tsctl.State(
                state_directory_path,
                state_file_path,
                **credentials,
                org_id=org_id
            )
        else:
            return


def _ensure_args(request_data: Dict, *args: str) -> bool:
    """
    Take a set of args and a multidict to ensure they reside within.

    Args:
        *args: any number of (required) args to ensure exist in the

    Returns:
        True if all of the args exist and resolve to `True` if tested for bool value, otherwise False.
    """
    return all((arg in request_data and request_data[arg]) for arg in args)


@app.route('/version', methods=['GET'])
def version() -> Dict[str, str]:
    """
    Return the version of the backend app (based on tsctl.__version__).
    """
    return {
        "version": tsctl.__version__
    }


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
    return cached_read_json(f'{here}templates/rules/host.json')


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


@app.route('/plan', methods=['GET'])
def plan() -> Dict:
    """
    Get the current state file via tsctl.

    Returns:
        The state file, parsed as JSON.
    """
    return tsctl.tsctl.plan(state_file_path, show=False)


@app.route('/workspace', methods=['GET', 'POST'])
def workspace() -> Dict:
    """
    Set the workspace and return a list of rulesets as they appear on-disk. Expects a request payload that looks like

    {
        "workspace": "<org_id>"
    }

    Returns:
        A list of ruleset dictionaries.
    """
    if request.method == 'POST':
        request_data = request.get_json()
        if request_data and _ensure_args(request_data, 'workspace'):
            ws = request_data['workspace']

            # Set or update the workspace in the state file.
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
    print(request_data)
    if request_data and _ensure_args(request_data, 'organizations'):
        for org_id in request_data['organizations']:
            print(org_id)
            organization = new_state(org_id=org_id)
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
    if request_data and _ensure_args(request_data, 'organizations'):
        for org_id in request_data['organizations']:
            organization = new_state(org_id=org_id)
            organization.push()
        return tsctl.tsctl.plan(state_file_path, show=False)
    else:
        abort(HTTPStatus.BAD_REQUEST)


# Git


@app.route('/git/clone', methods=['POST'])
def clone_git() -> Dict:
    """
    Clone out a Git repo. Expects an object like

    {
        "directory": "",
        "gitURL": ""
    }

    Returns:
        The contents of the directory once it has been cloned.
    """
    request_data = request.get_json()
    if request_data and _ensure_args(request_data, 'directory', 'git-url'):
        directory = request_data['directory']
        git_repo = request_data['gitURL']
        return {
            "organizations": initialize_repo(directory, git_repo)
        }
    else:
        abort(HTTPStatus.BAD_REQUEST)


@app.route('/git/refresh', methods=[''])
def refresh_git() -> Dict:
    """
    Essentially the same as `git push -u origin master`, followed by

    Returns:

    """


@app.route('/git/push', methods=['POST'])
def push_git() -> Dict:
    """


    Returns:

    """


# Copy


@app.route('/copy', methods=['POST'])
def copy() -> Dict:
    """
    Copy either a rule or ruleset intra- or extra-organization.

    {
        "destination_organization": "<optional_organization_ID>",
        "rules": [
            {
                "rule_id": "<rule_ID>",
                "ruleset_id": "<ruleset_ID>",
                "rule_name_postfix": "<optional_postfix>"
            },
            ...
        ],
        "rulesets": [
            {
                "ruleset_id": "<src_ruleset_ID>",
                "ruleset_name_postfix": "<optional_postfix>"
            },
            ...
        ],
        "tags": [
            {
                "src_rule_id": "<src_rule_id>",
                "dst_rule_id": "<dst_rule_id>"
            },
            ...
        ]
    }

    Returns:
        The state file, following the copies.
    """
    request_data = request.get_json()
    if request_data:
        destination_organization: Optional[str] = None
        if _ensure_args(request_data, 'destination_organization'):
            # All copies should be made to another organization, not to the current workspace.
            destination_organization = request_data['destination_organization']

        if (organization := new_state()) is None:
            return {
                "error": "must set workspace before copying."
            }

        if _ensure_args(request_data, 'rules'):
            for rule in request_data['rules']:
                if not _ensure_args(rule, 'rule_id', 'ruleset_id'):
                    return {
                        "error": "rule must have fields 'rule_id' and 'ruleset_id' defined."
                    }
                rule_id, ruleset_id = rule['rule_id'], rule['ruleset_id']
                rule_name_postfix = None
                if _ensure_args(rule, 'rule_name_postfix'):
                    rule_name_postfix = rule['rule_name_postfix']
                if destination_organization:
                    organization.copy_rule_out(rule_id, ruleset_id, destination_organization, postfix=rule_name_postfix)
                else:
                    organization.copy_rule(rule_id, ruleset_id, postfix=rule_name_postfix)

        if _ensure_args(request_data, 'rulesets'):
            for ruleset in request_data['rulesets']:
                if not _ensure_args(ruleset, 'ruleset_id'):
                    return {
                        "error": "ruleset must have field 'ruleset_id' defined."
                    }
                ruleset_id = ruleset['ruleset_id']
                ruleset_name_postfix = None
                if _ensure_args(ruleset, 'ruleset_name_postfix'):
                    ruleset_name_postfix = ruleset['ruleset_name_postfix']
                if destination_organization:
                    organization.copy_ruleset_out(ruleset_id, postfix=ruleset_name_postfix)
                else:
                    organization.copy_ruleset(ruleset_id, postfix=ruleset_name_postfix)

        if _ensure_args(request_data, 'tags'):
            for tag in request_data['tags']:
                if not _ensure_args(tag, 'src_rule_id', 'dst_rule_id'):
                    return {
                        "error": "tags must have fields 'src_rule_id' and 'dst_rule_id' defined."
                    }
                src_rule_id, dst_rule_id = tag['src_rule_id'], tag['dst_rule_id']
                if destination_organization:
                    _destination_organization = new_state(org_id=destination_organization)
                    if (tags_data := organization.get_tags(src_rule_id)) is not None:
                        _destination_organization.create_tags(dst_rule_id, tags_data)
                    else:
                        return {
                            "error": f"tags data does not exist on rule ID '{src_rule_id}'."
                        }
                else:
                    if (tags_data := organization.get_tags(src_rule_id)) is not None:
                        organization.create_tags(dst_rule_id, tags_data)
                    else:
                        return {
                            "error": f"tags data does not exist on rule ID '{src_rule_id}'."
                        }

        return tsctl.tsctl.plan(state_file_path, show=False)

    else:
        abort(HTTPStatus.BAD_REQUEST)


# Rules and rulesets (general methods)


@app.route('/rule', methods=['GET', 'PUT', 'POST', 'DELETE'])
def rule() -> Dict:
    """
    Depending on the method of request, either

    • Get all rules, with optional filtering capabilities by type, ID, etc. Optional query parameters include

        organization=<org_id>
        rule_id=<rule_id>
        rule_type=<rule_type>
        severity=<rule_severity>

    • update a rule in-place,

    {
        "rule_id": "some_rule_id",
        "data": {
            <rule fields>
        }
    }

    • create a new rule entirely,

    {
        "ruleset_id": "<required parent ruleset ID>"
        "data": {
            <rule fields>
        }
    }

    • or, delete a rule, querying by ID(s).

        ?rule_id=<rule_id1>&rule_id=<rule_id2>

    where rule_postfix is the postfix to apply to the rule title (defaults to " - COPY"), since rule and ruleset titles
    must be unique in the TS platform.

    Returns:
        The updated state file, minus workspace, to show the update that took place.
    """
    if request.method == 'GET':
        ...

    elif request.method == 'PUT':
        # Update the rule in-place.
        request_data = request.get_json()
        if request_data and _ensure_args(request_data, 'rule_id', 'data'):
            if (organization := new_state()) is None:
                return {
                    "error": "must set workspace before you can update rules."
                }
            rule_id = request_data['rule_id']
            rule_data = request_data['data']
            organization.update_rule(rule_id, rule_data)
        else:
            abort(HTTPStatus.BAD_REQUEST)

    elif request.method == 'POST':
        # Create a new rule.
        request_data = request.get_json()
        if request_data and _ensure_args(request_data, 'ruleset_id', 'data') and request_data['ruleset_id']:
            ruleset_id = request_data['ruleset_id']
            data = request_data['data']
            org_id = tsctl.tsctl.plan(state_file_path, show=False)['workspace']
            if not org_id:
                return {
                    "error": "must set workspace before you can post new rules."
                }
            if (organization := new_state()) is None:
                return {
                    "error": "must set workspace before you can create rules."
                }
            for update in data:
                rule = update['rule']
                if 'tags' in update:
                    tags = update['tags']
                else:
                    tags = None
                organization.create_rule(ruleset_id, rule, tags)
            return tsctl.tsctl.plan(state_file_path, show=False)
        else:
            abort(HTTPStatus.BAD_REQUEST)

    elif request.method == 'DELETE':
        # Delete rule(s).
        ...

    return tsctl.tsctl.plan(state_file_path, show=False)


@app.route('/rule/tags', methods=['PUT'])
def update_tags() -> Dict:
    """
    Update the tags on a rule in this workspace. Expects a data object similar to the endpoint above.

    {
        "rule_id": "<some_rule_id>",
        "tags": {
            "inclusion": [{...}],
            "exclusion": [{...}]
        }
    }

    Returns:
        The updated tags' JSON.
    """
    request_data = request.get_json()
    if request_data and _ensure_args(request_data, 'rule_id', 'data'):
        if (organization := new_state()) is None:
            return {
                "error": "must set workspace before you can update tags."
            }
        rule_id = request_data['rule_id']
        tags_data = request_data['data']
        organization.create_tags(rule_id, tags_data)
    else:
        abort(HTTPStatus.BAD_REQUEST)


@app.route('/ruleset', methods=['GET', 'PUT', 'POST', 'DELETE'])
def ruleset() -> Dict:
    """
    Depending on the method of request, either

    • Get a list of rulesets,
    • Update a ruleset's JSON,

    {
        "ruleset_id": "",
        "data": {
            "name": "",
            "description": "",
            "ruleIds": []
        }
    }

    • Create a ruleset,

    <same JSON expected as with the update/POST request>

    • or, delete a ruleset(s) with querying parameters like

        ?ruleset_id=<ruleset_id1>&ruleset_id=<ruleset_id2>

    Returns:
        The updated state file, minus workspace, to show the update that took place.
    """
    if request.method == 'GET':
        ...

    elif request.method == 'PUT':
        ...

    elif request.method == 'POST':
        ...

    elif request.method == 'DELETE':
        ...

    return tsctl.tsctl.plan(state_file_path, show=False)


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8000
    )
