"""
Provide a slightly-higher level interface between tsctl's state methods and calls and what will be the front end.
"""

from typing import Dict

import tsctl

from http import HTTPStatus
from flask import Flask, redirect, url_for, request, abort
from functools import lru_cache

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
    if 'workspace' in request.form and request.method == 'POST':
            ws = request.form['workspace']
            tsctl.tsctl.workspace(state_directory_path, state_file_path, ws, credentials)
            return tsctl.tsctl.plan(state_file_path, show=False)
    elif request.method == 'GET':
        return tsctl.tsctl.plan(state_file_path, show=False)
    else:
        abort(HTTPStatus.BAD_REQUEST)


@app.route('/templates/ruleset', methods=['GET'])
def template_ruleset() -> Dict:
    """
    Get an empty ruleset template.

    Returns:
        The read template from disk.
    """
    return cached_read_json('templates/ruleset.json')


@app.route('/templates/tags', methods=['GET'])
def template_tags() -> Dict:
    """
    Get a skeleton tags JSON template.

    Returns:
        The read template from disk.
    """
    return cached_read_json('templates/tags.json')


@app.route('/templates/rules/audit', methods=['GET'])
def template_rules_audit() -> Dict:
    """
    Get a skeleton audit rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json('templates/rules/audit.json')


@app.route('/templates/rules/cloudtrail', methods=['GET'])
def template_rules_cloudtrail() -> Dict:
    """
    Get a skeleton cloudtrail rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json('templates/rules/cloudtrail.json')


@app.route('/templates/rules/file', methods=['GET'])
def template_rules_file() -> Dict:
    """
    Get a skeleton FIM rule.

    Returns:
        The read template from disk.
    """
    return cached_read_json('templates/rules/file.json')


@app.route('/plan', methods=['GET'])
def plan() -> Dict:
    """
    Get the current state file via tsctl.

    Returns:
        The state file, parsed as JSON.
    """
    return tsctl.tsctl.plan(state_file_path, show=False)


@app.route('/create-rule', methods=['POST'])
def create_rule() -> Dict:
    """
    Create a rule.

    Returns:

    """



@app.route('/copy-rule', methods=['POST'])
def copy_rule() -> Dict:
    """
    Copy a rule that already exists.

    Returns:

    """


@app.route('/copy-rule-out', methods=['POST'])
def copy_rule_out() -> Dict:
    """
    Copy a rule from this organization into a new one.

    Returns:

    """


@app.route('/update-rule', methods=['POST'])
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
        port='8000'
    )
