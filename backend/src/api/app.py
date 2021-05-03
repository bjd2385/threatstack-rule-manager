"""
Provide a slightly-higher level interface between tsctl's state methods and calls and what will be the front end.
"""

from typing import List, Dict

import tsctl

from http import HTTPStatus
from flask import Flask, redirect, url_for, request, abort

app = Flask(__name__)

state_directory_path, state_file_path, credentials = tsctl.tsctl.config_parse()


@app.route('/workspace', methods=['POST'])
def workspace() -> Dict:
    """
    Set the workspace and return a list of rulesets as they appear on-disk.

    Returns:
        A list of ruleset dictionaries.
    """
    if 'workspace' in request.form:
        workspace = request.form['workspace']
        tsctl.tsctl.workspace(state_directory_path, state_file_path, workspace, credentials)
        return tsctl.tsctl.plan(state_file_path, show=False)
    else:
        abort(HTTPStatus.BAD_REQUEST)


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port='8000'
    )
