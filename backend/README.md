tsctl
=====

`tsctl` is a Terraform-inspired CLI that allows you to perform most common tasks related to organization-level rule management in [Threat Stack's platform](https://www.threatstack.com/), such as

* creating, copying, and deleting rules and rulesets, and
* applying version control to local state (by default, tracked in `~/.threatstack`), to track rule development and change history on the platform as organizations develop rules to reflect security practices and standards.

```text
$ tsctl -h
usage: tsctl [-h] [--create-rule RULESET FILE] [--copy-rule RULE RULESET] [--copy-rule-out RULE RULESET ORGID] [--update-rule RULE FILE] [--update-tags RULE FILE]
             [--delete-rule RULE] [--create-ruleset FILE] [--copy-ruleset RULESET] [--copy-ruleset-out RULESET ORGID] [--update-ruleset RULESET FILE]
             [--delete-ruleset RULESET] [-l] [-r] [--push] [--plan] [-w ORGID] [--colorful] [--version]

A Threat Stack rule manager for your terminal.

optional arguments:
  -h, --help            show this help message and exit
  --create-rule RULESET FILE
                        (lazy) Create a new rule from a JSON file.
  --copy-rule RULE RULESET
                        (lazy) Copy a rule from one ruleset to another (in the same organization).
  --copy-rule-out RULE RULESET ORGID
                        (lazy) Copy a rule from the current workspace to a ruleset in a different organization.
  --update-rule RULE FILE
                        (lazy) Update a rule in a ruleset with a rule in a JSON file.
  --update-tags RULE FILE
                        (lazy) Update the tags on a rule.
  --delete-rule RULE    (lazy) Delete a rule from the current workspace.
  --create-ruleset FILE
                        (lazy) Create a new ruleset.
  --copy-ruleset RULESET
                        (lazy) Copy an entire ruleset with a new name to the same organization.
  --copy-ruleset-out RULESET ORGID
                        (lazy) Copy an entire ruleset in the current workspace to a different organization.
  --update-ruleset RULESET FILE
                        (lazy) Update a ruleset from a JSON file.
  --delete-ruleset RULESET
                        (lazy) Delete a ruleset from the current workspace.
  -l, --list            List rulesets and (view) rules
  -r, --refresh         Refresh local copy of the organization's rules and flush local state.
  --push                Push a workspace's state to remote state (the platform).
  --plan                View the state file, or the tracked difference between local state and remote state.
  -w ORGID, --workspace ORGID
                        Set the organization ID within which you are working, automatically starts a refresh.
  --colorful            Add xterm coloring to output. Only works on certain commands (--list).
  --version             Print the version of 'tsctl'.

Remember to commit and push your changes on '/home/brandon/.threatstack/' to a git repository to maintain version control.

```

## Install

### Run the Container

This is the preferred deployment strategy. To successfully start the container, you must define environment variables `USER_ID` and `API_KEY`, which will be used to interact with the Threat Stack platform.
```shell
$ docker run -it -d -e 'API_KEY=<your-key>' -e 'USER_ID=<your-key>' -p 8000:8000 --name ts-rule-manager rule-manager:latest
814b24dbd26463a9ea96ca256f08bc5f9a8b566670c7b8ea42e362d2e7823163
$ docker ps
CONTAINER ID   IMAGE                 COMMAND         CREATED         STATUS        PORTS                    NAMES
814b24dbd264   rule-manager:latest   "bash app.sh"   3 seconds ago   Up 1 second   0.0.0.0:8000->8000/tcp   ts-rule-manager

```
By default, the container listens on port `8000` on all available interfaces. This may be modified and confined to a particular interface (or different port) by adjusting the Gunicorn `bind` setting in [gunicorn.py](src/api/gunicorn.py#L28)

#### API

Running the container starts the Flask-based API. Please view the [public documentation](https://documenter.getpostman.com/view/8527107/TzXtHfYj) (via Postman) and import the Postman library (in [src/tests/postman/](src/tests/postman/tsctl%20backend%20Flask%20API.postman_collection.json)) to test requests against the API directly. Or, start the frontend container to interact visually with the API.

### Host-based Installation

Clone out this repository and check out the latest tag for a stable version, or download the latest release, followed by
```shell
$ pip install -r requirements.txt
$ python setup.py install
```
Following these steps, you should have the `tsctl` executable in your `$PATH`, and you can start by setting the workspace (organization).
```shell
$ tsctl --workspace <organization-id>
$ tsctl --plan
{
  "workspace": "<organization-id>",
  "organizations": {}
}
```

## FAQs

#### How is drift between local and remote (platform) state tracked?

The state file (by default, `~/.threatstack/.threatstack.state.json`) tracks local organization changes to rules, rulesets and tags. Its contents can be interpreted as a minimal number of requests to bring remote state into sync with local state. This state file is flushed upon pushing local changes. You can view local change with `tsctl --plan`.

#### What does the local state directory's structure look like?

The state directory is structured like ~
```text
~ $ tree -a .threatstack/
.threatstack/
├── 5d7bb7c49f4d069836a064c2
│   ├── 6bd566f5-d63c-11e9-bc18-196d1feb576b
│   │   ├── 6bd69f79-d63c-11e9-bc18-4de0411d891c
│   │   │   ├── rule.json
│   │   │   └── tags.json
│   │   └── ruleset.json
...
├── .gitignore
└── .threatstack.state.json
```

In other words, it is a hierarchy of organizations, rulesets, and rules. Requirements enforced by `tsctl` include

* unique ruleset names and IDs, organization-wide, and
* unique rule names and IDs, organization-wide.

## Development Notes

* Be sure to increment [`src/tsctl/__init__.__version__`](src/tsctl/__init__.py) when producing new releases. This is referenced while calling `--version`, as well as during the build process with `setuptools`.

#### TODOs

1. Add an `(MODIFIED)` string to the end of rules or rulesets under `--list` output that reside in the state file and will be pushed.
2. Add proper `logging` implementation throughout the module.
3. Set up GH Actions when the repo is tagged.
4. Add `Organization :> Ruleset :> Rule` classes so we can simplify `state.State` by extending or overloading methods? Would make a lot of the logic clearer and easier to maintain.
    - This may also mean that we can define operators between organizations and rulesets? Maybe even rules, for backend-based diffs retrievable via API?
5. Bash autocompletions would be cool.
6. Ensure logging includes source and destination rule/ruleset IDs, so we know where `*-localonly` copies came from for reproducibility. Probably `DEBUG` loglevel.
7. Add a db for faster/better lookups than just plain directory traversal.
8. Might need to look into `refresh` locks, so multiple refresh requests aren't made at the same time. This could be enforced in front end React state, but..