tsctl
=====

`tsctl` is a Terraform-inspired CLI that allows you to perform most common tasks related to organization-level rule management in [Threat Stack's platform](https://www.threatstack.com/), such as

* creating and deleting rules and rulesets,
* copying rules, both intra-organizationally and extra, and
* applying version control to the local state path (by default, `~/.threatstack`) to track rule development and history on the platform as you and your organization learn and develop security practices.

```shell
$ tsctl -h
usage: tsctl [-h] [-l] [-a FILE] [-c RULESET FILE] [-n RULE RULESET] [-N RULE RULESET ORGID] [-m RULESET NEWNAME] [-M RULESET ORGID] [-u RULESET RULE FILE] [-U RULESET FILE] [-d RULE] [-D RULESET] [-t RULE FILE] [-r] [-p] [-s] [-w ORGID] [--colorful] [-v]

A Threat Stack rule manager for your terminal.

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            List rulesets and (view) rules
  -a FILE, --create-ruleset FILE
                        (lazy) Create a new ruleset in the configured org.
  -c RULESET FILE, --create-rule RULESET FILE
                        (lazy) Create a new rule from a JSON file.
  -n RULE RULESET, --copy-rule RULE RULESET
                        (lazy) Copy a rule from one ruleset to another (in the same organization).
  -N RULE RULESET ORGID, --copy-rule-out RULE RULESET ORGID
                        (lazy) Copy a rule from the current workspace to a ruleset in a different organization.
  -m RULESET NEWNAME, --copy-ruleset RULESET NEWNAME
                        (lazy) Copy an entire ruleset with a new name to the same workspace.
  -M RULESET ORGID, --copy-ruleset-out RULESET ORGID
                        (lazy) Copy an entire ruleset in the current workspace to a different organization.
  -u RULESET RULE FILE, --update-rule RULESET RULE FILE
                        (lazy) Update a rule in a ruleset with a rule in a JSON file.
  -U RULESET FILE, --update-ruleset RULESET FILE
                        (lazy) Update a ruleset from a JSON file.
  -d RULE, --delete-rule RULE
                        (lazy) Delete a rule from the current workspace.
  -D RULESET, --delete-ruleset RULESET
                        (lazy) Delete a ruleset from the current workspace.
  -t RULE FILE, --update-tags RULE FILE
                        (lazy) Create or update tags on a rule.
  -r, --refresh         Refresh local copy of the organization's rules and flush local state.
  -p, --push            Push local state to remote state (across all organizations).
  -s, --plan            View the state file, or the tracked difference between local state and remote state.
  -w ORGID, --workspace ORGID
                        Set the organization ID within which you are working, automatically starts a refresh.
  --colorful            Add xterm coloring to output. Only works on certain commands (--list).
  -v, --version         Print the version of 'tsctl'.

Remember to commit and push your changes on '/home/brandon/.threatstack/' to a git repository to maintain version control.
```

### Installation

#### Environment Variables

* `API_KEY`:
* `USER_ID`: 
* `LOGLEVEL`: (optional, default: `INFO`)
* `LAZY_EVAL`: (optional, default: `false`)
* `CONFIG_DIR`: (optional, default: `~/.threatstack`)

### FAQs

#### What does the local state directory's structure look like?

My current view is that the state directory will be structured like ~
```text
~ $ tree -a .threatstack/
.threatstack/
├── 5d7bb7c49f4d069836a064c2
│   ├── 6bd566f5-d63c-11e9-bc18-196d1feb576b
│   │   ├── 6bd69f79-d63c-11e9-bc18-4de0411d891c
│   │   │   ├── rule.json
│   │   │   └── tags.json
│   │   └── ruleset.json
│   ├── 6be3e51a-d63c-11e9-bc18-01fe680446ed
│   └── 6c2078d1-d63c-11e9-bc18-1b06bdc4074a
├── .gitignore
└── .threatstack.state.json
```

#### How is drift between local and remote (platform) state tracked?

The state file (by default, `~/.threatstack/.threatstack.state.json`) tracks local organization changes. This state file is flushed upon pushing local changes. You can view local change with `tsctl --plan`.

### TODOs

1. Add an `(MODIFIED)` string to the end of rules or rulesets under `--list` output that reside in the state file and will be pushed.
2. Add proper `logging` implementation throughout the module.
3. Set up GH Actions when the repo is tagged.

### Development Notes

* Be sure to update [`src/tsctl/__init__.__version__`](src/tsctl/__init__.py) when producing new releases. This is referenced while calling `--version`, as well as during the build process with `setuptools`.