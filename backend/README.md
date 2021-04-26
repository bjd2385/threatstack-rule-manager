tsctl
=====

`tsctl` is a Terraform-inspired CLI that allows you to perform most common tasks related to organization-level rule management in [Threat Stack's platform](https://www.threatstack.com/), such as

* creating and deleting rules and rulesets,
* copying rules, both intra-organizationally and extra, and
* applying version control to the local state path (by default, `~/.threatstack`) to track rule development and history on the platform as you and your organization learn and develop security practices.

```text
$ tsctl -h
usage: tsctl [-h] [--create-rule RULESET FILE] [--copy-rule RULE RULESET] [--copy-rule-out RULE RULESET ORGID] [--update-rule RULE FILE] [--update-tags RULE FILE] [--delete-rule RULE] [--create-ruleset FILE] [--copy-ruleset RULESET] [--copy-ruleset-out RULESET ORGID]
             [--update-ruleset RULESET FILE] [--delete-ruleset RULESET] [-l] [-r] [--push] [--push-all] [--plan] [-w ORGID] [--colorful] [--version]

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
                        (lazy) Copy an entire ruleset with a new name to the same workspace.
  --copy-ruleset-out RULESET ORGID
                        (lazy) Copy an entire ruleset in the current workspace to a different organization.
  --update-ruleset RULESET FILE
                        (lazy) Update a ruleset from a JSON file.
  --delete-ruleset RULESET
                        (lazy) Delete a ruleset from the current workspace.
  -l, --list            List rulesets and (view) rules
  -r, --refresh         Refresh local copy of the organization's rules and flush local state.
  --push                Push a workspace's state to remote state (the platform).
  --push-all            Push all modified local organizations to remote state (the platform).
  --plan                View the state file, or the tracked difference between local state and remote state.
  -w ORGID, --workspace ORGID
                        Set the organization ID within which you are working, automatically starts a refresh.
  --colorful            Add xterm coloring to output. Only works on certain commands (--list).
  --version             Print the version of 'tsctl'.

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
4. Simplify state.State rule and ruleset directory lookups by adding some new methods.
5. Add `Organization :> Ruleset :> Rule` classes so we can simplify `state.State` by extending or overloading methods? Would make a lot of the logic clearer and easier to maintain.
    - This may also mean that we can define operators between organizations and rulesets? Maybe even rules, for backend-based diffs retrievable via API?

### Development Notes

* Be sure to update [`src/tsctl/__init__.__version__`](src/tsctl/__init__.py) when producing new releases. This is referenced while calling `--version`, as well as during the build process with `setuptools`.