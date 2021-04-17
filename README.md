### Rule Management with `tsctl`

`tsctl` allows you to perform the most common tasks in organization-level rule management, such as

* creating rules and rulesets,
* copying rules, both intra-organizational and extra, and
* applying version control to local state.

In addition to the above, since the tool works out of a local directory (by default, 
`~/.threatstack`), it allows for version control with `git`.

## FAQs

### How do I configure the tool?

After installing `tsctl`, you should see one new directory in your home directory, `~/.threatstack`, that stores local state. You may optionally place a
file `~/.threatstack.conf` in your home directory to configure the location and name of the local state directory. Other options for this file include

* `STATE_FILE_NAME`
* `CONF_DIRECTORY` - 

### What does the local state directory's structure look like?

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
The `.threatstack.state.json` state file tracks local organization and cross-organization changes. This state file is flushed upon pushing local changes. You can view local, uncommitted changes by either typing `git status .` in the configured local state directory or via `tsctl diff`.

### What am I _not_ trying to solve?

### Environment Variables

* `API_KEY`:
* `USER_ID`: 
* `LOGLEVEL`: (optional, default: `INFO`)
* `LAZY_EVAL`: (optional, default: `false`)
* `CONFIG_DIR`: (optional, default: `~/.threatstack`)

### TODOs

1. Per Ryan Plessner, need to check request headers in the `utils.retry` decorator so that if sleep time is not set, it will wait the appropriate amount of time on '429s.
2. Add state modification, so you can add local state to the state file that will be pushed when the user runs `--push` and viewable with `--diff`.
3. Add an `(MODIFIED)` string to the end of rules or rulesets under `--list` output that reside in the state file and will be pushed.