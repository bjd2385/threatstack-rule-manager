Threat Stack Rule Manager
=========================

### Run locally

You must have `docker-compose` installed (the application has been tested with `>= 1.29.2`), as well as define a local `.env` file with `API_KEY` and `USER_ID` defined, followed by running
```shell
$ docker compose up --build -d
```
to start the app with default settings. The `backend` service typically takes <10s to build, while the frontend, React-based application can run for several minutes while all modules are installed.
