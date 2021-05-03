#! /bin/bash
# Run the Gunicorn-wrapped Flask API to interact with the local filesystem.

gunicorn -c src/api/gunicorn.py api.app:app
