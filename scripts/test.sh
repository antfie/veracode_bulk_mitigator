#!/usr/bin/env bash

set -e

uv run black .
uv run flake8 --ignore=E501,W503,E501 --exclude=.venv
uv run python -m unittest discover --failfast --pattern "*_test.py"