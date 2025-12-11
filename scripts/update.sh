#!/usr/bin/env bash

set -e

uv sync --upgrade
uv pip freeze > requirements.txt
