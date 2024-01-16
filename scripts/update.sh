#!/usr/bin/env bash

set -e

pipenv update
pipenv run pip freeze > requirements.txt