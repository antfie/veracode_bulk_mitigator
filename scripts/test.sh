#!/usr/bin/env bash

set -e

pipenv update

black .
pipenv run flake8 --ignore=E501,W503,E501