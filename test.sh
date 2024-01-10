#!/usr/bin/env bash

set -e

pipenv update
pipenv check
black .
flake8 --ignore=E501,W503