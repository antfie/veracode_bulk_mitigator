#!/usr/bin/env bash

set -e

pipenv update
pipenv requirements > requirements.txt