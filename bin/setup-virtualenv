#!/bin/bash

# Enable tracing of command invocations
set -x

if [ "$#" -lt 1 ]; then
  BASE_DIR=$( cd "$(dirname $0)/..)" ; pwd -P )
else
  BASE_DIR="$1"
fi

echo "BASE_DIR: $BASE_DIR"

MUDMANAGER_VIRTENV_NAME=virtualenv

# This requires the "virtualenv" package to be installed

cd "$BASE_DIR"

echo "Creating virtualenv $MUDMANAGER_VIRTENV_NAME (in $BASE_DIR/$MUDMANAGER_VIRTENV_NAME)"
virtualenv --clear -p $(which python3.6) $BASE_DIR/$MUDMANAGER_VIRTENV_NAME

source $MUDMANAGER_VIRTENV_NAME/bin/activate

pip install -r requirements.txt
