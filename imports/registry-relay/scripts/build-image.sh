#!/usr/bin/env sh
set -eu

image="${1:-registry-relay:local}"

docker build -t "$image" .
