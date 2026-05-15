#!/usr/bin/env sh
set -eu

image="${1:-data_gate:local}"

docker build -t "$image" .
