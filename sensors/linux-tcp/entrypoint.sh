#!/usr/bin/env sh
set -eu

INTERFACE="${ZCI_SENSOR_INTERFACE:-eth0}"
SOCKET="${ZCI_SENSOR_SOCKET:-/run/zci/tcp-sensor.sock}"

mkdir -p "$(dirname "$SOCKET")"
make clean
make
exec ./tcp-sensor "$INTERFACE" "$SOCKET"
