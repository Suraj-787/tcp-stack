#!/bin/bash
# Launches a Linux container with the capabilities raw sockets / iptables / tc need.
# Mounts this directory into /work so edits made on macOS are visible immediately.
set -e
cd "$(dirname "$0")"

docker build -t tcp-stack-dev .

docker run --rm -it \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --sysctl net.ipv4.ip_forward=0 \
    -v "$(pwd)":/work \
    -w /work \
    tcp-stack-dev \
    bash
