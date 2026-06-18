#!/bin/bash
# Builds and runs the full TCP stack test inside a Linux container.
# Usage: bash run-test.sh [http|nc]
#   http  (default) — connects to python http.server, does a real HTTP GET
#   nc              — connects to netcat, proves handshake without HTTP
set -e
cd "$(dirname "$0")"

MODE=${1:-http}

docker build -q -t tcp-stack-dev . >/dev/null

echo ""
echo "======================================================"
echo "  Mini TCP Stack — running in Linux container"
echo "  Mode: $MODE"
echo "======================================================"
echo ""

docker run --rm \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v "$(pwd)":/work \
    -w /work \
    tcp-stack-dev bash -c "
        set -e
        make -s

        # Suppress the kernel's RST (explained in the plan / walkthrough)
        iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

        # Start packet capture in background
        mkdir -p captures
        tcpdump -i lo -w captures/latest.pcap port 8080 2>/dev/null &
        TCPDUMP_PID=\$!
        sleep 0.5

        if [ '$MODE' = 'nc' ]; then
            echo '--- Starting netcat listener on :8080 ---'
            nc -l 8080 > /tmp/nc_out.txt &
            SERVER_PID=\$!
        else
            echo '--- Starting Python HTTP server on :8080 ---'
            (cd /tmp && python3 -m http.server 8080 >/dev/null 2>&1) &
            SERVER_PID=\$!
        fi
        sleep 0.5

        echo '--- Running tcp_stack ---'
        ./tcp_stack

        sleep 0.5
        kill \$SERVER_PID 2>/dev/null || true
        sleep 0.5
        kill \$TCPDUMP_PID 2>/dev/null || true
        sleep 0.5

        iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP

        if [ '$MODE' = 'nc' ]; then
            echo ''
            echo '--- Bytes received by netcat (proves our TCP data actually arrived) ---'
            cat /tmp/nc_out.txt
        fi

        echo ''
        echo '--- Packet summary from tcpdump ---'
        tcpdump -r captures/latest.pcap -n 2>/dev/null | grep -v '^$' || true
    "

echo ""
echo "Packet capture saved to: captures/latest.pcap"
echo "Open it in Wireshark to see the full handshake + data + teardown."
