FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    gcc make gdb \
    iptables iproute2 \
    tcpdump net-tools netcat-openbsd \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Docker Desktop's Linux VM doesn't expose nf_tables netlink generation id to
# unprivileged-ish containers; the legacy ip_tables backend works without it.
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy

WORKDIR /work
