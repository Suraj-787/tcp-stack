# Mini TCP/IP Stack in C

A userspace TCP implementation built on raw sockets. Bypasses the OS TCP stack entirely and manually implements the protocol from scratch — three-way handshake, data transfer, retransmission with exponential backoff, sliding window flow control, and clean four-way teardown.

Validated by sending a real HTTP GET request and receiving the response, confirmed correct by Wireshark packet capture analysis.

---

## What this is

Normal applications use the OS TCP stack:
```
your app → socket() → OS TCP → IP layer → NIC → network
```

This project replaces the OS TCP layer entirely:
```
your app → raw socket → this code handles TCP → IP layer → NIC → network
```

Every TCP header byte is constructed manually. The state machine (`CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED`) is implemented in C. The OS only handles IP and Ethernet below.

---

## What it implements

- **Three-way handshake** — SYN → SYN+ACK → ACK, with randomized ISN
- **Checksum** — ones-complement sum over a pseudo-header + TCP segment
- **Data transfer** — MSS-sized segmentation (1460 bytes), PSH+ACK flagging
- **Sliding window** — respects peer's advertised receive window, tracks in-flight bytes
- **Retransmission** — exponential backoff timer (1s → 2s → 4s → ... → 64s), up to 5 retries per segment
- **Four-way teardown** — handles both active close (FIN_WAIT path) and passive close (LAST_ACK path) correctly
- **RST suppression** — uses `iptables` to prevent the kernel from killing connections the userspace stack owns

---

## Project structure

```
tcp-stack/
├── main.c           — entry point: handshake → HTTP GET → receive → close
├── tcp.c            — state machine, send/recv logic, retransmission, teardown
├── tcp.h            — TCP/IP structs (packed), state enum, connection state, declarations
├── ip.c             — IP header construction
├── checksum.c       — ones-complement checksum (with pseudo-header for TCP)
├── utils.c          — hex dump, flag printer, state name lookup
├── tests/
│   └── test_retransmit.c  — Phase 5 stress test: multi-segment send under packet loss
├── Dockerfile       — Ubuntu 24.04 with gcc, iptables, iproute2, tcpdump, python3
├── docker-run.sh    — interactive Linux shell with NET_RAW + NET_ADMIN capabilities
├── run-test.sh      — one-command test runner (builds, runs, captures packets)
└── captures/        — tcpdump .pcap files (gitignored), open in Wireshark
```

---

## How to run

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/). Everything else (Linux, raw sockets, iptables) runs inside the container.

```bash
# Full test: real HTTP GET against python http.server, full teardown
bash run-test.sh

# Handshake-only test against netcat (proves SYN→SYN+ACK→ACK + data delivery)
bash run-test.sh nc
```

The script handles everything: builds the image, compiles the code, starts the server, suppresses RST via iptables, captures packets, and runs the stack. Packet capture is saved to `captures/latest.pcap`.

---

## Sample output

```
[STATE] CLOSED
[TX] seq=655947879 ack=0 len=0 FLAGS: SYN
[STATE] -> SYN_SENT
[TCP] Waiting for SYN+ACK...
[RX] seq=28996423 ack=655947880 win=65495 FLAGS: SYN ACK
[TCP] Got SYN+ACK. peer_seq=28996423, our new seq=655947880, ack=28996424
[TX] seq=655947880 ack=28996424 len=0 FLAGS: ACK
[STATE] -> ESTABLISHED
[TCP] Connection ESTABLISHED

[TX] seq=655947880 ack=28996424 len=35 FLAGS: ACK PSH
[TCP] Sent 35 bytes (total 35/35)
[RX] ack=655947915 FLAGS: ACK
[TCP] ACK'd segment seq=655947880 len=35

[RX] seq=28996424 FLAGS: ACK PSH
[TCP] Received 155 bytes (total 155)
[RX] seq=28996579 FLAGS: ACK PSH
[TCP] Received 187 bytes (total 342)
[RX] FLAGS: ACK FIN
[TCP] Received FIN from peer

[RESPONSE] 342 bytes received
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.12.3
...
```

---

## Wireshark validation

After any test run, open `captures/latest.pcap` in Wireshark:

```
[S]   54321 → 8080   seq=X               SYN
[S.]  8080  → 54321  seq=Y  ack=X+1      SYN+ACK
[.]   54321 → 8080   ack=Y+1             ACK  (ESTABLISHED)
[P.]  54321 → 8080   len=35              HTTP GET
[.]   8080  → 54321  ack=X+36            ACK
[P.]  8080  → 54321  len=155             HTTP response pt.1
[P.]  8080  → 54321  len=187             HTTP response pt.2
[F.]  8080  → 54321                      FIN (server done)
[F.]  54321 → 8080                       FIN (our close)
```

Right-click any packet → **Follow → TCP Stream** to see the full HTTP exchange reassembled by Wireshark — confirming the implementation is wire-correct.

---

## Technical notes

**The RST problem** — when our raw SYN reaches a local server and it replies with SYN+ACK, the OS kernel also sees that reply. Since the kernel has no record of our raw socket's connection, it would normally send a RST to kill it. `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` suppresses this, giving our userspace code exclusive control.

**Why Docker** — raw sockets (`SOCK_RAW`) and `iptables` require Linux. The container runs with `--cap-add=NET_RAW --cap-add=NET_ADMIN`, which is sufficient without full `--privileged`.

**Passive vs. active close** — `tcp_close()` detects whether the peer already sent FIN (state = `CLOSE_WAIT`, passive path: send FIN → LAST_ACK → wait ACK → CLOSED) or whether we're initiating (state = `ESTABLISHED`, active path: full FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT sequence). Getting this wrong causes a hang — the code handles both correctly.
