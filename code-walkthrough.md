# TCP Stack — Code Walkthrough (for someone new to C)

This walks through every file in the project, building up from C fundamentals
to the actual networking logic. Written for a first networking project / first
time writing C.

---

## Part 1: C concepts you need before any of this makes sense

**Structs** are C's way of grouping related fields into one object — no
classes, no methods, just data:

```c
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
} tcp_hdr_t;
```

`typedef struct {...} tcp_hdr_t;` means "define this struct shape, and let me
call it `tcp_hdr_t`" instead of writing `struct tcp_hdr_t` everywhere.
`uint16_t` is "unsigned 16-bit integer" — exact-width types from
`<stdint.h>`, used here because network protocols specify exact byte widths
(a port number is *exactly* 2 bytes, not "whatever int is on this machine").

**Pointers** are addresses-of-things. `tcp_conn_t *conn` means `conn` doesn't
hold a connection — it holds the *memory address* where a connection lives.
`conn->seq` means "go to that address, read the `seq` field." This matters
enormously for performance and for this project specifically because we're
going to point a struct directly at raw bytes pulled off the network (more on
that below).

**`__attribute__((packed))`** — by default, C compilers insert padding bytes
between struct fields so each field lands on a convenient memory boundary
(faster CPU access). But a network packet has *no padding* — it's a precise
byte layout defined by RFC 793. `packed` tells gcc "lay this out with zero
gaps," so when we overlay this struct directly onto bytes from the wire,
every field lines up exactly where the protocol says it should be.

**`static` on a function** (used a lot in `tcp.c`) means "only visible inside
this file." It's not exported to other `.c` files — basically a private
helper.

**Byte order (`htons`, `htonl`, `ntohs`, `ntohl`)** — this is the single most
confusing thing for C beginners doing networking, so let's nail it. Your CPU
stores multi-byte numbers in **little-endian** order: the number `1` as a
32-bit int is stored as bytes `01 00 00 00`. But every network protocol uses
**big-endian** ("network byte order"): `1` is sent as `00 00 00 01`. If you
don't convert, a port number `8080` (`0x1F90`) gets sent backwards and
becomes `0x901F` = 36895 on the wire.

- `htons` = "host to network, short" (16-bit, e.g. ports)
- `htonl` = "host to network, long" (32-bit, e.g. sequence numbers)
- `ntohs`/`ntohl` = the reverse, for reading incoming data

You'll see `htons(8080)` when *sending* and `ntohs(th->dst_port)` when
*reading*. Every single multi-byte field in a packet header goes through one
of these.

---

## `tcp.h` — the blueprint for everything

This is a **header file**: it contains no logic, just *declarations* — "here's
what types and functions exist." Other `.c` files `#include "tcp.h"` to learn
about these shapes without needing to see how they're implemented. The
`#ifndef TCP_H / #define TCP_H / #endif` at top/bottom is an "include guard"
— if two files both include `tcp.h`, this stops the compiler from defining
everything twice and erroring out.

**The flags (`TH_FIN`, `TH_SYN`, etc.):** TCP packets carry a "flags" byte
where each *bit* means something. `0x02` in binary is `00000010` — bit 1 set,
meaning SYN. `0x10` is `00010000` — bit 4 set, meaning ACK. We can combine
flags with bitwise OR: `TH_SYN | TH_ACK` = `0x02 | 0x10` = `0x12` =
`00010010` — both bits set, both flags present. This is how a single byte
represents 6 independent yes/no signals.

**The state enum (`tcp_state_t`):** an `enum` is just a list of named
integers (`TCP_CLOSED` = 0, `TCP_SYN_SENT` = 1, etc.). This *is* the state
machine from the plan — every connection sits in exactly one of these states
at any moment, and the functions later move it between them.

**`tcp_hdr_t` — this is the heart of the whole project.** A real TCP header
is 20 raw bytes that travel over the wire. This struct describes those 20
bytes field-by-field so our C code can read/write them by name (`th->seq_num`)
instead of manually indexing into a byte array. Because of `packed`, this
struct's memory layout is byte-for-byte identical to the real wire format —
meaning we can literally point this struct type at a chunk of received bytes
and the fields "just work." That trick — overlaying a struct on raw memory —
is called **type punning**, and it's used constantly in `tcp.c`.

Notice `data_off` and `flags` are each `uint8_t` (1 byte) even though the
real TCP spec packs "data offset" into the upper 4 bits of one byte and
reserves the lower 4 bits. We handle that bit-shuffling manually elsewhere
(`(sizeof(tcp_hdr_t)/4) << 4`), not in the struct.

**`ip_hdr_t`:** same idea, but for the IP layer underneath TCP. Every TCP
segment travels inside an IP packet, so we build this header too (since we
told the OS "I'll handle the IP header myself" — see `tcp.c` below).

**`pseudo_hdr_t`:** this one's never actually sent on the wire. It exists
*only* so the checksum math includes the source/destination IP addresses
(explained in `checksum.c` below) — it's scratch memory we build temporarily
just to compute a number.

**The connection state (`segment_t`, `tcp_conn_t`):** `segment_t` is one
outgoing chunk of data we're tracking until it's acknowledged — its raw
bytes, how many bytes, what sequence number it started at, when we sent it,
how many times we've retried. `tcp_conn_t` is the "this is everything about
one TCP connection" struct: the raw socket file descriptor, both IPs/ports,
our current sequence/ack numbers, and an array of 64 `segment_t` slots
(`send_buf`) used for the retransmission logic.

---

## `checksum.c` — proving the data wasn't corrupted in transit

The checksum's job: the receiver computes the same checksum over the bytes it
got, and if it doesn't match what's in the header, it knows the packet got
mangled and silently drops it. This is a 1980s-era cheap error-detection
scheme, much weaker than something like CRC32, but TCP still uses it for
backward compatibility.

**`compute_checksum` — the generic algorithm:**
- `void *buf` is a pointer with no specified type — "I don't know what this
  points to, treat it as raw bytes." `(uint16_t *)buf` then says "actually,
  read it two bytes at a time."
- The `while (len > 1)` loop walks through the buffer two bytes at a time
  (`sum += *ptr++` reads the current 16-bit value, adds it to the running
  total, then advances the pointer by one `uint16_t`, i.e. 2 bytes),
  accumulating a sum.
- `if (len == 1)` handles an odd-length buffer — one leftover byte gets added
  on its own.
- **The fold step** is the "ones-complement" part: `sum` is a 32-bit number,
  but the checksum field is only 16 bits. If the sum overflowed past 16 bits,
  we don't just truncate it — ones-complement arithmetic says "wrap the
  overflow back around and add it in" (`sum & 0xFFFF` keeps the low 16 bits,
  `sum >> 16` grabs whatever overflowed past bit 16, and we add them
  together). The `while` repeats this in case adding the carry back in causes
  *another* overflow.
- `return (uint16_t)(~sum)` — `~` is bitwise NOT, flipping every bit. This is
  the actual "ones-complement" — the checksum field stores the *inverted*
  sum, which is why the plan's notes say "if the result is 0xFFFF, the
  checksum is valid": sum + inverted-sum always equals all-1-bits.

**`tcp_checksum` — why we need a "fake" header:**
TCP's checksum isn't computed over just the TCP header+data — the spec
requires it to *also* cover the source/destination IP addresses, even though
those technically belong to the layer below. This stops a checksum from
validating correctly if a packet's source/destination got swapped or
corrupted at the IP layer. Since this pseudo-header is never actually
transmitted, we build it in a throwaway buffer: `calloc` allocates `total`
bytes (TCP header size + pseudo-header size) and zeroes them, we fill in the
pseudo-header fields, `memcpy` copies the real TCP header+data right after
it, run the checksum over the *whole combined buffer*, then `free` the
temporary memory. The result is what actually gets written into the real TCP
header's checksum field.

---

## `ip.c` — the layer underneath TCP

Normally your OS handles IP for you completely. Here, because we're using a
raw socket with `IP_HDRINCL` (explained below), *we* have to build this
20-byte header ourselves before every send.

- `static uint16_t ip_id = 1;` — a **module-level static variable**. Unlike a
  local variable inside a function (which resets every call), this persists
  across calls and is private to `ip.c`. Each IP packet needs a unique ID
  (used if the packet gets fragmented), so we just increment a counter.
- `iph->ihl_ver = (4 << 4) | 5;` — this packs two 4-bit values into one byte:
  IP version (4, for IPv4) and header length (5, meaning 5×4=20 bytes, no IP
  options). `4 << 4` shifts `4` left by 4 bits, putting it in the upper
  nibble (`0100 0000`), then `| 5` sets the lower nibble (`0000 0101`),
  giving `0100 0101` = `0x45` — if you've ever seen a packet capture starting
  with byte `45`, that's this line.
- `iph->tot_len = htons(sizeof(ip_hdr_t) + payload_len)` — total packet size
  (IP header + everything after it, i.e. the TCP header and any data),
  converted to network byte order.
- `iph->ttl = 64` — "Time To Live," decremented by every router hop; prevents
  packets looping forever. 64 is a typical default.
- `iph->checksum = 0` — we deliberately leave this as zero. When we set
  `IP_HDRINCL`, we're telling the kernel "trust me, I built the IP header"
  but the *kernel still computes the IP-layer checksum for us* on send
  (unlike the TCP checksum, which we must compute ourselves in `checksum.c`
  because the kernel has no idea we're tunneling TCP through a raw socket).

---

## `utils.c` — debugging helpers, no protocol logic

This is the simplest file, purely for human-readable logging:
- `hex_dump`: prints raw bytes as hex pairs, 16 per line — a classic
  debugging tool for "show me literally what's in this buffer."
- `log_tcp_flags`: `flags & TH_SYN` is a **bitwise AND** — it checks "is the
  SYN bit set in this byte?" without disturbing the other bits. If `flags` is
  `0x12` (SYN+ACK = `00010010`) and `TH_SYN` is `0x02` (`00000010`), then
  `flags & TH_SYN` = `00000010` = nonzero = true, so it prints "SYN". This is
  the same pattern used everywhere flags are checked (e.g.
  `if (th.flags & TH_FIN)` in `tcp.c`).
- `tcp_state_str`: just maps the enum number back to a readable string for
  printing in logs like `[STATE] -> ESTABLISHED`.

---

## `tcp.c` — the core logic, walked in runtime order

### Step 1: `tcp_create` — opening the raw socket

This is where the project's whole premise lives.

- `calloc(1, sizeof(tcp_conn_t))` — allocate memory for one `tcp_conn_t`
  struct on the heap, zeroed out, and return a pointer to it. (`malloc` would
  give uninitialized garbage memory; `calloc` zeroes it — important here
  since `send_buf` should start with every slot's `in_use` flag at 0.)
- **`socket(AF_INET, SOCK_RAW, IPPROTO_TCP)`** — this is the line that makes
  everything else in the project possible. A normal app calls
  `socket(AF_INET, SOCK_STREAM, 0)` and the kernel handles all of TCP for you
  invisibly. `SOCK_RAW` instead says "give me a socket where I see and
  construct entire IP packets myself" — the kernel just shuttles raw bytes in
  and out, no TCP state machine, no automatic ACKs, nothing. This requires
  root, which is why the program needs `sudo` (or, in our case, the Docker
  container's capabilities).
- **`setsockopt(..., IP_HDRINCL, ...)`** — by default even a raw socket still
  expects *you* to hand it just the TCP-and-up bytes, and the kernel builds
  the IP header for you. `IP_HDRINCL` flips that: "I am providing the IP
  header too, starting from the very first byte." That's why `ip.c` exists —
  without this flag, `build_ip_header` would be pointless.
- `inet_addr("127.0.0.1")` converts a human-readable IP string into the 4-byte
  binary form used on the wire (and already in network byte order,
  conveniently).
- `srand(time(NULL) ^ getpid())` then `rand()` picks a randomized **Initial
  Sequence Number (ISN)**. If sequence numbers were predictable/static, an
  old, already-dead connection's leftover packets bouncing around the network
  could be mistaken for part of a brand new connection between the same two
  ports — randomizing makes that collision astronomically unlikely.

### Step 2: `send_tcp_packet` — building one packet, byte by byte

This is the function every other function calls whenever it wants to put a
packet on the wire.

- **The buffer:** `tcp_len` is the TCP header plus whatever data we're
  attaching. `pkt_len` is the *whole* packet (IP header + TCP header + data).
  `calloc(1, pkt_len)` allocates one contiguous, zeroed block of raw bytes
  big enough to hold all of it. This `pkt` buffer is what actually gets
  handed to the kernel for transmission.
- **The type-punning trick:** `pkt` is just `uint8_t*` — an address with no
  structure. `(ip_hdr_t *)pkt` reinterprets that *same address* as "this is
  where an IP header begins." `(tcp_hdr_t *)(pkt + sizeof(ip_hdr_t))`
  reinterprets a *later* address (20 bytes further in) as "this is where a
  TCP header begins." Now `iph->ttl = 64` and `pkt[8] = 64` would do the
  exact same thing — but writing it through the struct is far less
  error-prone than manually counting byte offsets.
- Delegates to `build_ip_header` from `ip.c` to fill in the first 20 bytes.
- **Filling the TCP header fields:**
  - `seq_num`/`ack_num` get `htonl`'d (32-bit, byte-order converted) from the
    connection's current state.
  - `ack_num` is conditionally set: a pure SYN packet (no ACK flag) legitimately
    has no ack number yet (`flags & TH_ACK ? htonl(conn->ack) : 0`).
  - `data_off = (sizeof(tcp_hdr_t) / 4) << 4` — recall the TCP header has the
    offset packed into the *upper* 4 bits of one byte (we don't use any
    options, so it's always exactly 20 bytes = 5 32-bit words).
    `sizeof(tcp_hdr_t)/4` = `20/4` = `5`. `5 << 4` shifts it into the upper
    nibble: `0101 0000` = `0x50`. The lower 4 bits stay 0 (reserved).
  - `window = htons(65535)` — this is *our* receive window, the maximum we'll
    always advertise (we're not implementing real flow-control limiting on
    the receive side, just always claiming we can take the max).
  - `checksum = 0` — must be zero *before* computing the checksum, since the
    checksum field itself can't be part of the sum used to calculate itself.
- If there's a data payload (e.g. our HTTP GET request), copy it into the
  buffer right after where the TCP header ends.
- Now that the entire packet (header + data) is assembled, run the real
  checksum algorithm over it and write the result into the header. This must
  happen *after* the data copy and *after* zeroing the checksum field, or the
  math would be wrong.
- `sockaddr_in` is the standard C networking "address" structure — even
  though we built our own IP header with the destination address inside it,
  the `sendto()` syscall still requires you to separately specify *where* via
  this struct (it uses it for routing the packet, separate from what's
  literally inside the bytes we wrote).
- **The fault-injection hook** (`should_simulate_drop`): before actually
  sending, roll a die; if it lands within the configured loss percentage
  *and* this is a data segment (`TH_PSH`), skip the real `sendto()` call
  entirely but still return success, so the caller behaves exactly as if the
  network silently ate the packet. Controlled via env var
  `TCP_SIMULATE_LOSS_PCT` — this is the mechanism that let us prove the
  retransmission logic actually works when Docker Desktop's `tc netem`
  wouldn't cooperate on loopback.

### Step 3: `process_ack` — bookkeeping when an ACK arrives

This runs every time we receive a packet that has the ACK flag set (called
from inside `recv_packet`, which all the higher-level functions call).

Conceptually: we keep an array of 64 "segments" we've sent but haven't yet
had confirmed (`conn->send_buf`). Each one knows its own starting sequence
number and length. When an ACK comes in carrying `ack_num`, TCP's rule is
**cumulative acknowledgment** — `ack_num` means "I've successfully received
every byte up through `ack_num - 1`," not just "I got that one specific
segment." So:

- The loop checks every segment slot still marked `in_use`. `seq + len <=
  ack_num` means "this segment's last byte is below what's been
  acknowledged" → it's been fully confirmed, so we clear it (`in_use = 0`),
  freeing that slot for a future send.
- `send_base` tracks "the earliest byte we've sent that *isn't* yet
  acknowledged" — i.e., the left edge of our sliding window. Since ACKs are
  cumulative, if `ack_num` is bigger than our current `send_base`, we can
  just jump `send_base` forward to `ack_num` directly rather than figuring
  out which exact segments to retire — cheaper and exactly matches real TCP
  semantics.

### Step 4: `retransmit_check` — "did anyone forget to ACK me?"

This gets called repeatedly (from `tcp_send`'s polling loop) and scans every
still-unacknowledged segment, asking "has it been too long since I sent
this?"

- `int rto = RTO_INITIAL << conn->send_buf[i].retries` — **exponential
  backoff**. `RTO_INITIAL` is 1 (second). `<<` is a left bit-shift, which for
  integers is the same as multiplying by 2 per shift. So retry 0 → `1 << 0` =
  1s, retry 1 → `1 << 1` = 2s, retry 2 → `1 << 2` = 4s, etc. — each retry
  doubles the wait, capped at `RTO_MAX` (64s), so we don't hammer an already
  struggling network.
- `if (now - sent_at >= rto)` — has enough time elapsed since we last sent
  (or retried) this segment? If not, leave it alone, move to the next slot.
- If we've already retried `MAX_RETRIES` (5) times with no luck, give up —
  mark the slot free and stop trying. This mirrors real TCP, which eventually
  kills a connection it can't get acknowledged.
- Otherwise: retransmit it. `send_tcp_packet` always reads `conn->seq` to
  decide what sequence number to stamp on the outgoing packet, but this old
  segment has its *own* original sequence number (it might not be the most
  recent thing we sent). So we temporarily overwrite `conn->seq` with the
  segment's original number, call `send_tcp_packet`, then restore `conn->seq`
  back to whatever it was — "borrowing" the connection struct's field for one
  packet without permanently disturbing it.
- Reset the segment's `sent_at` to now and bump `retries`, so the backoff
  timer restarts for the next round.

### Step 5: `recv_packet` — reading and filtering incoming traffic

A raw socket with `IPPROTO_TCP` receives a copy of **every** TCP packet the
kernel sees on this interface — not just ones meant for us. This function's
job is to keep reading until it finds one that's actually ours, then hand
back the parsed info.

- `uint8_t buf[PACKET_BUF]` — a 64KB **stack-allocated** array (no
  `malloc`/`calloc` needed; it lives and dies with this function call
  automatically).
- `struct timeval tv = {timeout_sec, 0}` + `setsockopt(..., SO_RCVTIMEO,
  ...)` — without this, `recvfrom` would block *forever* if nothing ever
  arrives. This sets a timeout so the call gives up and returns an error
  after `timeout_sec` seconds, letting the caller decide what "nobody
  answered" means.
- **The filtering loop** (matters a lot since we see *all* TCP traffic, not
  just ours):
  - `ip_hdr_len = (iph->ihl_ver & 0x0F) * 4` — remember `ihl_ver` packs
    version+headerlen into one byte; `& 0x0F` masks off the upper 4 bits
    (version), keeping only the lower 4 (header length in 32-bit words), then
    `*4` converts to bytes.
  - `if (iph->src_addr != conn->dst_ip) continue;` — not from the peer we're
    talking to? Skip it, loop back to `recvfrom` again.
  - `if (ntohs(th->dst_port) != MY_PORT) continue;` — not addressed to our
    port? Skip it too.
  - Once both checks pass, this packet is genuinely part of our connection.
- **This is where the "always-on" ACK processing happens.** Every single
  packet we successfully parse (regardless of whether the caller cares about
  ACKs right now) updates `conn->peer_window` and, if the ACK flag is set,
  calls `process_ack`. This is why retransmission/window-sliding "just works"
  everywhere — `tcp_connect`, `tcp_send`, `tcp_recv`, and `tcp_close` all
  eventually call `recv_packet`, so they all get this bookkeeping for free
  without each having to remember to do it themselves.
- **Extracting the payload:** `tcp_hdr_len = (th->data_off >> 4) * 4` reverses
  the packing from earlier — shift right by 4 to discard the lower (reserved)
  bits, leaving the word-count, times 4 for bytes. `total_len` (from the IP
  header) minus the IP header size minus the TCP header size is whatever's
  left over — the actual application data, if any.

### Step 6: `tcp_connect` — the three-way handshake itself

This function does literally three things, in order, matching the plan's
diagram exactly:

1. **Send SYN**: build and send a packet with only the SYN flag set, no data.
   State moves `CLOSED → SYN_SENT`.
2. **Wait for SYN+ACK**: block (up to 5 seconds) for a reply.
   `(th.flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK)` checks "are *both*
   SYN and ACK bits set?" — masking with the combined flags and comparing
   against the same combined value. If the peer sent something else, we bail.
3. **The sequence number handoff** — the trickiest part conceptually:
   - `conn->ack = ntohl(th.seq_num) + 1` — the peer's SYN packet "uses up"
     one sequence number (even though a SYN carries no actual data, the
     protocol still counts it as 1 byte for bookkeeping purposes). So "the
     next byte I expect from them" is their sequence number plus 1.
   - `conn->seq = ntohl(th.ack_num)` — similarly, *our* SYN used up one of
     *our* sequence numbers. Conveniently, the peer's ACK number already
     tells us exactly what our next sequence number should be, so we just
     adopt that value directly.
4. **Send ACK**: now that we know the correct seq/ack numbers, send a plain
   ACK with no data. The state becomes `ESTABLISHED`, and
   `send_base = conn->seq` initializes the sliding-window bookkeeping
   ("nothing sent yet that's unacknowledged").

This is the whole handshake — 3 packets, 3 state transitions, exactly as
drawn in the plan.

### Step 7: `tcp_send` — chopping data into segments, respecting the window

`data` here might be much bigger than what fits in one packet (1460 bytes,
the MSS — Maximum Segment Size, chosen so the whole IP packet stays under the
typical 1500-byte Ethernet MTU). This function loops, sending one MSS-sized
chunk at a time, until everything's been queued.

- **Window-full check:** `in_flight = conn->seq - conn->send_base` is "how
  many bytes have I sent that aren't yet acknowledged?" If that's already at
  or above what the peer told us it can buffer (`conn->peer_window`, learned
  from their advertised window in every received packet), we stop sending
  new data and instead poll: call `recv_packet` with a short 1-second timeout
  (just checking "did an ACK arrive that would free up space?"), then
  `retransmit_check` (in case something old needs resending), then loop back
  and re-check.
- `chunk = min(len - sent, MSS)` — take either the rest of the data or one
  full MSS, whichever's smaller.
- **Finding a free tracking slot:** before sending, we need an open slot in
  `send_buf` to remember this segment for potential retransmission. If all
  64 are full (rare, but possible under heavy loss), wait the same way as the
  window-full case.
- Record this segment's metadata (sequence number, length, timestamp, retry
  count starting at 0) and copy its actual bytes into the slot — this copy
  matters because `data` (the caller's buffer) might get freed or overwritten
  before we need to retransmit later; the segment needs its *own* durable
  copy.
- Actually send it, flagged `ACK | PSH` (ACK because we're always
  acknowledging whatever we've previously received; PSH — "push" —
  historically meant "deliver this to the application immediately, don't
  buffer it," conventionally set on any segment carrying real data).
- Advance `conn->seq` by however many bytes we just sent.

**The drain loop** (after the main while loop): once every chunk has been
*sent*, that doesn't mean it's been *acknowledged*. Without this, a small
payload that fits entirely under the window would get sent in one shot and
`tcp_send` would return immediately — and if one of those packets got lost,
nothing would ever notice or retry it, because `retransmit_check` is only
called from inside the window-full/buffer-full waiting branches above, which
a small payload never triggers. This loop just keeps polling and retrying
until every segment's slot is freed (acknowledged) or gives up after
`MAX_RETRIES`. **This was a real bug found during testing** — see the
"bugs found during testing" section below.

### Step 8: `tcp_recv` — receiving the response data

This is the mirror image of `tcp_send`, repeatedly calling `recv_packet`
(5-second timeout — we're willing to actually wait, not just poll) until
either the buffer's full or the peer signals it's done.

- Whenever a packet carries actual data, copy it into the caller's buffer
  (with a bounds check so we never write past the end of `buf` — a classic
  buffer-overflow guard), then **advance our own `ack` and immediately send
  an ACK**. This is the receiver-side half of the conversation: every chunk
  of data the peer sends, we must acknowledge so they know it arrived and can
  slide *their* window forward.
- FIN means "I have no more data to send, ever." Just like SYN, FIN consumes
  one sequence number, so `conn->ack++` before acknowledging it, then we
  ACK it and move to `CLOSE_WAIT`.

### Step 9: closing the connection — two different paths

TCP close isn't symmetric — whoever sends FIN *first* is the "active
closer," and the side that receives it is the "passive closer," and they go
through different state sequences:

**`tcp_close_passive`**: runs when the *peer* already sent FIN first (which
`tcp_recv` already detected and ACKed, moving us into `CLOSE_WAIT`). Since
we've already received their FIN, all that's left is: send our own FIN, move
to `LAST_ACK`, wait for them to ACK it, then we're `CLOSED`. Only 2 more
packets needed.

**`tcp_close_active`**: runs when *we* initiate the close from `ESTABLISHED`
(peer hasn't sent FIN yet). This needs the full four-step dance: send FIN →
`FIN_WAIT_1`, wait for their ACK → `FIN_WAIT_2`, wait for *their* FIN → send
our ACK → `TIME_WAIT`, then sleep before fully closing. `TIME_WAIT`
(shortened to 4 seconds here from the real-world 60s "2×MSL") exists in real
TCP to absorb any stray duplicate packets still wandering the network from
this connection, so they don't get mistaken for a brand new one reusing the
same ports.

**`tcp_close`** is the public function `main.c` actually calls — it just
looks at the current state and dispatches to whichever of the two paths
applies. This dispatch is exactly the bug found during testing: originally
there was only one path (the active one), so when the server had already
sent FIN, the code incorrectly tried to do the active-close dance on top of a
connection that was already half-closed, and it hung waiting for a FIN that
would never come (since it already arrived and was consumed).

**`tcp_destroy`** is simple cleanup: `close()` the raw socket file descriptor
(releasing the resource back to the OS) and `free()` the heap memory we
`calloc`'d back in `tcp_create`. In C, nothing is garbage-collected — every
`calloc`/`malloc` needs a matching `free`, or that memory is "leaked" until
the program exits.

---

## `main.c` — tying it all together

This is the only file with an actual `main` function — the entry point every
C program needs. Everything here is just calling the public functions
declared in `tcp.h`, in the obvious order:

1. `tcp_create` — open the raw socket, set up connection state, pick a random
   ISN.
2. `tcp_connect` — perform the three-way handshake. If it fails, clean up and
   exit.
3. Build a literal HTTP request string and `tcp_send` it — note
   `(uint8_t *)req`: `req` is `const char *` (text), but `tcp_send` expects
   `const uint8_t *` (raw bytes) — this is a **cast**, explicitly telling the
   compiler "I know these are different types, treat this pointer as the
   other type." Since both are really just "address of some bytes," this is
   safe here.
4. `tcp_recv` into a 64KB stack buffer, then print the first 300 characters of
   whatever came back.
5. `tcp_close` — runs whichever close path applies based on current state.
6. `tcp_destroy` — release the socket and free the connection struct.

---

## Putting it together: one real run, traced

Here's what actually happened in the Phase 4 test, mapped onto the code:

```
[TX] seq=362833854 ... SYN          ← tcp_connect: send_tcp_packet(conn, TH_SYN, ...)
[RX] seq=3090045606 ack=362833855 ... SYN ACK   ← recv_packet sees the server's reply
                                                    conn->ack = 3090045606+1, conn->seq = 362833855
[TX] seq=362833855 ack=3090045607 ... ACK       ← tcp_connect: handshake done, ESTABLISHED

[TX] seq=362833855 ... len=35 ACK PSH           ← tcp_send: our HTTP GET, 35 bytes, one segment
[RX] ack=362833890 ... ACK                       ← recv_packet → process_ack frees that segment's slot
[RX] seq=3090045607 ... ACK PSH                 ← tcp_recv: server's response, segment 1 (155 bytes)
[TX] ack=3090045762 ... ACK                      ← tcp_recv: we ACK what we received
[RX] seq=3090045762 ... ACK PSH                 ← segment 2 (275 bytes)
[RX] ... ACK FIN                                 ← server says "done sending", state → CLOSE_WAIT

[TX] ... ACK FIN                                 ← tcp_close → tcp_close_passive: our FIN, state → LAST_ACK
[RX] ... ACK                                     ← server ACKs our FIN, state → CLOSED
```

Every line is a direct consequence of one specific function call doing
exactly what's described above. A good next step for building intuition:
open `captures/final.pcap` in Wireshark side-by-side with these `[TX]`/`[RX]`
log lines and match each printed line to the packet Wireshark shows — that'll
cement how the C code's view of the world (structs, function calls) maps onto
the actual bytes on the wire.

---

## Bugs found during testing (and why they matter)

Two real bugs surfaced only once this was actually run against real servers
in the Docker container — worth understanding both, since they're the kind of
subtle protocol-state bugs that are easy to miss by just reading code:

1. **Passive vs. active close** — `tcp_close` originally always ran the
   active-close path (FIN_WAIT_1 → FIN_WAIT_2 → wait for peer FIN). When the
   server (Python's `http.server`) sent its FIN *before* we called
   `tcp_close` (because it had already finished sending its response), our
   connection was sitting in `CLOSE_WAIT`, not `ESTABLISHED`. The old code
   sent a FIN, moved to `FIN_WAIT_1`, and then sat there waiting for a second
   FIN from the peer that would never come — that FIN had already arrived and
   been consumed. Fixed by splitting into `tcp_close_active` and
   `tcp_close_passive`, dispatched based on current state.

2. **No retransmission for small payloads** — `tcp_send`'s only call to
   `retransmit_check` was inside the "window full" / "buffer full" waiting
   loops. For a payload that fits entirely under the peer's advertised
   window (any payload under ~64KB, which is most things), every chunk gets
   queued and sent immediately without ever entering those loops — so
   `tcp_send` would send everything and return right away. If one of those
   packets was dropped, nothing would ever check on it again. Fixed by adding
   a "drain loop" after all chunks are queued: keep polling for ACKs and
   calling `retransmit_check` until every segment is either acknowledged or
   gives up after `MAX_RETRIES`.

Both were caught by actually running the code against `nc` and a real HTTP
server inside the Docker container, not by reading the code — a good
reminder that for protocol/state-machine code, runtime behavior under real
conditions (including induced packet loss) finds bugs that look completely
fine on paper.
