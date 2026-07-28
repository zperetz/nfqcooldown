# Outbound payload split (development)

This mode splits the first queued IPv4/TCP payload segment sent by the local
server process to its client. nftables must select the direction, normally
`OUTPUT`, `tcp sport 443`.

## Run

```bash
sudo ./nfqcooldown \
  --queue 444 \
  --packet payload \
  --action split \
  --split-at 1 \
  --split-mark 0x1000 \
  --split-delay 1ms \
  --verbose
```

Load `examples/nftables-output-split.nft` after replacing the interface name.

The service needs `CAP_NET_ADMIN` for NFQUEUE and `CAP_NET_RAW` for the second
raw IPv4 segment.

## Design

The original segment `SEQ=N, LEN=L` is represented as:

- modified NFQUEUE packet: `SEQ=N, LEN=split-at`;
- raw packet: `SEQ=N+split-at, LEN=L-split-at`.

The first part has PSH and FIN cleared. The second part keeps the original TCP
flags. IPv4 and TCP checksums are recalculated for both packets.

The split mark is applied to both packets. A later nftables base chain copies
it to `ct mark`; the queue rule skips both marked packets and marked flows.

## Current limits

- IPv4 only;
- no fragmented IPv4 packets;
- no GSO/GRO normalization inside the daemon;
- selection of the first flow payload is performed by conntrack mark rules;
- raw injection is Linux-only;
- this is development code and should first be tested on a non-critical host.
