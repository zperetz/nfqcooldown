# nfqcooldown
[![Build](https://github.com/zperetz/nfqcooldown/actions/workflows/build.yml/badge.svg)](https://github.com/zperetz/nfqcooldown/actions/workflows/build.yml)

**nfqcooldown** is an NFQUEUE-based IPv4 TCP SYN rate-limiting and shaping daemon for Linux.

It applies configurable rate-limiting and shaping policies to incoming TCP SYN packets.

The project is intended for experiments with TCP connection pacing, firewall behavior, packet filtering strategies, and client connection patterns.

## What it does

nfqcooldown receives selected packets from the Linux kernel through Netfilter NFQUEUE.

For each incoming TCP SYN packet, it tracks the source IP address and applies a cooldown policy. If a client tries to open a new TCP connection too soon, nfqcooldown can:

* temporarily delay a SYN packet to smooth bursts of new connections
* drop the SYN packet
* mark the SYN packet so nftables can actively reject it

This makes it possible to implement packet handling logic that is difficult or impossible to express with standard iptables modules such as `recent`, `hashlimit`, or `connlimit`.

## Features

* Per-source-IP TCP SYN rate limiting and shaping
* NFQUEUE-based userspace packet decisions
* SYN burst shaping with bounded packet delays
* Packet-mark bypass support
* Packet marking for nftables-based active rejection
* For DROP action:
      Fixed cooldown mode
      Random cooldown mode
      Jitter cooldown mode
* IP/CIDR whitelist
* Verbose per-packet logging
* Periodic aggregate statistics
* systemd-friendly design
* Written in Go

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/zperetz/nfqcooldown/main/install.sh | sudo bash
```

## How it works

A typical setup looks like this:

```text
incoming TCP SYN
        |
        v
iptables NFQUEUE rule
        |
        v
nfqcooldown daemon
        |
        +--> ACCEPT
        +--> DROP
        +--> SHAPE
        +--> MARK FOR REJECT
```

Example iptables rule:

```bash
sudo iptables -t mangle -I INPUT 1 -i eth0 -p tcp --dport 443 \
  -m tcp --tcp-flags SYN,RST,ACK SYN \
  -j NFQUEUE --queue-num 443 --queue-bypass
```
The `--queue-bypass` option is recommended. If the daemon is stopped or crashes, packets continue through the normal firewall path instead of being blocked.

If you use the default filter INPUT chain, make sure the normal ACCEPT rule remains below the NFQUEUE rule:

```bash
sudo iptables -A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT
```

For a more robust setup, nftables is recommended. The following example also includes the iOS TCP fingerprint bypass for telemt.
The example uses two packet-mark bits:

* `0x400` — bypasses nfqcooldown processing for matching Telemt iOS packets
* `0x800` — marks packets that nfqcooldown wants nftables to reject

```bash
sudo mkdir -p /etc/nftables.d
sudo tee /etc/nftables.d/nfqcooldown.nft >/dev/null <<'EOF'
table ip nfqcooldown {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        @th,108,20 0x2ffff \
        @th,160,16 0x0204 \
        @th,192,16 0x0103 \
        @th,224,24 0x010108 \
        @th,320,32 0x04020000 \
        meta mark set meta mark | 0x400 \
        counter
    }

    chain input {
        type filter hook input priority mangle; policy accept;

        iifname "eth0" \
        tcp dport 443 \
        tcp flags & (fin|syn|rst|ack) == syn \
        queue flags bypass to 443
    }

    chain input_reject {
        type filter hook input priority mangle + 1; policy accept;

        iifname "eth0" \
        tcp dport 443 \
        tcp flags & (fin|syn|rst|ack) == syn \
        meta mark & 0x800 != 0 \
        counter \
        reject with icmp type host-unreachable
    }
}
EOF
sudo tee /etc/systemd/system/nfqcooldown-nft.service >/dev/null <<'EOF'
[Unit]
Description=Load nfqcooldown nftables rules
After=network-online.target ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=-/usr/sbin/nft delete table ip nfqcooldown
ExecStart=/usr/sbin/nft -f /etc/nftables.d/nfqcooldown.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
```

Check and apply your nftables rules:
```bash
#Check
sudo nft -c -f /etc/nftables.d/nfqcooldown.nft

#Apply
sudo systemctl daemon-reload
sudo systemctl enable --now nfqcooldown-nft.service
```

Do not forget to replace ```eth0``` with your external interface.

Check your nft rules status:
```bash
sudo systemctl status nfqcooldown-nft.service
sudo nft list table ip nfqcooldown
```

## Build from source

Build the binary:

```bash
make build
```

Install it manually:

```bash
sudo install -m 0755 ./bin/nfqcooldown /usr/local/sbin/nfqcooldown
```

Or use:

```bash
sudo make install
```

## Quick start

Add an iptables NFQUEUE rule:

```bash
sudo iptables -I INPUT 1 -i eth0 -p tcp --dport 443 \
  -m tcp --tcp-flags SYN,RST,ACK SYN \
  -j NFQUEUE --queue-num 443 --queue-bypass
```

Start nfqcooldown:

### Shaping

```bash
sudo nfqcooldown \
  --queue 443 \
  --packet syn \
  --action shape \
  --burst-interval 1050ms \
  --burst-max-delay 350ms \
  --max-pending-delays 4 \
  --cleanup-every 8s \
  --cleanup-after 15s \
  --skip-mark 0x400
```


Other usage examples:

### Fixed cooldown

Allow one SYN per source IP every 500 ms:

```bash
sudo nfqcooldown \
  --queue 443 \
  --action drop \
  --mode fixed \
  --cooldown 500ms
```

### Random cooldown

Choose a random cooldown between 300 ms and 450 ms after each accepted SYN:

```bash
sudo nfqcooldown \
  --queue 443 \
  --action drop \
  --mode random \
  --min-delay 300ms \
  --max-delay 450ms
```

### Jitter cooldown

Use a 500 ms base cooldown with ±100 ms jitter:

```bash
sudo nfqcooldown \
  --queue 443 \
  --action drop \
  --mode jitter \
  --cooldown 500ms \
  --jitter 100ms
```

### Whitelist trusted IPs

```bash
sudo nfqcooldown \
  --queue 443 \
  --action drop \
  --mode fixed \
  --cooldown 500ms \
  --whitelist 90.80.70.60,185.186.187.188/32
```

### Verbose logging

```bash
sudo nfqcooldown \
  --queue 443 \
  --packet syn \
  --action shape \
  --verbose
```

Verbose mode logs individual packet decisions.

## Command-line options

| Option                  | Description                                            |
| ----------------------- | ------------------------------------------------------ |
| `--queue`               | NFQUEUE number                                         |
| `--packet`              | Packet type; synack is intended for diagnostics        |
| `--action`              | Action inside cooldown: `drop` or `shape`              |
| `--mode`                | Cooldown algorithm: `fixed`, `random`, or `jitter`     |
| `--cooldown`            | Base cooldown duration for fixed or jitter mode        |
| `--min-delay`           | Minimum delay for random mode                          |
| `--max-delay`           | Maximum delay for random mode                          |
| `--jitter`              | Jitter range around base cooldown                      |
| `--whitelist`           | Comma-separated list of trusted IPs or CIDRs  (IPv4)   |
| `--verbose`             | Enable per-packet decision logging                     |
| `--seed`                | Random seed for reproducible experiments               |
| `--stats-every`         | Aggregate statistics interval                          |
| `--cleanup-every`       | Remove inactive IPs from memory every `duration`       |
| `--cleanup-after`       | Remove inactive IPs from memory after `duration`       |
| `--forget-on-drop`      | Remove IP in case of DROP action                       |
| `--max-drops-per-ip`    | Force accept after N consecutive drops from same IP    |
| `--burst-interval`      | Min interval between released SYN packets for shape    |
| `--burst-max-delay`     | Maximum permitted delay for shape                      |
| `--max-pending-delays`  | Global pending shaped-packet limit                     |
| `--skip-mark`           | Accept matching packet marks before shaping/drop       |
| `--reject-mark`         | Mark packet for icmp-reject instead of drop (nftables) |

## systemd service

Example service file:

```ini
[Unit]
Description=NFQUEUE SYN cooldown
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/default/nfqcooldown.cfg
ExecStart=/usr/local/sbin/nfqcooldown $ARGS

Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Example (best practice, but ymmv)`/etc/default/nfqcooldown.cfg`:

```bash
ARGS="
  --queue 443
  --packet syn
  --action shape
  --burst-interval 1050ms
  --burst-max-delay 350ms
  --max-pending-delays 4
  --cleanup-every 8s
  --cleanup-after 15s
  --skip-mark 0x400
  --reject-mark 0x800
"
```

Enable service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nfqcooldown
```

View logs:

```bash
journalctl -u nfqcooldown -f
```

## Logging

Normal mode prints aggregate statistics:

```text
[nfqcooldown] accepted=51 delayed=7 dropped=3 tracked_ips=4 action=shape packet=syn burst_interval=1s burst_max_delay=50ms max_pending_delays=2 last=SHAPE-RELEASE ip=1.2.3.4 packet_id=51 remaining=0s
```

Verbose mode prints every packet decision:

```text
[nfqcooldown] SHAPE-ACCEPT ip=1.2.3.4 packet=15
[nfqcooldown] SHAPE-DELAY ip=1.2.3.4 packet=16 delay=42ms pending=1
[nfqcooldown] SHAPE-RELEASE ip=1.2.3.4 packet=16
```

## Current limitations

* IPv4 only (IPv6 is not supported)
* TCP SYN and SYN/ACK packet parsing

## License

MIT
