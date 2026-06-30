# nfqcooldown
[![Build](https://github.com/zperetz/nfqcooldown/actions/workflows/build.yml/badge.svg)](https://github.com/zperetz/nfqcooldown/actions/workflows/build.yml)

**nfqcooldown** is an experimental NFQUEUE-based TCP SYN pacing daemon for Linux.

It allows userspace logic to decide what to do with incoming TCP SYN packets: accept them, drop them, or delay them according to configurable cooldown algorithms.

The project is intended for experiments with TCP connection pacing, firewall behavior, packet filtering strategies, and client connection patterns.

## What it does

nfqcooldown receives selected packets from the Linux kernel through Netfilter NFQUEUE.

For each incoming TCP SYN packet, it tracks the source IP address and applies a cooldown policy. If a client tries to open a new TCP connection too soon, nfqcooldown can:

* drop the SYN packet;
* delay the SYN packet and accept it later;
* mark it as rejected in logs.

This makes it possible to implement packet handling logic that is difficult or impossible to express with standard iptables modules such as `recent`, `hashlimit`, or `connlimit`.

## Features

* Per-source-IP TCP SYN cooldown
* NFQUEUE-based userspace packet decisions
* Fixed cooldown mode
* Random cooldown mode
* Jitter cooldown mode
* Drop mode
* Delay mode
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
        +--> DELAY, then ACCEPT
```

Example iptables rule:

```bash
iptables -I INPUT 1 -i eth0 -p tcp --dport 443 \
  -m tcp --tcp-flags SYN SYN \
  -j NFQUEUE --queue-num 443 --queue-bypass
```

The `--queue-bypass` option is recommended. If the daemon is stopped or crashes, packets continue through the normal firewall path instead of being blocked.

## Installation

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

Run nfqcooldown with a fixed 500 ms cooldown:

```bash
sudo /usr/local/sbin/nfqcooldown \
  --queue 443 \
  --action drop \
  --mode fixed \
  --cooldown 500ms
```

Add an iptables NFQUEUE rule:

```bash
sudo iptables -I INPUT 1 -i eth0 -p tcp --dport 443 \
  --tcp-flags FIN,SYN,RST,ACK SYN \
  -j NFQUEUE --queue-num 443 --queue-bypass
```

## Usage examples

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

### Delay instead of drop

Delay packets that arrive inside the cooldown window:

```bash
sudo nfqcooldown \
  --queue 443 \
  --action delay \
  --mode random \
  --min-delay 300ms \
  --max-delay 450ms
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
  --action delay \
  --mode random \
  --min-delay 300ms \
  --max-delay 450ms \
  --verbose
```

Verbose mode logs individual packet decisions.

## Command-line options

| Option            | Description                                          |
| ----------------- | ---------------------------------------------------- |
| `--queue`         | NFQUEUE number                                       |
| `--action`        | Action inside cooldown: `drop`, `delay`, or `reject` |
| `--mode`          | Cooldown algorithm: `fixed`, `random`, or `jitter`   |
| `--cooldown`      | Base cooldown duration                               |
| `--min-delay`     | Minimum delay for random mode                        |
| `--max-delay`     | Maximum delay for random mode                        |
| `--jitter`        | Jitter range around base cooldown                    |
| `--whitelist`     | Comma-separated list of trusted IPs or CIDRs         |
| `--verbose`       | Enable per-packet decision logging                   |
| `--seed`          | Random seed for reproducible experiments             |
| `--stats-every`   | Aggregate statistics interval                        |
| `--cleanup-after` | Remove inactive IPs from memory after this duration  |

## systemd service

Example service file:

```ini
[Unit]
Description=NFQUEUE SYN cooldown
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/default/nfqcooldown
ExecStart=/usr/local/sbin/nfqcooldown --queue ${QUEUE} --action ${ACTION} --mode ${MODE} --cooldown ${COOLDOWN} --min-delay ${MIN_DELAY} --max-delay ${MAX_DELAY} --jitter ${JITTER} --whitelist ${WHITELIST} --verbose=${VERBOSE}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Example `/etc/default/nfqcooldown`:

```bash
QUEUE=443
ACTION=drop
MODE=fixed
COOLDOWN=500ms
MIN_DELAY=300ms
MAX_DELAY=450ms
JITTER=100ms
WHITELIST=
VERBOSE=false
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

## iptables example

A minimal setup for TCP port 443:

```bash
sudo iptables -I INPUT 1 -i eth0 -p tcp --dport 443 \
  --tcp-flags FIN,SYN,RST,ACK SYN \
  -j NFQUEUE --queue-num 443 --queue-bypass
```

Make sure your normal ACCEPT rule remains below it:

```bash
sudo iptables -A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT
```

## Logging

Normal mode prints aggregate statistics:

```text
[nfqcooldown] accepted=51 delayed=16 dropped=0 rejected=0 tracked_ips=9 action=delay mode=random cooldown=500ms min=300ms max=450ms jitter=150ms last=ACCEPT ip=1.2.3.4 actual_cooldown=419ms elapsed=0s remaining=0s
```

Verbose mode prints every packet decision:

```text
[nfqcooldown] ACCEPT ip=1.2.3.4 packet=123 elapsed=512ms new_cooldown=437ms
[nfqcooldown] DELAY ip=1.2.3.4 packet=124 cooldown=437ms elapsed=120ms remaining=317ms
[nfqcooldown] ACCEPT-AFTER-DELAY ip=1.2.3.4 packet=124 waited=317ms new_cooldown=421ms
```

## Current limitations

* IPv4 TCP SYN parsing only
* `reject` mode is currently logged separately but uses a DROP verdict internally
* Real TCP RST generation is not implemented yet
* Per-source-IP tracking only
* No JSON logs yet
* No Prometheus metrics yet

## Roadmap

* [x] Fixed cooldown algorithm
* [x] Random cooldown algorithm
* [x] Jitter cooldown algorithm
* [x] Drop action
* [x] Delay action
* [x] IP/CIDR whitelist
* [x] Verbose logging
* [ ] True TCP RST reject mode
* [ ] JSON logging
* [ ] CSV export
* [ ] Prometheus metrics
* [ ] Global cooldown scope
* [ ] Subnet-based cooldown scope
* [ ] Random-walk algorithm
* [ ] nftables examples
* [ ] GitHub Actions build workflow

## License

MIT
