# nfqcooldown

NFQUEUE-based SYN cooldown daemon for TCP connection pacing experiments.

## Features

- per-source-IP cooldown for pure TCP SYN packets
- actions: `drop`, `delay`, `reject` (`reject` currently maps to DROP verdict; real TCP RST is a future feature)
- algorithms: `fixed`, `random`, `jitter`
- whitelist by IP/CIDR
- normal aggregate logs or per-packet `--verbose` logs
- designed for iptables NFQUEUE rules with `--queue-bypass`

## Build

On WSL or another Linux machine with Go 1.25+:

```bash
cd nfqcooldown
make build
```

Or:

```bash
go build -o nfqcooldown ./cmd/nfqcooldown
```

Copy the binary:

```bash
scp ./bin/nfqcooldown root@server:/usr/local/sbin/nfqcooldown
```

## iptables rule

Example for incoming pure SYN packets to 443 on eth0:

```bash
iptables -I INPUT 1 -i eth0 -p tcp --dport 443 \
  --tcp-flags FIN,SYN,RST,ACK SYN \
  -j NFQUEUE --queue-num 443 --queue-bypass
```

Keep your normal ACCEPT rule below it, for example:

```bash
iptables -A INPUT -i eth0 -p tcp --dport 443 -j ACCEPT
```

## Run manually

```bash
/usr/local/sbin/nfqcooldown --queue 443 --action drop --mode fixed --cooldown 500ms
```

```bash
/usr/local/sbin/nfqcooldown --queue 443 --action delay --mode random --min-delay 300ms --max-delay 450ms
```

```bash
/usr/local/sbin/nfqcooldown --queue 443 --action delay --mode jitter --cooldown 500ms --jitter 100ms
```

Verbose mode:

```bash
/usr/local/sbin/nfqcooldown --queue 443 --action delay --mode random --min-delay 300ms --max-delay 450ms --verbose
```

Whitelist:

```bash
/usr/local/sbin/nfqcooldown --queue 443 --cooldown 500ms --whitelist 93.158.192.22,185.93.42.204/32
```

## systemd

```bash
cp nfqcooldown.service /etc/systemd/system/nfqcooldown.service
cp nfqcooldown.default /etc/default/nfqcooldown
systemctl daemon-reload
systemctl enable --now nfqcooldown
journalctl -u nfqcooldown -f
```
