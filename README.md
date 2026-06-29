# nfqcooldown

**nfqcooldown** is a lightweight experimental daemon for Linux that controls the pacing of incoming TCP connection establishment using **Netfilter NFQUEUE**.

Instead of relying on static firewall rules, nfqcooldown allows custom decision logic to be applied to every incoming TCP SYN packet. The daemon can:

* rate-limit new connections on a per-client basis;
* delay or drop selected SYN packets;
* apply different cooldown algorithms (fixed, random, jitter);
* whitelist trusted clients;
* provide detailed per-packet logging for experiments and debugging.

The project was designed as a flexible platform for researching TCP connection pacing and firewall behavior rather than as a traditional packet filter.

## Features

* Per-client cooldown tracking
* Fixed, random and jitter-based cooldown algorithms
* Multiple actions:

  * ACCEPT
  * DROP
  * DELAY
  * REJECT (planned)
* IP/CIDR whitelist
* Verbose event logging
* Aggregate statistics
* systemd integration
* Lightweight Go implementation

## Typical use cases

* TCP connection pacing experiments
* Firewall and NFQUEUE research
* Connection rate limiting
* Protocol testing
* Studying client connection behavior
* Building custom packet filtering policies

## Why NFQUEUE?

Traditional firewall modules such as `hashlimit`, `recent` or `connlimit` provide only predefined matching logic.

NFQUEUE makes it possible to implement arbitrary decision algorithms in userspace while still processing packets at the kernel firewall layer.

This enables sophisticated policies that are difficult or impossible to express using iptables or nftables alone.

## Status

The project is experimental and under active development.

New algorithms and packet processing strategies are welcome.
