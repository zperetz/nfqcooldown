package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	core "nfqcooldown/internal"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

var Version = "dev"

type Config struct {
	QueueNum          uint
	Action            string
	Mode              string
	Cooldown          time.Duration
	MinDelay          time.Duration
	MaxDelay          time.Duration
	Jitter            time.Duration
	Whitelist         string
	Verbose           bool
	Seed              int64
	StatsEvery        time.Duration
	CleanupAfter      time.Duration
	CleanupEvery      time.Duration
	ForgetOnDrop      bool
	MaxDropsPerIP     int
	RejectMark        int
	Packet            string
	MaxPendingDelays  int
	DelayStrategy     string
	SingleDropRepeats int
	PaceInterval      time.Duration
	MaxQueuedDelay    time.Duration
}

func parseConfig() Config {
	queueNum := flag.Uint("queue", 443, "NFQUEUE number")
	action := flag.String("action", "drop", "action inside cooldown: drop, delay or reject")
	mode := flag.String("mode", "fixed", "interval algorithm: fixed, random or jitter")
	cooldownStr := flag.String("cooldown", "500ms", "base cooldown: 300ms, 500ms, 1s")
	minDelayStr := flag.String("min-delay", "300ms", "random mode minimum delay")
	maxDelayStr := flag.String("max-delay", "700ms", "random mode maximum delay")
	jitterStr := flag.String("jitter", "100ms", "jitter mode spread around cooldown")
	whitelist := flag.String("whitelist", "", "comma-separated CIDR/IP whitelist")
	verbose := flag.Bool("verbose", false, "log every SYN decision instead of periodic aggregate stats")
	seed := flag.Int64("seed", 0, "random seed; 0 means current time")
	statsEveryStr := flag.String("stats-every", "30s", "aggregate stats interval")
	cleanupAfterStr := flag.String("cleanup-after", "10m", "forget inactive IPs after this duration")
	cleanupEveryStr := flag.String("cleanup-every", "30s", "cleanup interval")
	forgetOnDrop := flag.Bool("forget-on-drop", false, "forget source IP state after DROP/REJECT")
	maxDropsPerIP := flag.Int("max-drops-per-ip", 0, "force accept after N consecutive drops from same IP; 0 disables")
	rejectMarkStr := flag.String("reject-mark", "0", "packet mark for reject action, e.g. 0x44; 0 disables")
	packet := flag.String("packet", "syn", "packet type to process: syn or synack")
	maxPendingDelays := flag.Int("max-pending-delays", 0, "maximum pending delayed packets; 0 disables limit")
	delayStrategy := flag.String("delay-strategy", "sleep", "delay strategy: sleep, pace or single")
	singleDropRepeats := flag.Int("single-drop-repeats", 0, "for single strategy: drop first N packets while delay is pending; 0 drops all")
	paceIntervalStr := flag.String("pace-interval", "250ms", "interval between paced delayed packets")
	maxQueuedDelayStr := flag.String("max-queued-delay", "0", "maximum queued delay for pace strategy; 0 disables")

	flag.Usage = printUsage

	for _, arg := range os.Args[1:] {
		switch arg {
		case "--help":
			printUsage()
			os.Exit(0)
		case "--version":
			fmt.Printf("nfqcooldown %s\n", Version)
			os.Exit(0)
		}
	}

	flag.Parse()

	cooldown := mustDuration("cooldown", *cooldownStr)
	minDelay := mustDuration("min-delay", *minDelayStr)
	maxDelay := mustDuration("max-delay", *maxDelayStr)
	jitter := mustDuration("jitter", *jitterStr)
	statsEvery := mustDuration("stats-every", *statsEveryStr)
	cleanupAfter := mustDuration("cleanup-after", *cleanupAfterStr)
	cleanupEvery := mustDuration("cleanup-every", *cleanupEveryStr)
	paceInterval := mustDuration("pace-interval", *paceIntervalStr)
	maxQueuedDelay := mustDuration("max-queued-delay", *maxQueuedDelayStr)

	rejectMark64, err := strconv.ParseUint(*rejectMarkStr, 0, 32)
	if err != nil {
		fatalf("bad reject-mark %q: %v", *rejectMarkStr, err)
	}

	if *action != "drop" && *action != "delay" && *action != "reject" {
		fatalf("bad action %q: use drop, delay or reject", *action)
	}

	if *packet != "syn" && *packet != "synack" {
		fatalf("bad packet %q: use syn or synack", *packet)
	}

	if *delayStrategy != "sleep" && *delayStrategy != "pace" && *delayStrategy != "single" {
		fatalf("bad delay-strategy %q: use sleep, pace or single", *delayStrategy)
	}

	if *singleDropRepeats < 0 {
		fatalf("bad single-drop-repeats %d: must be >= 0", *singleDropRepeats)
	}

	return Config{
		QueueNum:          *queueNum,
		Packet:            *packet,
		Action:            *action,
		Mode:              *mode,
		Cooldown:          cooldown,
		MinDelay:          minDelay,
		MaxDelay:          maxDelay,
		Jitter:            jitter,
		Whitelist:         *whitelist,
		Verbose:           *verbose,
		RejectMark:        int(rejectMark64),
		Seed:              *seed,
		StatsEvery:        statsEvery,
		MaxDropsPerIP:     *maxDropsPerIP,
		ForgetOnDrop:      *forgetOnDrop,
		CleanupAfter:      cleanupAfter,
		CleanupEvery:      cleanupEvery,
		MaxPendingDelays:  *maxPendingDelays,
		DelayStrategy:     *delayStrategy,
		SingleDropRepeats: *singleDropRepeats,
		PaceInterval:      paceInterval,
		MaxQueuedDelay:    maxQueuedDelay,
	}
}

func mustDuration(name, value string) time.Duration {
	d, err := time.ParseDuration(value)
	if err != nil {
		fatalf("bad %s %q: %v", name, value, err)
	}
	return d
}

func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
func logVerbose(enabled bool, format string, args ...any) {
	if enabled {
		fmt.Printf("[nfqcooldown] "+format+"\n", args...)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `nfqcooldown %s

Experimental NFQUEUE-based TCP SYN pacing daemon.

USAGE:
    nfqcooldown [OPTIONS]

CORE OPTIONS:
    --queue <n>                 NFQUEUE number (default: 443)
    --action <mode>             Action inside cooldown: drop | delay | reject (default: drop)
    --mode <algorithm>          Cooldown algorithm: fixed | random | jitter (default: fixed)
    --packet <syn|synack>       Packet type to process (default: syn)

TIMING:
    --cooldown <duration>       Base cooldown for fixed/jitter mode (default: 500ms)
    --min-delay <duration>      Random mode minimum cooldown (default: 300ms)
    --max-delay <duration>      Random mode maximum cooldown (default: 700ms)
    --jitter <duration>         Jitter around base cooldown (default: 100ms)

STATE:
    --cleanup-every <duration>  Cleanup interval (default: 30s)
    --cleanup-after <duration>  Forget inactive IPs after this duration (default: 10m)
    --forget-on-drop            Forget source IP state after DROP/REJECT
    --max-drops-per-ip <n>      Force accept after N consecutive drops; 0 disables
    --reject-mark <mark>        packet mark for reject action, e.g. 0x44; 0 disables
    --single-drop-repeats <n>   In single strategy, drop first N pending repeats; 0 drops all

FILTERING:
    --whitelist <ip,cidr,...>   Comma-separated IP/CIDR whitelist

LOGGING:
    --stats-every <duration>    Aggregate stats interval (default: 30s)
    --verbose                   Log every SYN decision

RANDOMNESS:
    --seed <n>                  Random seed; 0 means current time

OTHER:
    --help                      Show this help
    --version                   Show program version

EXAMPLES:
    nfqcooldown --queue 443 --action drop --mode fixed --cooldown 500ms

    nfqcooldown --queue 443 --action drop --mode random \
      --min-delay 300ms --max-delay 450ms

    nfqcooldown --queue 443 --action delay --mode jitter \
      --cooldown 500ms --jitter 100ms

`, Version)
}

func main() {
	cfg := parseConfig()
	if cfg.Seed == 0 {
		cfg.Seed = time.Now().UnixNano()
	}
	rand.Seed(cfg.Seed)

	algorithm, err := core.NewAlgorithm(cfg.Mode, cfg.Cooldown, cfg.MinDelay, cfg.MaxDelay, cfg.Jitter)
	if err != nil {
		fatalf("%v", err)
	}
	whitelist, err := core.NewWhitelist(cfg.Whitelist)
	if err != nil {
		fatalf("%v", err)
	}

	state := core.NewState(algorithm)
	counters := &core.Counters{}

	nfqConfig := nfqueue.Config{NfQueue: uint16(cfg.QueueNum), MaxPacketLen: 0xffff, MaxQueueLen: 8192, Copymode: nfqueue.NfQnlCopyPacket, WriteTimeout: 15 * time.Millisecond}
	nf, err := nfqueue.Open(&nfqConfig)
	if err != nil {
		fatalf("could not open nfqueue: %v", err)
	}
	defer nf.Close()
	_ = nf.SetOption(netlink.NoENOBUFS, true)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go cleanupLoop(ctx, state, cfg.CleanupEvery, cfg.CleanupAfter)
	go statsLoop(ctx, cfg, state, counters)

	var pendingDelays int64
	var nextSendAtByIP sync.Map
	var singlePendingByIP sync.Map
	var singleDropCountByIP sync.Map
	handler := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		if a.Payload == nil {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		var srcIP string
		var matched bool

		switch cfg.Packet {
		case "syn":
			srcIP, matched = core.ParseIPv4PureTCPSYN(*a.Payload)

		case "synack":
			info, ok := core.ParseIPv4TCPSYNACK(*a.Payload)
			if ok {
				srcIP = info.ClientIP
				matched = true
			}
		}

		if !matched {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		if whitelist.Contains(srcIP) {
			ev := core.LastEvent{Type: "ACCEPT-WHITELIST", IP: srcIP, PacketID: id}
			state.RememberEvent(ev)
			counters.IncAccepted()
			logVerbose(cfg.Verbose, "ACCEPT-WHITELIST ip=%s packet=%d", srcIP, id)
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		now := time.Now()
		allowed, cooldown, elapsed, remaining, _ := state.Decide(srcIP, now, id)
		if allowed {
			counters.IncAccepted()
			logVerbose(cfg.Verbose, "ACCEPT ip=%s packet=%d elapsed=%s new_cooldown=%s", srcIP, id, elapsed, cooldown)
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		switch cfg.Action {
		case "drop":
			dropCount := state.IncDrop(srcIP)

			if cfg.MaxDropsPerIP > 0 && dropCount > cfg.MaxDropsPerIP {
				cd, _ := state.ForceAccept(srcIP, time.Now(), id)
				counters.IncAccepted()

				logVerbose(cfg.Verbose,
					"FORCE-ACCEPT ip=%s packet=%d drops=%d new_cooldown=%s",
					srcIP, id, dropCount, cd,
				)

				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}
			counters.IncDropped()
			state.RememberEvent(core.LastEvent{Type: "DROP", IP: srcIP, PacketID: id, Cooldown: cooldown, Elapsed: elapsed, Remaining: remaining})
			if cfg.ForgetOnDrop {
				state.Forget(srcIP)
			}
			logVerbose(cfg.Verbose, "DROP ip=%s packet=%d cooldown=%s elapsed=%s remaining=%s", srcIP, id, cooldown, elapsed, remaining)
			_ = nf.SetVerdict(id, nfqueue.NfDrop)
			return 0
		case "reject":
			dropCount := state.IncDrop(srcIP)

			if cfg.MaxDropsPerIP > 0 && dropCount > cfg.MaxDropsPerIP {
				cd, _ := state.ForceAccept(srcIP, time.Now(), id)
				counters.IncAccepted()

				logVerbose(cfg.Verbose,
					"FORCE-ACCEPT ip=%s packet=%d drops=%d new_cooldown=%s",
					srcIP, id, dropCount, cd,
				)

				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}
			counters.IncRejected()
			state.RememberEvent(core.LastEvent{Type: "REJECT-DROP", IP: srcIP, PacketID: id, Cooldown: cooldown, Elapsed: elapsed, Remaining: remaining})
			if cfg.ForgetOnDrop {
				state.Forget(srcIP)
			}
			logVerbose(cfg.Verbose, "REJECT(DROP) ip=%s packet=%d cooldown=%s elapsed=%s remaining=%s", srcIP, id, cooldown, elapsed, remaining)
			if cfg.RejectMark != 0 {
				_ = nf.SetVerdictWithMark(id, nfqueue.NfAccept, cfg.RejectMark)
			} else {
				_ = nf.SetVerdict(id, nfqueue.NfDrop)
			}
			return 0
		case "delay":
			state.RememberEvent(core.LastEvent{Type: "DELAY", IP: srcIP, PacketID: id, Cooldown: cooldown, Elapsed: elapsed, Remaining: remaining})
			logVerbose(cfg.Verbose, "DELAY ip=%s packet=%d cooldown=%s elapsed=%s remaining=%s", srcIP, id, cooldown, elapsed, remaining)

			if cfg.MaxPendingDelays > 0 && atomic.LoadInt64(&pendingDelays) >= int64(cfg.MaxPendingDelays) {
				counters.IncDelayOverflowDropped()

				state.RememberEvent(core.LastEvent{
					Type:      "DELAY-OVERFLOW-DROP",
					IP:        srcIP,
					PacketID:  id,
					Cooldown:  cooldown,
					Elapsed:   elapsed,
					Remaining: remaining,
				})
				logVerbose(
					cfg.Verbose,
					"DELAY ip=%s packet=%d pending=%d cooldown=%s elapsed=%s remaining=%s",
					srcIP,
					id,
					atomic.LoadInt64(&pendingDelays),
					cooldown,
					elapsed,
					remaining,
				)
				_ = nf.SetVerdict(id, nfqueue.NfDrop)
				return 0
			}

			counters.IncDelayed()

			actualDelay := remaining

			if cfg.DelayStrategy == "pace" {
				now := time.Now()

				v, _ := nextSendAtByIP.LoadOrStore(srcIP, now)
				nextSendAt := v.(time.Time)

				if nextSendAt.Before(now) {
					nextSendAt = now
				}

				sendAt := nextSendAt.Add(cfg.PaceInterval)
				actualDelay = time.Until(sendAt)

				if cfg.MaxQueuedDelay > 0 && actualDelay > cfg.MaxQueuedDelay {
					counters.IncDelayOverflowDropped()

					state.RememberEvent(core.LastEvent{
						Type:      "PACE-OVERFLOW-DROP",
						IP:        srcIP,
						PacketID:  id,
						Cooldown:  cooldown,
						Elapsed:   elapsed,
						Remaining: actualDelay,
					})

					logVerbose(cfg.Verbose,
						"PACE-OVERFLOW-DROP ip=%s packet=%d queued_delay=%s max_queued_delay=%s",
						srcIP, id, actualDelay, cfg.MaxQueuedDelay,
					)

					_ = nf.SetVerdict(id, nfqueue.NfDrop)
					return 0
				}

				nextSendAtByIP.Store(srcIP, sendAt)
			}

			releaseSingle := false

			if cfg.DelayStrategy == "single" {
				if _, loaded := singlePendingByIP.LoadOrStore(srcIP, true); loaded {
					dropCount := 0
					if v, ok := singleDropCountByIP.Load(srcIP); ok {
						dropCount = v.(int)
					}

					if cfg.SingleDropRepeats > 0 && dropCount >= cfg.SingleDropRepeats {
						counters.IncAccepted()

						state.RememberEvent(core.LastEvent{
							Type:      "SINGLE-PENDING-ACCEPT",
							IP:        srcIP,
							PacketID:  id,
							Cooldown:  cooldown,
							Elapsed:   elapsed,
							Remaining: remaining,
						})

						logVerbose(cfg.Verbose,
							"SINGLE-PENDING-ACCEPT ip=%s packet=%d drops=%d limit=%d cooldown=%s elapsed=%s remaining=%s",
							srcIP, id, dropCount, cfg.SingleDropRepeats, cooldown, elapsed, remaining,
						)

						_ = nf.SetVerdict(id, nfqueue.NfAccept)
						return 0
					}

					singleDropCountByIP.Store(srcIP, dropCount+1)
					counters.IncDelayOverflowDropped()

					state.RememberEvent(core.LastEvent{
						Type:      "SINGLE-PENDING-DROP",
						IP:        srcIP,
						PacketID:  id,
						Cooldown:  cooldown,
						Elapsed:   elapsed,
						Remaining: remaining,
					})

					logVerbose(cfg.Verbose,
						"SINGLE-PENDING-DROP ip=%s packet=%d drops=%d limit=%d cooldown=%s elapsed=%s remaining=%s",
						srcIP, id, dropCount+1, cfg.SingleDropRepeats, cooldown, elapsed, remaining,
					)

					_ = nf.SetVerdict(id, nfqueue.NfDrop)
					return 0
				}

				releaseSingle = true
				singleDropCountByIP.Store(srcIP, 0)
			}

			atomic.AddInt64(&pendingDelays, 1)

			go func(packetID uint32, ip string, delay time.Duration, releaseSingle bool) {
				defer atomic.AddInt64(&pendingDelays, -1)
				time.Sleep(delay)
				cd, _ := state.MarkDelayedAccept(ip, time.Now(), packetID, delay)
				counters.IncAccepted()

				logVerbose(cfg.Verbose,
					"ACCEPT-AFTER-DELAY ip=%s packet=%d strategy=%s waited=%s new_cooldown=%s pending=%d",
					ip,
					packetID,
					cfg.DelayStrategy,
					delay,
					cd,
					atomic.LoadInt64(&pendingDelays),
				)

				_ = nf.SetVerdict(packetID, nfqueue.NfAccept)

				if releaseSingle {
					singlePendingByIP.Delete(ip)
					singleDropCountByIP.Delete(ip)
				}
			}(id, srcIP, actualDelay, releaseSingle)
			return 0
		}
		_ = nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	fmt.Printf("[nfqcooldown] started queue=%d action=%s mode=%s cooldown=%s min=%s max=%s jitter=%s whitelist=%d verbose=%v seed=%d\n", cfg.QueueNum, cfg.Action, cfg.Mode, cfg.Cooldown, cfg.MinDelay, cfg.MaxDelay, cfg.Jitter, whitelist.Len(), cfg.Verbose, cfg.Seed)
	err = nf.RegisterWithErrorFunc(ctx, handler, func(e error) int { fmt.Fprintf(os.Stderr, "nfqueue error: %v\n", e); return 0 })
	if err != nil {
		fatalf("register failed: %v", err)
	}
	<-ctx.Done()
}

func cleanupLoop(ctx context.Context, state *core.State, every, ttl time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			removed := state.Cleanup(ttl)
			if removed > 0 {
				fmt.Printf("[nfqcooldown] cleanup removed=%d ttl=%s\n", removed, ttl)
			}
		}
	}
}

func statsLoop(ctx context.Context, cfg Config, state *core.State, counters *core.Counters) {
	t := time.NewTicker(cfg.StatsEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if cfg.Verbose {
				continue
			}
			tracked, ev := state.Snapshot()
			accepted, delayed, dropped, rejected := counters.Snapshot()
			fmt.Printf("[nfqcooldown] accepted=%d delayed=%d dropped=%d rejected=%d tracked_ips=%d action=%s mode=%s cooldown=%s min=%s max=%s jitter=%s last=%s ip=%s packet=%d actual_cooldown=%s elapsed=%s remaining=%s\n", accepted, delayed, dropped, rejected, tracked, cfg.Action, cfg.Mode, cfg.Cooldown, cfg.MinDelay, cfg.MaxDelay, cfg.Jitter, ev.Type, ev.IP, ev.PacketID, ev.Cooldown, ev.Elapsed, ev.Remaining)
		}
	}
}
