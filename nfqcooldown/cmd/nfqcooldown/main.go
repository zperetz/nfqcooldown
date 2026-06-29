package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	core "nfqcooldown/internal"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

type Config struct {
	QueueNum     uint
	Action       string
	Mode         string
	Cooldown     time.Duration
	MinDelay     time.Duration
	MaxDelay     time.Duration
	Jitter       time.Duration
	Whitelist    string
	Verbose      bool
	Seed         int64
	StatsEvery   time.Duration
	CleanupAfter time.Duration
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
	flag.Parse()

	cooldown := mustDuration("cooldown", *cooldownStr)
	minDelay := mustDuration("min-delay", *minDelayStr)
	maxDelay := mustDuration("max-delay", *maxDelayStr)
	jitter := mustDuration("jitter", *jitterStr)
	statsEvery := mustDuration("stats-every", *statsEveryStr)
	cleanupAfter := mustDuration("cleanup-after", *cleanupAfterStr)

	if *action != "drop" && *action != "delay" && *action != "reject" {
		fatalf("bad action %q: use drop, delay or reject", *action)
	}

	return Config{QueueNum: *queueNum, Action: *action, Mode: *mode, Cooldown: cooldown, MinDelay: minDelay, MaxDelay: maxDelay, Jitter: jitter, Whitelist: *whitelist, Verbose: *verbose, Seed: *seed, StatsEvery: statsEvery, CleanupAfter: cleanupAfter}
}

func mustDuration(name, value string) time.Duration {
	d, err := time.ParseDuration(value)
	if err != nil { fatalf("bad %s %q: %v", name, value, err) }
	return d
}
func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
func logVerbose(enabled bool, format string, args ...any) { if enabled { fmt.Printf("[nfqcooldown] "+format+"\n", args...) } }

func main() {
	cfg := parseConfig()
	if cfg.Seed == 0 { cfg.Seed = time.Now().UnixNano() }
	rand.Seed(cfg.Seed)

	algorithm, err := core.NewAlgorithm(cfg.Mode, cfg.Cooldown, cfg.MinDelay, cfg.MaxDelay, cfg.Jitter)
	if err != nil { fatalf("%v", err) }
	whitelist, err := core.NewWhitelist(cfg.Whitelist)
	if err != nil { fatalf("%v", err) }

	state := core.NewState(algorithm)
	counters := &core.Counters{}

	nfqConfig := nfqueue.Config{NfQueue: uint16(cfg.QueueNum), MaxPacketLen: 0xffff, MaxQueueLen: 8192, Copymode: nfqueue.NfQnlCopyPacket, WriteTimeout: 15 * time.Millisecond}
	nf, err := nfqueue.Open(&nfqConfig)
	if err != nil { fatalf("could not open nfqueue: %v", err) }
	defer nf.Close()
	_ = nf.SetOption(netlink.NoENOBUFS, true)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go cleanupLoop(ctx, state, cfg.CleanupAfter)
	go statsLoop(ctx, cfg, state, counters)

	handler := func(a nfqueue.Attribute) int {
		if a.PacketID == nil { return 0 }
		id := *a.PacketID
		if a.Payload == nil { _ = nf.SetVerdict(id, nfqueue.NfAccept); return 0 }

		srcIP, isSyn := core.ParseIPv4PureTCPSYN(*a.Payload)
		if !isSyn { _ = nf.SetVerdict(id, nfqueue.NfAccept); return 0 }

		if whitelist.Contains(srcIP) {
			ev := core.LastEvent{Type: "ACCEPT-WHITELIST", IP: srcIP, PacketID: id}
			state.RememberEvent(ev); counters.IncAccepted()
			logVerbose(cfg.Verbose, "ACCEPT-WHITELIST ip=%s packet=%d", srcIP, id)
			_ = nf.SetVerdict(id, nfqueue.NfAccept); return 0
		}

		now := time.Now()
		allowed, cooldown, elapsed, remaining, _ := state.Decide(srcIP, now, id)
		if allowed {
			counters.IncAccepted()
			logVerbose(cfg.Verbose, "ACCEPT ip=%s packet=%d elapsed=%s new_cooldown=%s", srcIP, id, elapsed, cooldown)
			_ = nf.SetVerdict(id, nfqueue.NfAccept); return 0
		}

		switch cfg.Action {
		case "drop":
			counters.IncDropped()
			state.RememberEvent(core.LastEvent{Type: "DROP", IP: srcIP, PacketID: id, Cooldown: cooldown, Elapsed: elapsed, Remaining: remaining})
			logVerbose(cfg.Verbose, "DROP ip=%s packet=%d cooldown=%s elapsed=%s remaining=%s", srcIP, id, cooldown, elapsed, remaining)
			_ = nf.SetVerdict(id, nfqueue.NfDrop); return 0
		case "reject":
			counters.IncRejected()
			state.RememberEvent(core.LastEvent{Type: "REJECT-DROP", IP: srcIP, PacketID: id, Cooldown: cooldown, Elapsed: elapsed, Remaining: remaining})
			logVerbose(cfg.Verbose, "REJECT(DROP) ip=%s packet=%d cooldown=%s elapsed=%s remaining=%s", srcIP, id, cooldown, elapsed, remaining)
			_ = nf.SetVerdict(id, nfqueue.NfDrop); return 0
		case "delay":
			counters.IncDelayed()
			state.RememberEvent(core.LastEvent{Type: "DELAY", IP: srcIP, PacketID: id, Cooldown: cooldown, Elapsed: elapsed, Remaining: remaining})
			logVerbose(cfg.Verbose, "DELAY ip=%s packet=%d cooldown=%s elapsed=%s remaining=%s", srcIP, id, cooldown, elapsed, remaining)
			go func(packetID uint32, ip string, delay time.Duration) {
				time.Sleep(delay)
				cd, _ := state.MarkDelayedAccept(ip, time.Now(), packetID, delay)
				counters.IncAccepted()
				logVerbose(cfg.Verbose, "ACCEPT-AFTER-DELAY ip=%s packet=%d waited=%s new_cooldown=%s", ip, packetID, delay, cd)
				_ = nf.SetVerdict(packetID, nfqueue.NfAccept)
			}(id, srcIP, remaining)
			return 0
		}
		_ = nf.SetVerdict(id, nfqueue.NfAccept); return 0
	}

	fmt.Printf("[nfqcooldown] started queue=%d action=%s mode=%s cooldown=%s min=%s max=%s jitter=%s whitelist=%d verbose=%v seed=%d\n", cfg.QueueNum, cfg.Action, cfg.Mode, cfg.Cooldown, cfg.MinDelay, cfg.MaxDelay, cfg.Jitter, whitelist.Len(), cfg.Verbose, cfg.Seed)
	err = nf.RegisterWithErrorFunc(ctx, handler, func(e error) int { fmt.Fprintf(os.Stderr, "nfqueue error: %v\n", e); return 0 })
	if err != nil { fatalf("register failed: %v", err) }
	<-ctx.Done()
}

func cleanupLoop(ctx context.Context, state *core.State, ttl time.Duration) {
	t := time.NewTicker(60 * time.Second); defer t.Stop()
	for { select { case <-ctx.Done(): return; case <-t.C: state.Cleanup(ttl) } }
}

func statsLoop(ctx context.Context, cfg Config, state *core.State, counters *core.Counters) {
	t := time.NewTicker(cfg.StatsEvery); defer t.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-t.C:
			if cfg.Verbose { continue }
			tracked, ev := state.Snapshot()
			accepted, delayed, dropped, rejected := counters.Snapshot()
			fmt.Printf("[nfqcooldown] accepted=%d delayed=%d dropped=%d rejected=%d tracked_ips=%d action=%s mode=%s cooldown=%s min=%s max=%s jitter=%s last=%s ip=%s packet=%d actual_cooldown=%s elapsed=%s remaining=%s\n", accepted, delayed, dropped, rejected, tracked, cfg.Action, cfg.Mode, cfg.Cooldown, cfg.MinDelay, cfg.MaxDelay, cfg.Jitter, ev.Type, ev.IP, ev.PacketID, ev.Cooldown, ev.Elapsed, ev.Remaining)
		}
	}
}
