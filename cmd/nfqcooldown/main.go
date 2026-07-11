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
	QueueNum             uint
	Action               string
	Mode                 string
	Cooldown             time.Duration
	MinDelay             time.Duration
	MaxDelay             time.Duration
	Jitter               time.Duration
	Whitelist            string
	Verbose              bool
	Seed                 int64
	StatsEvery           time.Duration
	CleanupAfter         time.Duration
	CleanupEvery         time.Duration
	ForgetOnDrop         bool
	MaxDropsPerIP        int
	RejectMark           int
	Packet               string
	MaxPendingDelays     int
	DelayStrategy        string
	SleepRandomPerPacket bool
	SingleDropRepeats    int
	DelayStep            time.Duration
	DelayMax             time.Duration
	PaceInterval         time.Duration
	MaxQueuedDelay       time.Duration
	RetryAction          string
	RetryWindow          time.Duration
	RetryDelay           time.Duration
	MaxRetryAccepts      int
	BurstInterval        time.Duration
	BurstMaxDelay        time.Duration
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
	delayStrategy := flag.String("delay-strategy", "sleep", "delay strategy: sleep, pace, single or staircase")
	sleepRandomPerPacket := flag.Bool("sleep-random-per-packet", false, "for sleep+random: choose an independent random delay for each delayed packet")
	singleDropRepeats := flag.Int("single-drop-repeats", 0, "for single strategy: drop first N packets while delay is pending; 0 drops all")
	delayStepStr := flag.String("delay-step", "50ms", "for staircase strategy: increase delay by this step after each packet")
	delayMaxStr := flag.String("delay-max", "0", "for staircase strategy: maximum delay before dropping; 0 disables")
	paceIntervalStr := flag.String("pace-interval", "250ms", "interval between paced delayed packets")
	maxQueuedDelayStr := flag.String("max-queued-delay", "0", "maximum queued delay for pace strategy; 0 disables")
	retryAction := flag.String("retry-action", "off", "SYN/ACK retry action: off, accept, delay or drop")
	retryWindowStr := flag.String("retry-window", "2s", "time window for recognizing SYN/ACK retries")
	retryDelayStr := flag.String("retry-delay", "50ms", "delay used when retry-action=delay")
	maxRetryAccepts := flag.Int("max-retry-accepts", 1, "maximum rescued retries per handshake; 0 disables rescue")
	burstIntervalStr := flag.String("burst-interval", "100ms", "minimum interval between released packets in shape mode")
	burstMaxDelayStr := flag.String("burst-max-delay", "1s", "maximum queued delay in shape mode; packets beyond this limit are dropped")

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
	delayStep := mustDuration("delay-step", *delayStepStr)
	delayMax := mustDuration("delay-max", *delayMaxStr)
	paceInterval := mustDuration("pace-interval", *paceIntervalStr)
	maxQueuedDelay := mustDuration("max-queued-delay", *maxQueuedDelayStr)
	retryWindow := mustDuration("retry-window", *retryWindowStr)
	retryDelay := mustDuration("retry-delay", *retryDelayStr)
	burstInterval := mustDuration("burst-interval", *burstIntervalStr)
	burstMaxDelay := mustDuration("burst-max-delay", *burstMaxDelayStr)

	rejectMark64, err := strconv.ParseUint(*rejectMarkStr, 0, 32)
	if err != nil {
		fatalf("bad reject-mark %q: %v", *rejectMarkStr, err)
	}

	if *action != "drop" && *action != "delay" && *action != "reject" && *action != "shape" {
		fatalf("bad action %q: use drop, delay, reject or shape", *action)
	}

	if *packet != "syn" && *packet != "synack" {
		fatalf("bad packet %q: use syn or synack", *packet)
	}

	if *delayStrategy != "sleep" && *delayStrategy != "pace" && *delayStrategy != "single" && *delayStrategy != "staircase" {
		fatalf("bad delay-strategy %q: use sleep, pace, single or staircase", *delayStrategy)
	}

	if *delayStrategy == "staircase" && delayStep <= 0 {
		fatalf("bad delay-step %q: must be > 0 for staircase strategy", *delayStepStr)
	}

	if *sleepRandomPerPacket && (*delayStrategy != "sleep" || *mode != "random") {
		fatalf("--sleep-random-per-packet requires --delay-strategy sleep and --mode random")
	}

	if *singleDropRepeats < 0 {
		fatalf("bad single-drop-repeats %d: must be >= 0", *singleDropRepeats)
	}

	if *retryAction != "off" && *retryAction != "accept" && *retryAction != "delay" && *retryAction != "drop" {
		fatalf("bad retry-action %q: use off, accept, delay or drop", *retryAction)
	}
	if retryWindow <= 0 {
		fatalf("bad retry-window %q: must be > 0", *retryWindowStr)
	}
	if retryDelay < 0 {
		fatalf("bad retry-delay %q: must be >= 0", *retryDelayStr)
	}
	if *maxRetryAccepts < 0 {
		fatalf("bad max-retry-accepts %d: must be >= 0", *maxRetryAccepts)
	}
	if *action == "shape" && *packet != "syn" {
		fatalf("--action shape requires --packet syn")
	}
	if burstInterval <= 0 {
		fatalf("bad burst-interval %q: must be > 0", *burstIntervalStr)
	}
	if burstMaxDelay < 0 {
		fatalf("bad burst-max-delay %q: must be >= 0", *burstMaxDelayStr)
	}

	return Config{
		QueueNum:             *queueNum,
		Packet:               *packet,
		Action:               *action,
		Mode:                 *mode,
		Cooldown:             cooldown,
		MinDelay:             minDelay,
		MaxDelay:             maxDelay,
		Jitter:               jitter,
		Whitelist:            *whitelist,
		Verbose:              *verbose,
		RejectMark:           int(rejectMark64),
		Seed:                 *seed,
		StatsEvery:           statsEvery,
		MaxDropsPerIP:        *maxDropsPerIP,
		ForgetOnDrop:         *forgetOnDrop,
		CleanupAfter:         cleanupAfter,
		CleanupEvery:         cleanupEvery,
		MaxPendingDelays:     *maxPendingDelays,
		DelayStrategy:        *delayStrategy,
		SleepRandomPerPacket: *sleepRandomPerPacket,
		SingleDropRepeats:    *singleDropRepeats,
		DelayStep:            delayStep,
		DelayMax:             delayMax,
		PaceInterval:         paceInterval,
		MaxQueuedDelay:       maxQueuedDelay,
		RetryAction:          *retryAction,
		RetryWindow:          retryWindow,
		RetryDelay:           retryDelay,
		MaxRetryAccepts:      *maxRetryAccepts,
		BurstInterval:        burstInterval,
		BurstMaxDelay:        burstMaxDelay,
	}
}

func mustDuration(name, value string) time.Duration {
	d, err := time.ParseDuration(value)
	if err != nil {
		fatalf("bad %s %q: %v", name, value, err)
	}
	return d
}

func randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int63n(int64(max-min)+1))
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
    --action <mode>             Action: drop | delay | reject | shape (default: drop)
    --mode <algorithm>          Cooldown algorithm: fixed | random | jitter (default: fixed)
    --packet <syn|synack>       Packet type to process (default: syn)

TIMING:
    --cooldown <duration>       Base cooldown for fixed/jitter mode (default: 500ms)
    --min-delay <duration>      Random mode minimum cooldown (default: 300ms)
    --max-delay <duration>      Random mode maximum cooldown (default: 700ms)
    --jitter <duration>         Jitter around base cooldown (default: 100ms)
    --delay-step <duration>     Staircase step added after each packet (default: 50ms)
    --delay-max <duration>      Staircase maximum delay before DROP; 0 disables
    --sleep-random-per-packet   With sleep+random, randomize every delayed packet independently
    --burst-interval <duration> Minimum interval between released packets in shape mode (default: 100ms)
    --burst-max-delay <duration> Maximum queued delay in shape mode; 0 disables (default: 1s)

STATE:
    --cleanup-every <duration>  Cleanup interval (default: 30s)
    --cleanup-after <duration>  Forget inactive IPs after this duration (default: 10m)
    --forget-on-drop            Forget source IP state after DROP/REJECT
    --max-drops-per-ip <n>      Force accept after N consecutive drops; 0 disables
    --reject-mark <mark>        packet mark for reject action, e.g. 0x44; 0 disables
    --single-drop-repeats <n>   In single strategy, drop first N pending repeats; 0 drops all
    --retry-action <mode>        SYN/ACK retry action: off | accept | delay | drop
    --retry-window <duration>    Window for recognizing retries (default: 2s)
    --retry-delay <duration>     Delay for retry-action=delay (default: 50ms)
    --max-retry-accepts <n>      Maximum rescued retries per handshake (default: 1)

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

type retryKey struct {
	ClientIP   string
	ClientPort uint16
	ServerPort uint16
	Seq        uint32
	Ack        uint32
}

type retryEntry struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Rescued   int
}

type retryTracker struct {
	mu      sync.Mutex
	entries map[retryKey]retryEntry
}

func newRetryTracker() *retryTracker {
	return &retryTracker{entries: make(map[retryKey]retryEntry)}
}

func (t *retryTracker) observe(key retryKey, now time.Time, window time.Duration) (isRetry bool, rescued int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	if !ok || now.Sub(entry.FirstSeen) > window {
		t.entries[key] = retryEntry{FirstSeen: now, LastSeen: now}
		return false, 0
	}

	entry.LastSeen = now
	t.entries[key] = entry
	return true, entry.Rescued
}

func (t *retryTracker) markRescued(key retryKey) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	if !ok {
		return 0
	}
	entry.Rescued++
	t.entries[key] = entry
	return entry.Rescued
}

func (t *retryTracker) cleanup(now time.Time, ttl time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	removed := 0
	for key, entry := range t.entries {
		if now.Sub(entry.LastSeen) > ttl {
			delete(t.entries, key)
			removed++
		}
	}
	return removed
}

type burstPacerState struct {
	mu          sync.Mutex
	NextRelease time.Time
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
	retries := newRetryTracker()

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
	go retryCleanupLoop(ctx, retries, cfg.CleanupEvery, cfg.RetryWindow)
	go statsLoop(ctx, cfg, state, counters)

	type staircaseState struct {
		mu           sync.Mutex
		CurrentDelay time.Duration
		LastSeen     time.Time
	}

	var pendingDelays int64
	var nextSendAtByIP sync.Map
	var singlePendingByIP sync.Map
	var singleDropCountByIP sync.Map
	var staircaseByIP sync.Map
	var burstPacerByIP sync.Map
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
		var synAckInfo core.PacketInfo

		switch cfg.Packet {
		case "syn":
			srcIP, matched = core.ParseIPv4PureTCPSYN(*a.Payload)

		case "synack":
			info, ok := core.ParseIPv4TCPSYNACK(*a.Payload)
			if ok {
				synAckInfo = info
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

		if cfg.Packet == "synack" && cfg.RetryAction != "off" {
			key := retryKey{
				ClientIP:   synAckInfo.ClientIP,
				ClientPort: synAckInfo.ClientPort,
				ServerPort: synAckInfo.ServerPort,
				Seq:        synAckInfo.Seq,
				Ack:        synAckInfo.Ack,
			}

			isRetry, rescued := retries.observe(key, now, cfg.RetryWindow)
			if isRetry {
				canRescue := cfg.MaxRetryAccepts > 0 && rescued < cfg.MaxRetryAccepts

				switch {
				case cfg.RetryAction == "accept" && canRescue:
					rescueNumber := retries.markRescued(key)
					counters.IncAccepted()
					logVerbose(cfg.Verbose,
						"RETRY-ACCEPT ip=%s client_port=%d server_port=%d seq=%d ack=%d packet=%d rescue=%d/%d",
						srcIP, synAckInfo.ClientPort, synAckInfo.ServerPort, synAckInfo.Seq, synAckInfo.Ack,
						id, rescueNumber, cfg.MaxRetryAccepts,
					)
					_ = nf.SetVerdict(id, nfqueue.NfAccept)
					return 0

				case cfg.RetryAction == "delay" && canRescue:
					rescueNumber := retries.markRescued(key)
					atomic.AddInt64(&pendingDelays, 1)
					logVerbose(cfg.Verbose,
						"RETRY-DELAY ip=%s client_port=%d server_port=%d seq=%d ack=%d packet=%d delay=%s rescue=%d/%d",
						srcIP, synAckInfo.ClientPort, synAckInfo.ServerPort, synAckInfo.Seq, synAckInfo.Ack,
						id, cfg.RetryDelay, rescueNumber, cfg.MaxRetryAccepts,
					)
					go func(packetID uint32, delay time.Duration) {
						defer atomic.AddInt64(&pendingDelays, -1)
						time.Sleep(delay)
						counters.IncAccepted()
						_ = nf.SetVerdict(packetID, nfqueue.NfAccept)
					}(id, cfg.RetryDelay)
					return 0

				default:
					counters.IncDropped()
					logVerbose(cfg.Verbose,
						"RETRY-DROP ip=%s client_port=%d server_port=%d seq=%d ack=%d packet=%d rescued=%d/%d action=%s",
						srcIP, synAckInfo.ClientPort, synAckInfo.ServerPort, synAckInfo.Seq, synAckInfo.Ack,
						id, rescued, cfg.MaxRetryAccepts, cfg.RetryAction,
					)
					_ = nf.SetVerdict(id, nfqueue.NfDrop)
					return 0
				}
			}
		}
		if cfg.Action == "shape" {
			v, _ := burstPacerByIP.LoadOrStore(srcIP, &burstPacerState{})
			pacer := v.(*burstPacerState)

			pacer.mu.Lock()
			if pacer.NextRelease.IsZero() || !pacer.NextRelease.After(now) {
				pacer.NextRelease = now.Add(cfg.BurstInterval)
				nextRelease := pacer.NextRelease
				pacer.mu.Unlock()

				counters.IncAccepted()
				state.RememberEvent(core.LastEvent{Type: "SHAPE-ACCEPT", IP: srcIP, PacketID: id})
				logVerbose(cfg.Verbose,
					"SHAPE-ACCEPT ip=%s packet=%d next_release_in=%s interval=%s",
					srcIP, id, time.Until(nextRelease), cfg.BurstInterval,
				)
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}

			sendAt := pacer.NextRelease
			actualDelay := time.Until(sendAt)
			if actualDelay < 0 {
				actualDelay = 0
			}

			if cfg.BurstMaxDelay > 0 && actualDelay > cfg.BurstMaxDelay {
				pacer.mu.Unlock()
				counters.IncDelayOverflowDropped()
				state.RememberEvent(core.LastEvent{
					Type:      "SHAPE-OVERFLOW-DROP",
					IP:        srcIP,
					PacketID:  id,
					Remaining: actualDelay,
				})
				logVerbose(cfg.Verbose,
					"SHAPE-OVERFLOW-DROP ip=%s packet=%d queued_delay=%s max_delay=%s",
					srcIP, id, actualDelay, cfg.BurstMaxDelay,
				)
				_ = nf.SetVerdict(id, nfqueue.NfDrop)
				return 0
			}

			pacer.NextRelease = sendAt.Add(cfg.BurstInterval)
			nextRelease := pacer.NextRelease
			pacer.mu.Unlock()

			if cfg.MaxPendingDelays > 0 && atomic.LoadInt64(&pendingDelays) >= int64(cfg.MaxPendingDelays) {
				counters.IncDelayOverflowDropped()
				logVerbose(cfg.Verbose,
					"SHAPE-PENDING-DROP ip=%s packet=%d pending=%d limit=%d",
					srcIP, id, atomic.LoadInt64(&pendingDelays), cfg.MaxPendingDelays,
				)
				_ = nf.SetVerdict(id, nfqueue.NfDrop)
				return 0
			}

			counters.IncDelayed()
			atomic.AddInt64(&pendingDelays, 1)
			state.RememberEvent(core.LastEvent{
				Type:      "SHAPE-DELAY",
				IP:        srcIP,
				PacketID:  id,
				Remaining: actualDelay,
			})
			logVerbose(cfg.Verbose,
				"SHAPE-DELAY ip=%s packet=%d delay=%s next_release_in=%s interval=%s pending=%d",
				srcIP, id, actualDelay, time.Until(nextRelease), cfg.BurstInterval, atomic.LoadInt64(&pendingDelays),
			)

			go func(packetID uint32, ip string, delay time.Duration) {
				defer atomic.AddInt64(&pendingDelays, -1)
				time.Sleep(delay)
				counters.IncAccepted()
				logVerbose(cfg.Verbose,
					"SHAPE-RELEASE ip=%s packet=%d waited=%s pending=%d",
					ip, packetID, delay, atomic.LoadInt64(&pendingDelays),
				)
				_ = nf.SetVerdict(packetID, nfqueue.NfAccept)
			}(id, srcIP, actualDelay)
			return 0
		}

		allowed, cooldown, elapsed, remaining, _ := state.Decide(srcIP, now, id)
		if allowed {
			if cfg.DelayStrategy == "staircase" {
				v, _ := staircaseByIP.LoadOrStore(srcIP, &staircaseState{})
				st := v.(*staircaseState)
				st.mu.Lock()
				st.CurrentDelay = cfg.MinDelay
				st.LastSeen = now
				st.mu.Unlock()
			}

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

			if cfg.DelayStrategy == "sleep" && cfg.SleepRandomPerPacket {
				actualDelay = randomDuration(cfg.MinDelay, cfg.MaxDelay)
				logVerbose(cfg.Verbose,
					"SLEEP-RANDOM-DELAY ip=%s packet=%d delay=%s min=%s max=%s",
					srcIP, id, actualDelay, cfg.MinDelay, cfg.MaxDelay,
				)
			}

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

			if cfg.DelayStrategy == "staircase" {
				now := time.Now()
				v, _ := staircaseByIP.LoadOrStore(srcIP, &staircaseState{
					CurrentDelay: cfg.MinDelay,
					LastSeen:     now,
				})
				st := v.(*staircaseState)

				st.mu.Lock()
				if st.CurrentDelay <= 0 {
					st.CurrentDelay = cfg.MinDelay
				}
				if cfg.CleanupAfter > 0 && now.Sub(st.LastSeen) > cfg.CleanupAfter {
					st.CurrentDelay = cfg.MinDelay
				}
				actualDelay = st.CurrentDelay

				if cfg.DelayMax > 0 && actualDelay > cfg.DelayMax {
					st.LastSeen = now
					st.mu.Unlock()
					counters.IncDelayOverflowDropped()

					state.RememberEvent(core.LastEvent{
						Type:      "STAIRCASE-DROP",
						IP:        srcIP,
						PacketID:  id,
						Cooldown:  cooldown,
						Elapsed:   elapsed,
						Remaining: actualDelay,
					})

					logVerbose(cfg.Verbose,
						"STAIRCASE-DROP ip=%s packet=%d delay=%s delay_max=%s elapsed=%s",
						srcIP, id, actualDelay, cfg.DelayMax, elapsed,
					)

					_ = nf.SetVerdict(id, nfqueue.NfDrop)
					return 0
				}

				st.LastSeen = now
				st.mu.Unlock()

				logVerbose(cfg.Verbose,
					"STAIRCASE-DELAY ip=%s packet=%d delay=%s delay_step=%s delay_max=%s",
					srcIP, id, actualDelay, cfg.DelayStep, cfg.DelayMax,
				)
			}

			releaseSingle := false

			if cfg.DelayStrategy == "single" {
				if _, loaded := singlePendingByIP.LoadOrStore(srcIP, true); loaded {
					dropCount := 0
					if v, ok := singleDropCountByIP.Load(srcIP); ok {
						dropCount = v.(int)
					}

					if cfg.SingleDropRepeats > 0 && dropCount >= cfg.SingleDropRepeats {
						singleDropCountByIP.Store(srcIP, 0)

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

				if cfg.DelayStrategy == "staircase" {
					if v, ok := staircaseByIP.Load(ip); ok {
						st := v.(*staircaseState)
						st.mu.Lock()
						if st.CurrentDelay == delay {
							st.CurrentDelay += cfg.DelayStep
						}
						st.LastSeen = time.Now()
						nextDelay := st.CurrentDelay
						st.mu.Unlock()

						logVerbose(cfg.Verbose,
							"STAIRCASE-ADVANCE ip=%s packet=%d completed_delay=%s next_delay=%s delay_step=%s",
							ip, packetID, delay, nextDelay, cfg.DelayStep,
						)
					}
				}

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

func retryCleanupLoop(ctx context.Context, retries *retryTracker, every, ttl time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			retries.cleanup(now, ttl)
		}
	}
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
