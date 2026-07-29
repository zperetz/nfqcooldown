package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	Packet            string
	MaxPendingDelays  int
	BurstInterval     time.Duration
	BurstMaxDelay     time.Duration
	SkipMarkEnabled   bool
	SkipMarkValue     uint32
	SkipMarkMask      uint32
	SkipMarkSpec      string
	RejectMarkEnabled bool
	RejectMarkValue   uint32
	RejectMarkSpec    string
	SplitAt           int
	SplitMarkEnabled  bool
	SplitMarkValue    uint32
	SplitMarkSpec     string
	SplitDelay        time.Duration
	SplitSeenTTL      time.Duration
}

func parseConfig() Config {
	queueNum := flag.Uint("queue", 443, "NFQUEUE number")
	action := flag.String("action", "drop", "action: drop or shape")
	mode := flag.String("mode", "fixed", "cooldown algorithm for drop: fixed, random or jitter")
	cooldownStr := flag.String("cooldown", "500ms", "base cooldown for fixed/jitter mode")
	minDelayStr := flag.String("min-delay", "300ms", "random mode minimum cooldown")
	maxDelayStr := flag.String("max-delay", "700ms", "random mode maximum cooldown")
	jitterStr := flag.String("jitter", "100ms", "jitter spread around cooldown")
	whitelist := flag.String("whitelist", "", "comma-separated CIDR/IP whitelist")
	verbose := flag.Bool("verbose", false, "log every SYN decision instead of periodic aggregate stats")
	seed := flag.Int64("seed", 0, "random seed; 0 means current time")
	statsEveryStr := flag.String("stats-every", "30s", "aggregate stats interval")
	cleanupAfterStr := flag.String("cleanup-after", "10m", "forget inactive IPs after this duration")
	cleanupEveryStr := flag.String("cleanup-every", "30s", "cleanup interval")
	forgetOnDrop := flag.Bool("forget-on-drop", false, "forget source IP state after DROP")
	maxDropsPerIP := flag.Int("max-drops-per-ip", 0, "force accept after N consecutive drops from same IP; 0 disables")
	packet := flag.String("packet", "syn", "packet type to process: syn or synack")
	maxPendingDelays := flag.Int("max-pending-delays", 0, "maximum pending shaped packets globally; 0 disables")
	burstIntervalStr := flag.String("burst-interval", "100ms", "minimum interval between released SYN packets per IP in shape mode")
	burstMaxDelayStr := flag.String("burst-max-delay", "1s", "maximum permitted delay in shape mode; packets beyond this limit are dropped")
	skipMarkStr := flag.String("skip-mark", "", "accept packets matching mark or mark/mask, for example 0x400 or 0x400/0x400")
	rejectMarkStr := flag.String("reject-mark", "", "instead of dropping a packet, accept it with this mark set; nftables can reject it afterwards")
	splitAt := flag.Int("split-at", 1, "payload byte offset for split action")
	splitMarkStr := flag.String("split-mark", "0x1000", "packet mark set on split segments; nftables should persist it to ct mark")
	splitDelayStr := flag.String("split-delay", "1ms", "delay before sending the second split segment")
	splitSeenTTLStr := flag.String("split-seen-ttl", "1m", "remember split TCP segments for this duration and pass retransmissions unchanged")

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
	burstInterval := mustDuration("burst-interval", *burstIntervalStr)
	burstMaxDelay := mustDuration("burst-max-delay", *burstMaxDelayStr)
	skipMarkEnabled, skipMarkValue, skipMarkMask := mustMarkSpec("skip-mark", *skipMarkStr)
	rejectMarkEnabled, rejectMarkValue := mustMark("reject-mark", *rejectMarkStr)
	splitMarkEnabled, splitMarkValue := mustMark("split-mark", *splitMarkStr)
	splitDelay := mustDuration("split-delay", *splitDelayStr)
	splitSeenTTL := mustDuration("split-seen-ttl", *splitSeenTTLStr)

	if *action != "drop" && *action != "shape" && *action != "split" {
		fatalf("bad action %q: use drop, shape or split", *action)
	}
	if *mode != "fixed" && *mode != "random" && *mode != "jitter" {
		fatalf("bad mode %q: use fixed, random or jitter", *mode)
	}
	if *packet != "syn" && *packet != "synack" && *packet != "payload" {
		fatalf("bad packet %q: use syn, synack or payload", *packet)
	}
	if *action == "shape" && *packet != "syn" {
		fatalf("--action shape requires --packet syn")
	}
	if *action == "split" && *packet != "payload" {
		fatalf("--action split requires --packet payload")
	}
	if *packet == "payload" && *action != "split" {
		fatalf("--packet payload currently requires --action split")
	}
	if *action == "split" && !splitMarkEnabled {
		fatalf("--action split requires a non-zero --split-mark")
	}
	if *splitAt <= 0 {
		fatalf("bad split-at %d: must be > 0", *splitAt)
	}
	if splitDelay < 0 {
		fatalf("bad split-delay %q: must be >= 0", *splitDelayStr)
	}
	if splitSeenTTL <= 0 {
		fatalf("bad split-seen-ttl %q: must be > 0", *splitSeenTTLStr)
	}
	if *maxDropsPerIP < 0 {
		fatalf("bad max-drops-per-ip %d: must be >= 0", *maxDropsPerIP)
	}
	if *maxPendingDelays < 0 {
		fatalf("bad max-pending-delays %d: must be >= 0", *maxPendingDelays)
	}
	if burstInterval <= 0 {
		fatalf("bad burst-interval %q: must be > 0", *burstIntervalStr)
	}
	if burstMaxDelay < 0 {
		fatalf("bad burst-max-delay %q: must be >= 0", *burstMaxDelayStr)
	}

	return Config{
		QueueNum:          *queueNum,
		Action:            *action,
		Mode:              *mode,
		Cooldown:          cooldown,
		MinDelay:          minDelay,
		MaxDelay:          maxDelay,
		Jitter:            jitter,
		Whitelist:         *whitelist,
		Verbose:           *verbose,
		Seed:              *seed,
		StatsEvery:        statsEvery,
		CleanupAfter:      cleanupAfter,
		CleanupEvery:      cleanupEvery,
		ForgetOnDrop:      *forgetOnDrop,
		MaxDropsPerIP:     *maxDropsPerIP,
		Packet:            *packet,
		MaxPendingDelays:  *maxPendingDelays,
		BurstInterval:     burstInterval,
		BurstMaxDelay:     burstMaxDelay,
		SkipMarkEnabled:   skipMarkEnabled,
		SkipMarkValue:     skipMarkValue,
		SkipMarkMask:      skipMarkMask,
		SkipMarkSpec:      strings.TrimSpace(*skipMarkStr),
		RejectMarkEnabled: rejectMarkEnabled,
		RejectMarkValue:   rejectMarkValue,
		RejectMarkSpec:    strings.TrimSpace(*rejectMarkStr),
		SplitAt:           *splitAt,
		SplitMarkEnabled:  splitMarkEnabled,
		SplitMarkValue:    splitMarkValue,
		SplitMarkSpec:     strings.TrimSpace(*splitMarkStr),
		SplitDelay:        splitDelay,
		SplitSeenTTL:      splitSeenTTL,
	}
}

func mustDuration(name, value string) time.Duration {
	d, err := time.ParseDuration(value)
	if err != nil {
		fatalf("bad %s %q: %v", name, value, err)
	}
	return d
}

func mustMarkSpec(name, value string) (bool, uint32, uint32) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, 0, 0
	}

	parts := strings.Split(value, "/")
	if len(parts) > 2 || parts[0] == "" {
		fatalf("bad %s %q: use mark or mark/mask", name, value)
	}

	mark, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		fatalf("bad %s %q: invalid mark", name, value)
	}

	mask := uint64(0xffffffff)
	if len(parts) == 2 {
		if parts[1] == "" {
			fatalf("bad %s %q: empty mask", name, value)
		}
		mask, err = strconv.ParseUint(parts[1], 0, 32)
		if err != nil {
			fatalf("bad %s %q: invalid mask", name, value)
		}
		if mask == 0 {
			fatalf("bad %s %q: mask must not be zero", name, value)
		}
	}

	return true, uint32(mark), uint32(mask)
}

func mustMark(name, value string) (bool, uint32) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, 0
	}

	mark, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		fatalf("bad %s %q: invalid mark", name, value)
	}
	if mark == 0 {
		fatalf("bad %s %q: mark must not be zero", name, value)
	}

	return true, uint32(mark)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func logVerbose(enabled bool, format string, args ...any) {
	if enabled {
		fmt.Printf("[nfqcooldown] "+format+"\n", args...)
	}
}

func formatSkipMark(cfg Config) string {
	if !cfg.SkipMarkEnabled {
		return "disabled"
	}
	return fmt.Sprintf("0x%x/0x%x", cfg.SkipMarkValue, cfg.SkipMarkMask)
}

func formatRejectMark(cfg Config) string {
	if !cfg.RejectMarkEnabled {
		return "disabled"
	}
	return fmt.Sprintf("0x%x", cfg.RejectMarkValue)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `nfqcooldown %s

NFQUEUE-based TCP SYN rate limiter and TCP payload splitter.

USAGE:
    nfqcooldown [OPTIONS]

CORE OPTIONS:
    --queue <n>                   NFQUEUE number (default: 443)
    --action <drop|shape|split>   Packet action (default: drop)
    --packet <syn|synack|payload> Packet type; payload is used by split
    --mode <fixed|random|jitter>  Cooldown algorithm used by drop (default: fixed)

DROP MODE:
    --cooldown <duration>         Base cooldown for fixed/jitter mode (default: 500ms)
    --min-delay <duration>        Random mode minimum cooldown (default: 300ms)
    --max-delay <duration>        Random mode maximum cooldown (default: 700ms)
    --jitter <duration>           Jitter around cooldown (default: 100ms)
    --max-drops-per-ip <n>        Force accept after N consecutive drops; 0 disables
    --forget-on-drop              Forget source IP state after DROP

SPLIT MODE:
    --split-at <n>                Split payload before byte n (default: 1)
    --split-mark <mark>           Packet mark for nftables persistence (default: 0x1000)
    --split-delay <duration>      Delay before second segment (default: 1ms)
    --split-seen-ttl <duration>   Remember split segments and pass retransmits unchanged (default: 1m)

SHAPE MODE:
    --burst-interval <duration>   Minimum interval between released SYN packets per IP
    --burst-max-delay <duration>  Maximum permitted delay; larger delays are dropped
    --max-pending-delays <n>      Global pending shaped-packet limit; 0 disables

STATE:
    --cleanup-every <duration>    Cleanup interval (default: 30s)
    --cleanup-after <duration>    Forget inactive IPs after this duration (default: 10m)

FILTERING:
    --whitelist <ip,cidr,...>     Comma-separated IP/CIDR whitelist
    --skip-mark <mark[/mask]>     Accept matching packet marks before shaping/drop
    --reject-mark <mark>          Replace DROP with ACCEPT carrying old_mark|mark

LOGGING:
    --stats-every <duration>      Aggregate stats interval (default: 30s)
    --verbose                     Log every packet decision

OTHER:
    --seed <n>                    Random seed; 0 means current time
    --help                        Show this help
    --version                     Show program version

EXAMPLES:
    nfqcooldown --queue 443 --packet syn --action shape \
      --burst-interval 800ms --burst-max-delay 50ms

    nfqcooldown --queue 443 --packet syn --action drop \
      --mode jitter --cooldown 990ms --jitter 100ms \
      --max-drops-per-ip 7

    nfqcooldown --queue 444 --packet synack --action drop \
      --mode fixed --cooldown 1s --verbose

    nfqcooldown --queue 443 --packet syn --action shape \
      --skip-mark 0x400/0x400 \
      --reject-mark 0x800 \
      --burst-interval 1090ms --burst-max-delay 10ms

`, Version)
}

type shapeFlowKey struct {
	ClientIP   string
	ClientPort uint16
	ServerPort uint16
	Seq        uint32
}

type burstPacerState struct {
	mu          sync.Mutex
	LastRelease time.Time
	LastSeen    time.Time
	Pending     bool
}

type splitSegmentKey struct {
	SrcIP      [4]byte
	DstIP      [4]byte
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	PayloadLen int
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

	nfqConfig := nfqueue.Config{
		NfQueue:      uint16(cfg.QueueNum),
		MaxPacketLen: 0xffff,
		MaxQueueLen:  8192,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}
	nf, err := nfqueue.Open(&nfqConfig)
	if err != nil {
		fatalf("could not open nfqueue: %v", err)
	}
	defer nf.Close()
	_ = nf.SetOption(netlink.NoENOBUFS, true)

	var rawSender *core.RawIPv4Sender
	if cfg.Action == "split" {
		rawSender, err = core.NewRawIPv4Sender()
		if err != nil {
			fatalf("could not open raw IPv4 sender: %v", err)
		}
		defer rawSender.Close()
	}

	dropOrReject := func(id uint32, packetMark *uint32) {
		if !cfg.RejectMarkEnabled {
			_ = nf.SetVerdict(id, nfqueue.NfDrop)
			return
		}

		mark := cfg.RejectMarkValue
		if packetMark != nil {
			mark |= *packetMark
		}
		_ = nf.SetVerdictWithMark(id, nfqueue.NfAccept, int(mark))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var pendingDelays int64
	var burstPacerByIP sync.Map
	var shapePendingFlows sync.Map
	var splitSeen sync.Map

	go cleanupLoop(ctx, state, cfg.CleanupEvery, cfg.CleanupAfter)
	go shapeCleanupLoop(ctx, &burstPacerByIP, cfg.CleanupEvery, cfg.CleanupAfter)
	go splitSeenCleanupLoop(ctx, &splitSeen, cfg.CleanupEvery, cfg.SplitSeenTTL)
	go statsLoop(ctx, cfg, state, counters)

	handler := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID

		if a.Payload == nil {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		if cfg.Packet == "payload" {
			info, ok := core.ParseIPv4TCPPayload(*a.Payload)
			if !ok {
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}
			if cfg.SkipMarkEnabled && a.Mark != nil &&
				(*a.Mark&cfg.SkipMarkMask) == (cfg.SkipMarkValue&cfg.SkipMarkMask) {
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}

			var srcIPKey, dstIPKey [4]byte
			copy(srcIPKey[:], info.SrcIP.To4())
			copy(dstIPKey[:], info.DstIP.To4())

			splitKey := splitSegmentKey{
				SrcIP:      srcIPKey,
				DstIP:      dstIPKey,
				SrcPort:    info.SrcPort,
				DstPort:    info.DstPort,
				Seq:        info.Seq,
				PayloadLen: info.PayloadLen,
			}
			if _, alreadySplit := splitSeen.LoadOrStore(splitKey, time.Now()); alreadySplit {
				logVerbose(cfg.Verbose, "SPLIT-RETRANSMIT-PASS src=%s:%d dst=%s:%d seq=%d payload=%d packet=%d", info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, info.Seq, info.PayloadLen, id)
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}

			first, second, err := core.SplitIPv4TCPPacket(*a.Payload, info, cfg.SplitAt)
			if err != nil {
				splitSeen.Delete(splitKey)
				logVerbose(cfg.Verbose, "SPLIT-SKIP src=%s:%d dst=%s:%d seq=%d payload=%d packet=%d reason=%q", info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, info.Seq, info.PayloadLen, id, err)
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}

			secondKey := splitSegmentKey{
				SrcIP:      srcIPKey,
				DstIP:      dstIPKey,
				SrcPort:    info.SrcPort,
				DstPort:    info.DstPort,
				Seq:        info.Seq + uint32(cfg.SplitAt),
				PayloadLen: info.PayloadLen - cfg.SplitAt,
			}
			splitSeen.Store(secondKey, time.Now())

			mark := cfg.SplitMarkValue
			if a.Mark != nil {
				mark |= *a.Mark
			}
			if err := nf.SetVerdictModPacketWithConnMark(id, nfqueue.NfAccept, int(mark), first); err != nil {
				splitSeen.Delete(splitKey)
				splitSeen.Delete(secondKey)
				fmt.Fprintf(os.Stderr, "[nfqcooldown] split verdict failed packet=%d: %v\n", id, err)
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}
			go func() {
				if cfg.SplitDelay > 0 {
					time.Sleep(cfg.SplitDelay)
				}
				if err := rawSender.Send(second, mark); err != nil {
					splitSeen.Delete(secondKey)
					fmt.Fprintf(os.Stderr, "[nfqcooldown] split raw send failed src=%s:%d dst=%s:%d seq=%d len=%d: %v\n", info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, info.Seq+uint32(cfg.SplitAt), info.PayloadLen-cfg.SplitAt, err)
					return
				}
				logVerbose(cfg.Verbose, "SPLIT-RAW-SENT src=%s:%d dst=%s:%d seq=%d payload=%d mark=0x%x", info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, info.Seq+uint32(cfg.SplitAt), info.PayloadLen-cfg.SplitAt, mark)
			}()
			logVerbose(cfg.Verbose, "SPLIT src=%s:%d dst=%s:%d seq=%d payload=%d parts=%d+%d packet=%d split_mark=0x%x", info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, info.Seq, info.PayloadLen, cfg.SplitAt, info.PayloadLen-cfg.SplitAt, id, cfg.SplitMarkValue)
			return 0
		}

		var srcIP string
		var matched bool
		var synInfo core.PacketInfo

		switch cfg.Packet {
		case "syn":
			info, ok := core.ParseIPv4PureTCPSYNInfo(*a.Payload)
			if ok {
				synInfo = info
				srcIP = info.ClientIP
				matched = true
			}

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

		if cfg.SkipMarkEnabled && a.Mark != nil &&
			(*a.Mark&cfg.SkipMarkMask) == (cfg.SkipMarkValue&cfg.SkipMarkMask) {
			state.RememberEvent(core.LastEvent{
				Type:     "ACCEPT-SKIP-MARK",
				IP:       srcIP,
				PacketID: id,
			})
			counters.IncAccepted()
			logVerbose(
				cfg.Verbose,
				"ACCEPT-SKIP-MARK ip=%s packet=%d packet_mark=0x%x skip_mark=0x%x/0x%x",
				srcIP,
				id,
				*a.Mark,
				cfg.SkipMarkValue,
				cfg.SkipMarkMask,
			)
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		if whitelist.Contains(srcIP) {
			state.RememberEvent(core.LastEvent{
				Type:     "ACCEPT-WHITELIST",
				IP:       srcIP,
				PacketID: id,
			})
			counters.IncAccepted()
			logVerbose(cfg.Verbose, "ACCEPT-WHITELIST ip=%s packet=%d", srcIP, id)
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		now := time.Now()

		if cfg.Action == "shape" {
			flowKey := shapeFlowKey{
				ClientIP:   synInfo.ClientIP,
				ClientPort: synInfo.ClientPort,
				ServerPort: synInfo.ServerPort,
				Seq:        synInfo.Seq,
			}

			if _, pending := shapePendingFlows.Load(flowKey); pending {
				counters.IncDelayOverflowDropped()
				state.RememberEvent(core.LastEvent{
					Type:     "SHAPE-FLOW-PENDING-DROP",
					IP:       srcIP,
					PacketID: id,
				})
				logVerbose(
					cfg.Verbose,
					"SHAPE-FLOW-PENDING-DROP ip=%s client_port=%d server_port=%d seq=%d packet=%d",
					srcIP,
					synInfo.ClientPort,
					synInfo.ServerPort,
					synInfo.Seq,
					id,
				)
				dropOrReject(id, a.Mark)
				return 0
			}

			v, _ := burstPacerByIP.LoadOrStore(srcIP, &burstPacerState{})
			pacer := v.(*burstPacerState)

			pacer.mu.Lock()
			pacer.LastSeen = now

			if pacer.LastRelease.IsZero() || now.Sub(pacer.LastRelease) >= cfg.BurstInterval {
				pacer.LastRelease = now
				pacer.LastSeen = now
				pacer.Pending = false
				pacer.mu.Unlock()

				counters.IncAccepted()
				state.RememberEvent(core.LastEvent{
					Type:     "SHAPE-ACCEPT",
					IP:       srcIP,
					PacketID: id,
				})
				logVerbose(
					cfg.Verbose,
					"SHAPE-ACCEPT ip=%s client_port=%d server_port=%d seq=%d packet=%d next_release_in=%s interval=%s",
					srcIP,
					synInfo.ClientPort,
					synInfo.ServerPort,
					synInfo.Seq,
					id,
					cfg.BurstInterval,
					cfg.BurstInterval,
				)
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}

			actualDelay := cfg.BurstInterval - now.Sub(pacer.LastRelease)
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
				logVerbose(
					cfg.Verbose,
					"SHAPE-OVERFLOW-DROP ip=%s client_port=%d server_port=%d seq=%d packet=%d delay=%s max_delay=%s",
					srcIP,
					synInfo.ClientPort,
					synInfo.ServerPort,
					synInfo.Seq,
					id,
					actualDelay,
					cfg.BurstMaxDelay,
				)
				dropOrReject(id, a.Mark)
				return 0
			}

			if pacer.Pending {
				pacer.mu.Unlock()

				counters.IncDelayOverflowDropped()
				state.RememberEvent(core.LastEvent{
					Type:      "SHAPE-IP-PENDING-DROP",
					IP:        srcIP,
					PacketID:  id,
					Remaining: actualDelay,
				})
				logVerbose(
					cfg.Verbose,
					"SHAPE-IP-PENDING-DROP ip=%s client_port=%d server_port=%d seq=%d packet=%d delay=%s",
					srcIP,
					synInfo.ClientPort,
					synInfo.ServerPort,
					synInfo.Seq,
					id,
					actualDelay,
				)
				dropOrReject(id, a.Mark)
				return 0
			}

			if cfg.MaxPendingDelays > 0 &&
				atomic.LoadInt64(&pendingDelays) >= int64(cfg.MaxPendingDelays) {
				pacer.mu.Unlock()

				counters.IncDelayOverflowDropped()
				logVerbose(
					cfg.Verbose,
					"SHAPE-PENDING-DROP ip=%s client_port=%d server_port=%d seq=%d packet=%d pending=%d limit=%d",
					srcIP,
					synInfo.ClientPort,
					synInfo.ServerPort,
					synInfo.Seq,
					id,
					atomic.LoadInt64(&pendingDelays),
					cfg.MaxPendingDelays,
				)
				dropOrReject(id, a.Mark)
				return 0
			}

			pacer.Pending = true
			pacer.mu.Unlock()
			shapePendingFlows.Store(flowKey, true)

			counters.IncDelayed()
			atomic.AddInt64(&pendingDelays, 1)
			state.RememberEvent(core.LastEvent{
				Type:      "SHAPE-DELAY",
				IP:        srcIP,
				PacketID:  id,
				Remaining: actualDelay,
			})
			logVerbose(
				cfg.Verbose,
				"SHAPE-DELAY ip=%s client_port=%d server_port=%d seq=%d packet=%d delay=%s interval=%s pending=%d",
				srcIP,
				synInfo.ClientPort,
				synInfo.ServerPort,
				synInfo.Seq,
				id,
				actualDelay,
				cfg.BurstInterval,
				atomic.LoadInt64(&pendingDelays),
			)

			go func(
				packetID uint32,
				ip string,
				key shapeFlowKey,
				delay time.Duration,
				pacer *burstPacerState,
			) {
				defer atomic.AddInt64(&pendingDelays, -1)

				time.Sleep(delay)

				pacer.mu.Lock()
				releasedAt := time.Now()
				pacer.LastRelease = releasedAt
				pacer.LastSeen = releasedAt
				pacer.Pending = false
				pacer.mu.Unlock()
				shapePendingFlows.Delete(key)

				counters.IncAccepted()
				logVerbose(
					cfg.Verbose,
					"SHAPE-RELEASE ip=%s client_port=%d server_port=%d seq=%d packet=%d waited=%s pending=%d",
					ip,
					key.ClientPort,
					key.ServerPort,
					key.Seq,
					packetID,
					delay,
					atomic.LoadInt64(&pendingDelays),
				)
				_ = nf.SetVerdict(packetID, nfqueue.NfAccept)
			}(id, srcIP, flowKey, actualDelay, pacer)

			return 0
		}

		allowed, cooldown, elapsed, remaining, _ := state.Decide(srcIP, now, id)
		if allowed {
			counters.IncAccepted()
			logVerbose(
				cfg.Verbose,
				"ACCEPT ip=%s packet=%d elapsed=%s new_cooldown=%s",
				srcIP,
				id,
				elapsed,
				cooldown,
			)
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		dropCount := state.IncDrop(srcIP)
		if cfg.MaxDropsPerIP > 0 && dropCount > cfg.MaxDropsPerIP {
			cd, _ := state.ForceAccept(srcIP, time.Now(), id)
			counters.IncAccepted()
			logVerbose(
				cfg.Verbose,
				"FORCE-ACCEPT ip=%s packet=%d drops=%d new_cooldown=%s",
				srcIP,
				id,
				dropCount,
				cd,
			)
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		counters.IncDropped()
		state.RememberEvent(core.LastEvent{
			Type:      "DROP",
			IP:        srcIP,
			PacketID:  id,
			Cooldown:  cooldown,
			Elapsed:   elapsed,
			Remaining: remaining,
		})
		if cfg.ForgetOnDrop {
			state.Forget(srcIP)
		}
		logVerbose(
			cfg.Verbose,
			"DROP ip=%s packet=%d cooldown=%s elapsed=%s remaining=%s",
			srcIP,
			id,
			cooldown,
			elapsed,
			remaining,
		)
		dropOrReject(id, a.Mark)
		return 0
	}

	printStartupConfig(cfg, whitelist.Len())

	err = nf.RegisterWithErrorFunc(ctx, handler, func(e error) int {
		fmt.Fprintf(os.Stderr, "nfqueue error: %v\n", e)
		return 0
	})
	if err != nil {
		fatalf("register failed: %v", err)
	}

	<-ctx.Done()
}

func printStartupConfig(cfg Config, whitelistCount int) {
	switch cfg.Action {
	case "split":
		fmt.Printf(
			"[nfqcooldown] started queue=%d action=split packet=payload split_at=%d split_delay=%s split_mark=0x%x split_seen_ttl=%s skip_mark=%s verbose=%v\n",
			cfg.QueueNum, cfg.SplitAt, cfg.SplitDelay, cfg.SplitMarkValue, cfg.SplitSeenTTL, formatSkipMark(cfg), cfg.Verbose,
		)

	case "shape":
		fmt.Printf(
			"[nfqcooldown] started queue=%d action=shape packet=%s burst_interval=%s burst_max_delay=%s max_pending_delays=%d cleanup_every=%s cleanup_after=%s whitelist=%d skip_mark=%s reject_mark=%s verbose=%v seed=%d\n",
			cfg.QueueNum,
			cfg.Packet,
			cfg.BurstInterval,
			cfg.BurstMaxDelay,
			cfg.MaxPendingDelays,
			cfg.CleanupEvery,
			cfg.CleanupAfter,
			whitelistCount,
			formatSkipMark(cfg),
			formatRejectMark(cfg),
			cfg.Verbose,
			cfg.Seed,
		)

	case "drop":
		switch cfg.Mode {
		case "random":
			fmt.Printf(
				"[nfqcooldown] started queue=%d action=drop packet=%s mode=random min=%s max=%s max_drops_per_ip=%d forget_on_drop=%v cleanup_every=%s cleanup_after=%s whitelist=%d skip_mark=%s reject_mark=%s verbose=%v seed=%d\n",
				cfg.QueueNum,
				cfg.Packet,
				cfg.MinDelay,
				cfg.MaxDelay,
				cfg.MaxDropsPerIP,
				cfg.ForgetOnDrop,
				cfg.CleanupEvery,
				cfg.CleanupAfter,
				whitelistCount,
				formatSkipMark(cfg),
				formatRejectMark(cfg),
				cfg.Verbose,
				cfg.Seed,
			)

		case "jitter":
			fmt.Printf(
				"[nfqcooldown] started queue=%d action=drop packet=%s mode=jitter cooldown=%s jitter=%s max_drops_per_ip=%d forget_on_drop=%v cleanup_every=%s cleanup_after=%s whitelist=%d skip_mark=%s reject_mark=%s verbose=%v seed=%d\n",
				cfg.QueueNum,
				cfg.Packet,
				cfg.Cooldown,
				cfg.Jitter,
				cfg.MaxDropsPerIP,
				cfg.ForgetOnDrop,
				cfg.CleanupEvery,
				cfg.CleanupAfter,
				whitelistCount,
				formatSkipMark(cfg),
				formatRejectMark(cfg),
				cfg.Verbose,
				cfg.Seed,
			)

		default:
			fmt.Printf(
				"[nfqcooldown] started queue=%d action=drop packet=%s mode=fixed cooldown=%s max_drops_per_ip=%d forget_on_drop=%v cleanup_every=%s cleanup_after=%s whitelist=%d skip_mark=%s reject_mark=%s verbose=%v seed=%d\n",
				cfg.QueueNum,
				cfg.Packet,
				cfg.Cooldown,
				cfg.MaxDropsPerIP,
				cfg.ForgetOnDrop,
				cfg.CleanupEvery,
				cfg.CleanupAfter,
				whitelistCount,
				formatSkipMark(cfg),
				formatRejectMark(cfg),
				cfg.Verbose,
				cfg.Seed,
			)
		}
	}
}

func printStats(
	cfg Config,
	tracked int,
	accepted uint64,
	delayed uint64,
	dropped uint64,
	ev core.LastEvent,
) {
	switch cfg.Action {
	case "shape":
		fmt.Printf(
			"[nfqcooldown] accepted=%d delayed=%d dropped=%d tracked_ips=%d action=shape packet=%s burst_interval=%s burst_max_delay=%s max_pending_delays=%d last=%s ip=%s packet_id=%d remaining=%s\n",
			accepted,
			delayed,
			dropped,
			tracked,
			cfg.Packet,
			cfg.BurstInterval,
			cfg.BurstMaxDelay,
			cfg.MaxPendingDelays,
			ev.Type,
			ev.IP,
			ev.PacketID,
			ev.Remaining,
		)

	case "drop":
		switch cfg.Mode {
		case "random":
			fmt.Printf(
				"[nfqcooldown] accepted=%d dropped=%d tracked_ips=%d action=drop packet=%s mode=random min=%s max=%s max_drops_per_ip=%d last=%s ip=%s packet_id=%d actual_cooldown=%s elapsed=%s remaining=%s\n",
				accepted,
				dropped,
				tracked,
				cfg.Packet,
				cfg.MinDelay,
				cfg.MaxDelay,
				cfg.MaxDropsPerIP,
				ev.Type,
				ev.IP,
				ev.PacketID,
				ev.Cooldown,
				ev.Elapsed,
				ev.Remaining,
			)

		case "jitter":
			fmt.Printf(
				"[nfqcooldown] accepted=%d dropped=%d tracked_ips=%d action=drop packet=%s mode=jitter cooldown=%s jitter=%s max_drops_per_ip=%d last=%s ip=%s packet_id=%d actual_cooldown=%s elapsed=%s remaining=%s\n",
				accepted,
				dropped,
				tracked,
				cfg.Packet,
				cfg.Cooldown,
				cfg.Jitter,
				cfg.MaxDropsPerIP,
				ev.Type,
				ev.IP,
				ev.PacketID,
				ev.Cooldown,
				ev.Elapsed,
				ev.Remaining,
			)

		default:
			fmt.Printf(
				"[nfqcooldown] accepted=%d dropped=%d tracked_ips=%d action=drop packet=%s mode=fixed cooldown=%s max_drops_per_ip=%d last=%s ip=%s packet_id=%d actual_cooldown=%s elapsed=%s remaining=%s\n",
				accepted,
				dropped,
				tracked,
				cfg.Packet,
				cfg.Cooldown,
				cfg.MaxDropsPerIP,
				ev.Type,
				ev.IP,
				ev.PacketID,
				ev.Cooldown,
				ev.Elapsed,
				ev.Remaining,
			)
		}
	}
}

func splitSeenCleanupLoop(
	ctx context.Context,
	splitSeen *sync.Map,
	every time.Duration,
	ttl time.Duration,
) {
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case now := <-t.C:
			removed := 0
			splitSeen.Range(func(key, value any) bool {
				seenAt, ok := value.(time.Time)
				if !ok || now.Sub(seenAt) > ttl {
					splitSeen.Delete(key)
					removed++
				}
				return true
			})

			if removed > 0 {
				fmt.Printf("[nfqcooldown] split cleanup removed=%d ttl=%s\n", removed, ttl)
			}
		}
	}
}

func shapeCleanupLoop(
	ctx context.Context,
	burstPacerByIP *sync.Map,
	every time.Duration,
	ttl time.Duration,
) {
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case now := <-t.C:
			removed := 0

			burstPacerByIP.Range(func(key, value any) bool {
				pacer := value.(*burstPacerState)

				pacer.mu.Lock()
				stale := !pacer.Pending &&
					!pacer.LastSeen.IsZero() &&
					now.Sub(pacer.LastSeen) > ttl
				pacer.mu.Unlock()

				if stale {
					burstPacerByIP.Delete(key)
					removed++
				}

				return true
			})

			if removed > 0 {
				fmt.Printf(
					"[nfqcooldown] shape cleanup removed=%d ttl=%s\n",
					removed,
					ttl,
				)
			}
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
			accepted, delayed, dropped, _ := counters.Snapshot()

			printStats(cfg, tracked, accepted, delayed, dropped, ev)
		}
	}
}
