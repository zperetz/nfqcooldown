package internal

import (
	"fmt"
	"math/rand"
	"time"
)

type Algorithm interface {
	Next() time.Duration
	Name() string
}

type FixedAlgorithm struct { Cooldown time.Duration }
func (a FixedAlgorithm) Next() time.Duration { return a.Cooldown }
func (a FixedAlgorithm) Name() string { return "fixed" }

type RandomAlgorithm struct { Min, Max time.Duration }
func (a RandomAlgorithm) Next() time.Duration {
	if a.Max <= a.Min { return a.Min }
	delta := a.Max - a.Min
	return a.Min + time.Duration(rand.Int63n(int64(delta)+1))
}
func (a RandomAlgorithm) Name() string { return "random" }

type JitterAlgorithm struct { Base, Jitter time.Duration }
func (a JitterAlgorithm) Next() time.Duration {
	if a.Jitter <= 0 { return a.Base }
	spread := time.Duration(rand.Int63n(int64(a.Jitter)*2+1)) - a.Jitter
	v := a.Base + spread
	if v < 0 { return 0 }
	return v
}
func (a JitterAlgorithm) Name() string { return "jitter" }

func NewAlgorithm(mode string, cooldown, minDelay, maxDelay, jitter time.Duration) (Algorithm, error) {
	switch mode {
	case "fixed": return FixedAlgorithm{Cooldown: cooldown}, nil
	case "random": return RandomAlgorithm{Min: minDelay, Max: maxDelay}, nil
	case "jitter": return JitterAlgorithm{Base: cooldown, Jitter: jitter}, nil
	default: return nil, fmt.Errorf("bad mode %q: use fixed, random or jitter", mode)
	}
}
