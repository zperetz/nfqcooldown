package internal

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

type Algorithm interface {
	Next() time.Duration
	Name() string
}

type FixedAlgorithm struct {
	Cooldown time.Duration
}

func (a FixedAlgorithm) Next() time.Duration { return a.Cooldown }
func (a FixedAlgorithm) Name() string        { return "fixed" }

type RandomAlgorithm struct {
	Min time.Duration
	Max time.Duration
}

func (a RandomAlgorithm) Next() time.Duration {
	min := a.Min
	max := a.Max

	if min < 0 {
		min = 0
	}
	if max <= min {
		return min
	}

	return randomDurationInclusive(min, max)
}

func (a RandomAlgorithm) Name() string { return "random" }

type JitterAlgorithm struct {
	Base   time.Duration
	Jitter time.Duration
}

func (a JitterAlgorithm) Next() time.Duration {
	base := a.Base
	if base < 0 {
		base = 0
	}

	if a.Jitter <= 0 {
		return base
	}

	jitter := uint64(a.Jitter)

	// 2*jitter always fits in uint64 because time.Duration is int64.
	raw := randomUint64Inclusive(jitter * 2)

	if raw <= jitter {
		negativeOffset := jitter - raw
		if negativeOffset >= uint64(base) {
			return 0
		}
		return base - time.Duration(negativeOffset)
	}

	positiveOffset := raw - jitter
	maxPositiveOffset := uint64(math.MaxInt64 - int64(base))
	if positiveOffset > maxPositiveOffset {
		return time.Duration(math.MaxInt64)
	}

	return base + time.Duration(positiveOffset)
}

func (a JitterAlgorithm) Name() string { return "jitter" }

func randomDurationInclusive(min, max time.Duration) time.Duration {
	if min < 0 {
		min = 0
	}
	if max <= min {
		return min
	}

	span := uint64(max - min)
	offset := randomUint64Inclusive(span)

	return min + time.Duration(offset)
}

func randomUint64Inclusive(max uint64) uint64 {
	if max == math.MaxUint64 {
		return rand.Uint64()
	}

	size := max + 1

	// Rejection sampling avoids modulo bias and works for every range size.
	threshold := -size % size
	for {
		value := rand.Uint64()
		if value >= threshold {
			return value % size
		}
	}
}

func NewAlgorithm(
	mode string,
	cooldown time.Duration,
	minDelay time.Duration,
	maxDelay time.Duration,
	jitter time.Duration,
) (Algorithm, error) {
	switch mode {
	case "fixed":
		if cooldown < 0 {
			return nil, fmt.Errorf("cooldown must be >= 0")
		}
		return FixedAlgorithm{Cooldown: cooldown}, nil

	case "random":
		if minDelay < 0 {
			return nil, fmt.Errorf("min-delay must be >= 0")
		}
		if maxDelay < minDelay {
			return nil, fmt.Errorf("max-delay must be >= min-delay")
		}
		return RandomAlgorithm{Min: minDelay, Max: maxDelay}, nil

	case "jitter":
		if cooldown < 0 {
			return nil, fmt.Errorf("cooldown must be >= 0")
		}
		if jitter < 0 {
			return nil, fmt.Errorf("jitter must be >= 0")
		}
		return JitterAlgorithm{Base: cooldown, Jitter: jitter}, nil

	default:
		return nil, fmt.Errorf("bad mode %q: use fixed, random or jitter", mode)
	}
}
