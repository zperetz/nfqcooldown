package internal

import (
	"math"
	"testing"
	"time"
)

func TestRandomAlgorithmExtremeRangeDoesNotPanic(t *testing.T) {
	algorithm := RandomAlgorithm{
		Min: 0,
		Max: time.Duration(math.MaxInt64),
	}

	for i := 0; i < 1000; i++ {
		value := algorithm.Next()
		if value < algorithm.Min || value > algorithm.Max {
			t.Fatalf("value %s outside [%s, %s]", value, algorithm.Min, algorithm.Max)
		}
	}
}

func TestRandomAlgorithmExtremeOffsetDoesNotOverflow(t *testing.T) {
	algorithm := RandomAlgorithm{
		Min: time.Duration(math.MaxInt64 - 100),
		Max: time.Duration(math.MaxInt64),
	}

	for i := 0; i < 1000; i++ {
		value := algorithm.Next()
		if value < algorithm.Min || value > algorithm.Max {
			t.Fatalf("value %s outside [%s, %s]", value, algorithm.Min, algorithm.Max)
		}
	}
}

func TestJitterAlgorithmExtremeValuesDoNotPanic(t *testing.T) {
	algorithm := JitterAlgorithm{
		Base:   time.Duration(math.MaxInt64),
		Jitter: time.Duration(math.MaxInt64),
	}

	for i := 0; i < 1000; i++ {
		value := algorithm.Next()
		if value < 0 {
			t.Fatalf("negative duration: %s", value)
		}
	}
}

func TestJitterAlgorithmClampsToDurationRange(t *testing.T) {
	tests := []JitterAlgorithm{
		{Base: 0, Jitter: time.Duration(math.MaxInt64)},
		{Base: time.Duration(math.MaxInt64), Jitter: time.Duration(math.MaxInt64)},
		{Base: time.Second, Jitter: time.Duration(math.MaxInt64)},
	}

	for _, algorithm := range tests {
		for i := 0; i < 1000; i++ {
			value := algorithm.Next()
			if value < 0 {
				t.Fatalf("%+v produced negative duration %s", algorithm, value)
			}
		}
	}
}

func TestNewAlgorithmRejectsInvalidDurations(t *testing.T) {
	tests := []struct {
		mode                       string
		cooldown, min, max, jitter time.Duration
	}{
		{mode: "fixed", cooldown: -time.Second},
		{mode: "random", min: -time.Second, max: time.Second},
		{mode: "random", min: 2 * time.Second, max: time.Second},
		{mode: "jitter", cooldown: -time.Second, jitter: time.Second},
		{mode: "jitter", cooldown: time.Second, jitter: -time.Second},
	}

	for _, test := range tests {
		if _, err := NewAlgorithm(test.mode, test.cooldown, test.min, test.max, test.jitter); err == nil {
			t.Fatalf("expected error for %+v", test)
		}
	}
}
