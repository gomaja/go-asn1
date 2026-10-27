// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/growth_timing_test.go; SHA-256 d3fbdf093d06e3582f0d272161191868c57ddf9a8157ac0d3301b44a8069d939.
package ber

import (
	goruntime "runtime"
	"testing"
	"time"
)

// growthTimes interleaves five samples of each operation and keeps each minimum.
// Every accepted batch spans at least 50 ms, including after calibration, so
// scheduler pauses and coarse clocks cannot turn a later short batch into zero.
// The total sampling budget is smaller than two default testing.Benchmark runs.
func growthTimes(t testing.TB, operations ...func()) []int64 {
	t.Helper()
	defer goruntime.GOMAXPROCS(goruntime.GOMAXPROCS(1))
	return growthTimeSamples(operations, time.Now)
}

func growthTimeSamples(operations []func(), now func() time.Time) []int64 {
	calls := make([]int, len(operations))
	minima := make([]int64, len(operations))
	for i, operation := range operations {
		operation()
		calls[i] = 1
	}
	for sample := range 5 {
		for i, operation := range operations {
			for {
				start := now()
				for range calls[i] {
					operation()
				}
				elapsed := now().Sub(start)
				if elapsed < 50*time.Millisecond {
					calls[i] *= 2
					continue
				}
				perCall := max(int64(1), elapsed.Nanoseconds()/int64(calls[i]))
				if sample == 0 || perCall < minima[i] {
					minima[i] = perCall
				}
				break
			}
		}
	}
	return minima
}

func TestGrowthTimesInterleaveMinima(t *testing.T) {
	durations := []time.Duration{50, 100, 80, 90, 60, 70, 90, 80, 70, 60}
	var elapsed time.Duration
	reads := 0
	order := []int{}
	now := func() time.Time {
		if reads%2 == 1 {
			elapsed += durations[reads/2] * time.Millisecond
		}
		reads++
		return time.Unix(0, 0).Add(elapsed)
	}
	got := growthTimeSamples([]func(){func() { order = append(order, 0) }, func() { order = append(order, 1) }}, now)
	if got[0] != int64(50*time.Millisecond) || got[1] != int64(60*time.Millisecond) || reads != 20 {
		t.Fatalf("minima=%v clock reads=%d", got, reads)
	}
	for i, index := range order {
		if index != i%2 {
			t.Fatalf("sample order=%v", order)
		}
	}
	if len(order) != 12 {
		t.Fatalf("operation calls=%d, want two warmups and ten samples", len(order))
	}
}

func TestGrowthTimesCoarseClockAfterPause(t *testing.T) {
	const tick = 16 * time.Millisecond
	var elapsed time.Duration
	reads := 0
	now := func() time.Time {
		reads++
		if reads == 2 {
			elapsed += 64 * time.Millisecond
		}
		return time.Unix(0, 0).Add(elapsed / tick * tick)
	}
	got := growthTimeSamples([]func(){func() { elapsed += time.Microsecond }, func() { elapsed += 2 * time.Microsecond }}, now)
	for i, want := range []int64{1000, 2000} {
		if got[i] < want/2 || got[i] > want*2 {
			t.Fatalf("operation %d: %d ns, want near %d", i, got[i], want)
		}
	}
}
