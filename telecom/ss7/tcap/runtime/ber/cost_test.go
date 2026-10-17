// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/cost_test.go; SHA-256 6fd089459eba7b75f91880b693017d3136f4f8fc90feedae59dd25fee70b34d2.
package ber

import (
	"runtime"
	"testing"
	"time"
)

// allocationCost measures a fixed number of calls after warming f once. Tests
// using it must run serially: MemStats counts allocations for the whole process.
// One P also keeps background work from running alongside the measured calls.
func allocationCost(t testing.TB, runs int, f func()) (bytes, allocs uint64) {
	t.Helper()
	if runs < 1 {
		t.Fatal("allocation measurement needs at least one call")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	f()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	// Round up so a small amount of extra work is not hidden by averaging.
	return (after.TotalAlloc - before.TotalAlloc + uint64(runs-1)) / uint64(runs), (after.Mallocs - before.Mallocs + uint64(runs-1)) / uint64(runs)
}

// minimumTime is the fallback for scans whose repeated work does not allocate.
// Five independent batches reduce interference from scheduling and concurrent
// host load. Every measured batch must span at least 50 ms: a calibration
// pause must not let later samples fall below a coarse clock's resolution.
// Prefer allocationCost wherever the regression increases allocated memory.
func minimumTime(t testing.TB, f func()) time.Duration {
	t.Helper()
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	return minimumTimeSamples(f, time.Now)
}

func minimumTimeSamples(f func(), now func() time.Time) time.Duration {
	f()
	calls := 1
	var minimum time.Duration
	for sample := 0; sample < 5; {
		start := now()
		for range calls {
			f()
		}
		elapsed := now().Sub(start)
		if elapsed < 50*time.Millisecond {
			calls *= 2
			continue
		}
		// Batches can grow between samples, so compare per-call durations.
		perCall := elapsed / time.Duration(calls)
		if sample == 0 || perCall < minimum {
			minimum = perCall
		}
		sample++
	}
	return max(time.Nanosecond, minimum)
}
