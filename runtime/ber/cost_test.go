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
// host load; each batch uses the same number of calls, independent of its time.
// Prefer allocationCost wherever the regression increases allocated memory.
func minimumTime(t testing.TB, f func()) time.Duration {
	t.Helper()
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	return minimumTimeSamples(f, time.Now)
}

func minimumTimeSamples(f func(), now func() time.Time) time.Duration {
	f()
	calls := 1
	for calls < 1_000_000 {
		start := now()
		for range calls {
			f()
		}
		if now().Sub(start) >= 5*time.Millisecond {
			break
		}
		calls *= 2
	}
	var minimum time.Duration
	for sample := range 5 {
		start := now()
		for range calls {
			f()
		}
		elapsed := now().Sub(start)
		if sample == 0 || elapsed < minimum {
			minimum = elapsed
		}
	}
	return max(time.Nanosecond, minimum/time.Duration(calls))
}
