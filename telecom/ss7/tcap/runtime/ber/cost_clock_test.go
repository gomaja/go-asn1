// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/cost_clock_test.go; SHA-256 784d4c9d060190af39ff19431210ec82f8f8cdcb3c10d14ede8667a5da40930b.
package ber

import (
	"testing"
	"time"
)

func TestMinimumTimeSamplesCoarseClock(t *testing.T) {
	for _, pause := range []time.Duration{0, 64 * time.Millisecond} {
		t.Run(pause.String(), func(t *testing.T) {
			// A coarse clock can make calibration look slow because of one pause,
			// then return the same tick at both ends of a later short batch.
			const operationTime = time.Microsecond
			const tick = 16 * time.Millisecond
			origin := time.Unix(0, 0)
			var elapsed time.Duration
			reads, calls := 0, 0
			operation := func() { calls++; elapsed += operationTime }
			now := func() time.Time {
				reads++
				if reads == 2 {
					elapsed += pause
				}
				return origin.Add(elapsed / tick * tick)
			}
			got := minimumTimeSamples(operation, now)
			if got < operationTime/2 || got > 2*operationTime {
				t.Fatalf("coarse-clock measurement = %s for a %s operation (%d calls)", got, operationTime, calls)
			}
		})
	}
}
