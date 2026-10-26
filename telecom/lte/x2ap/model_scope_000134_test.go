// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	errors "errors"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	runtime "runtime"
	testing "testing"
)

func TestFreshSequenceImageChecksBudgetBeforeCopy(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 65540)
	initial := s06.CriticalityDiagnostics{}
	if err := initial.SetExtension(0, payload); err != nil {
		t.Fatal(err)
	}
	wire := listByteapiMust(initial.MarshalAPER())
	var value s06.CriticalityDiagnostics
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := value.MarshalAPER(aper.WithoutReplay(), aper.WithEncodeLimits(aper.Limits{MaxAllocatedBytes: 1024}))
	runtime.ReadMemStats(&after)
	if !errors.Is(err, aper.ErrLimit) || after.TotalAlloc-before.TotalAlloc > 16<<10 {
		t.Fatalf("sequence image copied before budget check: allocated=%d err=%v", after.TotalAlloc-before.TotalAlloc, err)
	}
}
