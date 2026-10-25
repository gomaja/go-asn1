// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestReceiverDefaultReportCeilingAndLinearGrowth(t *testing.T) {
	var previous float64
	for _, size := range []int{128, 256, 512} {
		wire := receiverUnknownWire(t, size)
		allocations := testing.AllocsPerRun(3, func() {
			var value s20.X2APPDU
			report, err := value.UnmarshalAPER(wire, aper.WithReceiverMode())
			if err != nil || len(report.Observations) != size {
				panic("unknown observations lost")
			}
		})
		if previous != 0 && allocations > previous*3 {
			t.Fatalf("reports grew superlinearly: size=%d allocations=%v previous=%v", size, allocations, previous)
		}
		previous = allocations
	}
	valid := receiverUnknownWire(t, 1)
	for _, size := range []int{1023, 1024, 1025} {
		wire := receiverUnknownWire(t, size)
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var reused s20.X2APPDU
			if _, err := reused.UnmarshalAPER(valid, options...); err != nil {
				t.Fatal(err)
			}
			for _, value := range []*s20.X2APPDU{new(s20.X2APPDU), &reused} {
				report, err := value.UnmarshalAPER(wire, options...)
				if size <= 1024 {
					if err != nil || len(report.Observations) != size {
						t.Fatalf("size=%d report=%+v err=%v", size, report, err)
					}
				} else {
					var located *aper.DecodeError
					if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || !located.Location.HasWireLocation || located.Location.Path == "" || len(report.Observations) != 1024 || value.Choice != 0 || value.ReceivedForm().Present() {
						t.Fatalf("report overflow size=%d observations=%d value=%+v err=%v location=%+v", size, len(report.Observations), value, err, located)
					}
				}
			}
		}
	}
}
