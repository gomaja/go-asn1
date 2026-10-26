// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	math "math"
	testing "testing"
)

func TestUint64ReplayEditRestore(t *testing.T) {
	// TS 36.423 V19.1.0 §9.3.5 gives both counters the full unsigned root.
	initial := s04.ERABUsageReportItem{StartTimeStamp: make([]byte, 4), EndTimeStamp: make([]byte, 4), UsageCountUL: math.MaxUint64, UsageCountDL: 1 << 63}
	eRABUsageReportItemsemanticEditRestore(t, s06.ERABUsageReportItemCodec(), initial, func(v *s04.ERABUsageReportItem) { v.UsageCountUL = math.MaxUint64 - 1 }, func(v *s04.ERABUsageReportItem) { v.UsageCountUL = math.MaxUint64 })
}
