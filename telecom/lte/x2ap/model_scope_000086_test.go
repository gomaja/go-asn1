// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s21"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestAllOperationBudgetsGrowLinearly(t *testing.T) {
	var previous [4]aper.DecodeUsage
	for _, size := range []int{64, 128, 256} {
		wire := receiverUnknownWire(t, size)
		var value s20.X2APPDU
		state := aper.ApplyDecodeOptions()
		if err := s20.X2apInternalX2APPDUUnmarshalAPERWithOptions(&value, wire, state); err != nil {
			t.Fatal(err)
		}
		var usages [4]aper.DecodeUsage
		usages[0] = state.Usage()
		encode, err := aper.EncodeBudget()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s20.X2apInternalX2APPDUMarshalAPERBudget(&value, encode, false); err != nil {
			t.Fatal(err)
		}
		usages[1] = aper.NewBudgetBuffer(encode).Usage()
		validate, err := aper.ValidationBudget()
		if err != nil {
			t.Fatal(err)
		}
		report, err := s21.X2apInternalValidateMessageBudget(&value, validate)
		if err != nil || *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		if _, err := s20.X2apInternalX2APPDUMarshalAPERBudget(&value, validate, false); err != nil {
			t.Fatal(err)
		}
		usages[2] = aper.NewBudgetBuffer(validate).Usage()
		build, err := aper.BuildBudget()
		if err != nil {
			t.Fatal(err)
		}
		report, err = s21.X2apInternalValidateMessageBudget(&value, build)
		if err != nil || *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		if _, err := s20.X2apInternalX2APPDUMarshalAPERBudget(&value, build, false); err != nil {
			t.Fatal(err)
		}
		usages[3] = aper.NewBudgetBuffer(build).Usage()
		for i, usage := range usages {
			if previous[i].Work != 0 && (usage.Work > previous[i].Work*3 || usage.AllocatedBytes > previous[i].AllocatedBytes*3) {
				t.Fatalf("size=%d operation=%d usage=%+v previous=%+v", size, i, usage, previous[i])
			}
			previous[i] = usage
		}
		// A failed decode keeps work and allocations charged to the same state.
		failed := aper.ApplyDecodeOptions(aper.WithLimits(aper.Limits{MaxReports: uint64(size - 1)}))
		var rejected s20.X2APPDU
		err = s20.X2apInternalX2APPDUUnmarshalAPERWithOptions(&rejected, wire, failed)
		_, err = aper.FinishDecode(failed, err)
		if !errors.Is(err, aper.ErrLimit) || failed.Usage().Work > usages[0].Work || failed.Usage().AllocatedBytes > usages[0].AllocatedBytes {
			t.Fatalf("failed-path budget=%+v success=%+v err=%v", failed.Usage(), usages[0], err)
		}
	}
}
