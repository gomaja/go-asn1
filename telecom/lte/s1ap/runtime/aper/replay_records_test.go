// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_records_test.go; SHA-256 5af97c031e3b23b54912a88b4b222a64f283f227917df35f6b2b4035d727e963.
package aper

import "testing"

func TestWithRecordsKeepsPaddingAndReplay(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		provenance := &truncatedExtension{kept: true, recovered: recovered, input: []byte{0xa5}}
		record := FinalPadding{bits: &finalBits{truncated: provenance}}
		padding := finalPaddingOf(CompletePadding{bits: 3, count: 2})
		merged := padding.WithRecords(record)
		if merged.Padding() != padding.Padding() || merged.bits.truncated != provenance || merged.Recovered() != recovered || merged.Truncated() == recovered {
			t.Fatalf("lost padding or replay: %+v", merged.bits)
		}
		if padding.bits.truncated != nil || finalPaddingOf(CompletePadding{bits: 3, count: 2}).bits.truncated != nil {
			t.Fatal("merge modified shared padding")
		}
		if got := padding.WithRecords(FinalPadding{}); got != padding {
			t.Fatal("empty replay changed padding")
		}
		if got := padding.WithRecords(padding); got != padding {
			t.Fatal("padding was treated as replay provenance")
		}
		if got := (FinalPadding{}).WithRecords(record); got != record {
			t.Fatal("empty final padding lost replay")
		}
		if suffix := merged.Trailing(); suffix.BitLength != 0 || len(suffix.Bytes) != 0 {
			t.Fatal("replay merge created a suffix")
		}
	}
}
