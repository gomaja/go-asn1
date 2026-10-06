package per

import (
	"testing"

	"github.com/gomaja/go-asn1/runtime"
)

func TestExplicitDefaultsRecord(t *testing.T) {
	if ExplicitDefaults(0) != (FinalPadding{}) {
		t.Fatal("an empty record is not the zero value")
	}
	record := ExplicitDefaults(1<<0 | 1<<5 | 1<<63)
	for index := -1; index <= MaxExplicitDefaults; index++ {
		want := index == 0 || index == 5 || index == 63
		if got := record.ExplicitDefault(index); got != want {
			t.Errorf("ExplicitDefault(%d) = %t, want %t", index, got, want)
		}
	}
	if (FinalPadding{}).ExplicitDefault(0) {
		t.Error("the zero value records an explicit default")
	}
	// A record carries no final bits: the encoding is completed as new.
	if !record.IsZero() || record.Trailing().BitLength != 0 {
		t.Error("a record carries final bits")
	}
	bb := NewBitBuffer()
	if err := bb.WriteBits(0x5, 3); err != nil {
		t.Fatal(err)
	}
	if got, err := bb.CompleteBytesWithFinalPadding(record); err != nil || len(got) != 1 || got[0] != 0xa0 {
		t.Errorf("completed %x, %v; want a0", got, err)
	}
}

func TestWithExplicitDefaultsKeepsBoth(t *testing.T) {
	record := ExplicitDefaults(1 << 2)
	padding := finalPaddingOf(CompletePadding{bits: 3, count: 2})
	merged := padding.WithExplicitDefaults(record)
	if !merged.ExplicitDefault(2) || merged.Padding() != padding.Padding() {
		t.Fatalf("merged padding %v, record %t", merged.Padding(), merged.ExplicitDefault(2))
	}
	// The shared padding table entry is not modified.
	if padding.ExplicitDefault(2) || finalPaddingOf(CompletePadding{bits: 3, count: 2}).ExplicitDefault(2) {
		t.Fatal("merging changed the shared padding table")
	}
	if got := padding.WithExplicitDefaults(FinalPadding{}); got != padding {
		t.Error("merging no record changed the padding")
	}
	if got := (FinalPadding{}).WithExplicitDefaults(record); got != record {
		t.Error("merging into no padding did not reuse the record")
	}
	for _, test := range []struct {
		name   string
		record func() FinalPadding
		want   float64
	}{
		{"merging into no padding", func() FinalPadding { return (FinalPadding{}).WithExplicitDefaults(record) }, 0},
		{"merging no record", func() FinalPadding { return padding.WithExplicitDefaults(FinalPadding{}) }, 0},
		{"recording nothing", func() FinalPadding { return ExplicitDefaults(0) }, 0},
		{"recording the eighth", func() FinalPadding { return ExplicitDefaults(1 << 7) }, 0},
		{"recording the first eight", func() FinalPadding { return ExplicitDefaults(0xff) }, 0},
		{"recording the ninth", func() FinalPadding { return ExplicitDefaults(1 << 8) }, 1},
	} {
		if got := testing.AllocsPerRun(100, func() { explicitDefaultSink = test.record() }); got != test.want {
			t.Errorf("%s allocates %v times, want %v", test.name, got, test.want)
		}
	}
	first, second := ExplicitDefaults(0xff), ExplicitDefaults(0xff)
	if first != second || !ExplicitDefaults(1<<8|1).ExplicitDefault(8) {
		t.Error("table records differ")
	}
}

// explicitDefaultSink keeps measured records from being optimised away.
var explicitDefaultSink FinalPadding

func TestUTCTimeEqualsCanonicalForm(t *testing.T) {
	for _, test := range []struct {
		text string
		want bool
	}{
		{"990102030400Z", true},
		{"9901020304Z", true},
		{"9901020404+0100", true},
		{"990102030401Z", false},
		{"990102030400+0001", false},
	} {
		value, err := runtime.ParseUTCTime(test.text)
		if err != nil {
			t.Fatal(err)
		}
		if got := UTCTimeEquals(value, "990102030400Z"); got != test.want {
			t.Errorf("UTCTimeEquals(%s) = %t, want %t", test.text, got, test.want)
		}
	}
	if UTCTimeEquals(runtime.UTCTime{}, "990102030400Z") {
		t.Error("an unset value equals a time")
	}
}
