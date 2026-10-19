// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_reconciliation_test.go; SHA-256 d81b601c1ef7806bba5c36f8b27f7c1c8d8701129974c8acf8eb3302624fdffc.
package ber

import (
	"slices"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestUTF8RuntimeReconciliation(t *testing.T) {
	type expected struct {
		path, source string
		offset       int
		indexes      []int
	}
	cases := []struct {
		name string
		run  func(*testing.T, []DecodeOption)
		want expected
	}{
		{"target mark", func(t *testing.T, o []DecodeOption) {
			w := structureWire(t, "30030c01ff")
			o = LocateDecodedElement(w, "Module.Msg", o)
			requireBER(t, ValidateBERElement(w, o...))
			MarkPreflightTarget(o, "text", w[2:])
		}, expected{"text", "Module.Msg.text", 2, []int{0}}},
		{"location after scan", func(t *testing.T, o []DecodeOption) {
			w := structureWire(t, "3009300706022a030c01ff")
			requireBER(t, ValidateBERElement(w, o...))
			_ = LocateDecodedElement(w, "Module.Container", o)
		}, expected{"child[0].child[1]", "Module.Container", 8, []int{0, 1}}},
		{"unlocated then located scan", func(t *testing.T, o []DecodeOption) {
			w := structureWire(t, "3009300706022a030c01ff")
			requireBER(t, ValidateBERElement(w[2:], o...))
			l := LocateDecodedElement(w, "Module.Container", o)
			requireBER(t, ValidateBERElement(w, l...))
		}, expected{"child[0].child[1]", "Module.Container", 8, []int{0, 1}}},
		{"typed offset after scan", func(t *testing.T, o []DecodeOption) {
			w := structureWire(t, "0c01ff")
			requireBER(t, ValidateBERElement(w, o...))
			_, _, err := DecodeString(w, tag.TagUTF8String, o...)
			requireBER(t, err)
		}, expected{"", "", 0, nil}},
		{"deep mark survives shallow mark", func(t *testing.T, o []DecodeOption) {
			w := structureWire(t, "3009300706022a030c01ff")
			requireBER(t, ValidateBERElement(w, o...))
			o = LocateDecodedElement(w, "Module.Container", o)
			MarkPreflightTarget(o, "private", w[2:])
			child := ChildDecodeOptions(o, "private")
			child = LocateDecodedElement(w[2:], "Module.Private", child)
			MarkPreflightOpaque(child, "open", w[8:], 3)
			MarkPreflightOpaque(o, "private", w[2:], 9)
		}, expected{"private.open", "Module.Private.open", 8, []int{0, 1}}},
		{"second input cannot relabel first", func(t *testing.T, o []DecodeOption) {
			a := structureWire(t, "300706022a030c01ff")
			b := structureWire(t, "300706022a030c0161")
			la := LocateDecodedElement(a, "Module.A", o)
			requireBER(t, ValidateBERElement(a, la...))
			lb := LocateDecodedElement(b, "Module.B", o)
			MarkPreflightOpaque(lb, "other", b[6:], 3)
		}, expected{"child[1]", "Module.A", 6, []int{1}}},
		{"child scan keeps absolute ancestry", func(t *testing.T, o []DecodeOption) {
			w := structureWire(t, "3009300706022a030c01ff")
			o = LocateDecodedElement(w, "Module.Container", o)
			requireBER(t, ValidateBERElement(w[2:], o...))
		}, expected{"child[1]", "Module.Container", 8, []int{0, 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reports ViolationLog
			options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 8})})
			tc.run(t, options)
			finish(true)
			got := reports.Snapshot()
			if len(got) != 1 || got[0].Path != tc.want.path || got[0].Source != tc.want.source ||
				got[0].Offset == nil || *got[0].Offset != tc.want.offset ||
				!slices.Equal(got[0].ChildIndexes, tc.want.indexes) {
				t.Fatalf("records=%+v want=%+v", got, tc.want)
			}
		})
	}
}

func requireBER(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
