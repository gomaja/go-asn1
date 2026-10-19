// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/direct_operation_test.go; SHA-256 6777125321792e426d27c76c326a42bf80819f686fa43bef660559bd58938b51.
package ber

import (
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestBERDirectReportsHaveFreshOperation(t *testing.T) {
	for _, entry := range []string{"typed", "implicit", "preflight", "constraint"} {
		t.Run(entry, func(t *testing.T) {
			var reports ViolationLog
			option := WithTolerance(&reports)
			wire := []byte{12, 1, 255}
			for _, octet := range []byte{255, 255, 254} {
				wire[2] = octet
				var err error
				switch entry {
				case "typed":
					_, _, err = DecodeString(wire, tag.TagUTF8String, option)
				case "implicit":
					_, err = DecodeImplicitStringValue(tag.TagUTF8String, false, wire[2:], option)
				case "preflight":
					err = ValidateBERElement(wire, option)
				case "constraint":
					err = CheckDecodedValue([]DecodeOption{option}, "text", "(0)", "1")
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			got := reports.Snapshot()
			if len(got) != 3 {
				t.Fatalf("separate calls merged: %+v", got)
			}
			if entry != "constraint" && (got[0].ObservedValue != "ff" || got[1].ObservedValue != "ff" || got[2].ObservedValue != "fe") {
				t.Fatalf("observations changed: %+v", got)
			}
		})
	}
}
