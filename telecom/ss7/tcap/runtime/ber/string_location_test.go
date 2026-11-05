// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_location_test.go; SHA-256 d401075ab725f03f3338be96d6afdd23308c488623557120ce7536096d6a91f8.
package ber

import (
	"fmt"
	"testing"
)

func TestScannedStringLocationSkipsAncestry(t *testing.T) {
	// X.690 (02/2021) §§8.9, 8.23.4–8.23.5, 8.23.10: the
	// enclosing SEQUENCE contains two strings with one invalid octet each.
	for _, number := range []byte{12, 18, 19, 22, 26} {
		t.Run(fmt.Sprint(number), func(t *testing.T) {
			wire := []byte{0x30, 6, number, 1, 255, number, 1, 255}
			var reports ViolationLog
			options := LocateDecodedElement(wire, "Strings", []DecodeOption{WithTolerance(&reports)})
			config, err := decodeOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			origin := config.location.decodeOrigin()
			if err := ValidateBERElement(wire, options...); err != nil {
				t.Fatal(err)
			}
			if origin.ancestryVisits != 0 || origin.search != nil || len(origin.located) != 0 {
				t.Fatalf("string scan searched ancestry: visits=%d search=%v targets=%d", origin.ancestryVisits, origin.search != nil, len(origin.located))
			}
			records := reports.Snapshot()
			if len(records) != 2 {
				t.Fatalf("records=%d, want 2", len(records))
			}
			for i, record := range records {
				if record.Offset == nil || *record.Offset != 2+3*i || record.Path != fmt.Sprintf("child[%d]", i) || record.Source != "" || record.ChildIndexes != nil {
					t.Fatalf("record %d lost location or metadata: %+v", i, record)
				}
			}
		})
	}
}
