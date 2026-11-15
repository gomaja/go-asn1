// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/external_profile_records_test.go; SHA-256 9299022f90865129f298633a88c8982ef34aec8d1be56db062df64a4b18c779e.
package ber

import (
	"fmt"
	"testing"
)

// X.690 (02/2021) §8.18 names the encoding CHOICE. The Q.773
// §4.1.1 form finding belongs to that received identifier exactly once.
func TestExternalProfileRecordsLocated(t *testing.T) {
	for _, choice := range []byte{0xa1, 0xa2} {
		payload := []byte{4, 1, 5}
		path := "encoding.octet-aligned"
		if choice == 0xa2 {
			payload = []byte{3, 2, 0, 5}
			path = "encoding.arbitrary"
		}
		external := append([]byte{0x28, byte(6 + len(payload)), 6, 2, 0x2a, 3, choice, byte(len(payload))}, payload...)
		t.Run(path+"/direct", func(t *testing.T) {
			var log ViolationLog
			options := TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, "External", "Synthetic-Names", "External")
			if _, _, err := DecodeExternal(external, options...); err != nil {
				t.Fatal(err)
			}
			records := log.Snapshot()
			if len(records) != 1 || records[0].Path != path || records[0].Source != "Synthetic-Names.External."+path || records[0].Offset == nil || *records[0].Offset != 6 {
				t.Fatalf("records: %+v", records)
			}
		})
		for _, mode := range []struct {
			name   string
			option DecodeOption
		}{{"adaptive", nil}, {"light", ForceGeneratedBERLightForTesting()}, {"proof", ForceGeneratedBERProofForTesting()}} {
			t.Run(path+"/"+mode.name, func(t *testing.T) {
				wire := append(append([]byte{0x30, byte(2 * len(external))}, external...), external...)
				var log ViolationLog
				options := []DecodeOption{WithTolerance(&log)}
				if mode.option != nil {
					options = append(options, mode.option)
				}
				options = TrackTCAPForm(options, "UserInformation", "DialoguePDUs", "UserInformation")
				owned, err := OwnGeneratedBERInput(wire, options)
				if err != nil {
					t.Fatal(err)
				}
				values, _, _, err := DecodeGeneratedExternalSequence(owned, options)
				if err != nil || len(values) != 2 {
					t.Fatalf("decode: %v values=%d", err, len(values))
				}
				records := log.Snapshot()
				if len(records) != 2 {
					t.Fatalf("records: %+v", records)
				}
				for i, v := range records {
					want := fmt.Sprintf("element[%d].%s", i, path)
					if v.Path != want || v.Source != "DialoguePDUs.UserInformation."+want || v.Offset == nil || *v.Offset != 8+i*len(external) {
						t.Fatalf("record: %+v", v)
					}
				}
			})
		}
	}
}

func TestExternalEncodingPathOptions(t *testing.T) {
	for _, path := range []string{"encoding.single-ASN1-type", "encoding.octet-aligned", "encoding.arbitrary"} {
		if err := ValidateDecodeOptions(ChildDecodeOptions(nil, path)...); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if err := ValidateEncodeOptions(ChildEncodeOptions(nil, path)...); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	for _, path := range []string{"", "bad.path", "encoding.unknown", "encoding.single-ASN1-type.child"} {
		if err := ValidateDecodeOptions(ChildDecodeOptions(nil, path)...); err == nil {
			t.Fatalf("decode accepted %q", path)
		}
		if err := ValidateEncodeOptions(ChildEncodeOptions(nil, path)...); err == nil {
			t.Fatalf("encode accepted %q", path)
		}
	}
}
