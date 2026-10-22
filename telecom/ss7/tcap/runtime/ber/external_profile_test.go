// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/external_profile_test.go; SHA-256 154afe4c97e94c00b5e50fee409345179c8e515cd601763442c33821ba08a87e.
package ber

import (
	"bytes"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"reflect"
	"testing"
)

// X.690 (02/2021) §§8.1.3, 8.18.9: an EXTERNAL open value uses
// its identified syntax, independently of the caller's protocol profile.
func TestExternalOpenValueProfileScope(t *testing.T) {
	for _, text := range []string{
		"2809060130a00404810141",
		"280c060130a00724800401410000",
		"2808060130a003608100",
		"2809060130a00460800000",
		// The standalone helper does not claim the EXTERNAL's own headers.
		// Generated protocol decoders enforce their profile on those headers.
		"280906810130a003040141",
		"2809060130a08103040141",
	} {
		wire := structureWire(t, text)
		_, _, contents, err := DecodeTLV(wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range externalTestProfiles() {
			for _, tolerant := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/tolerant=%t", text, profile.name, tolerant), func(t *testing.T) {
					for _, implicit := range []bool{false, true} {
						var reports ViolationLog
						var options []DecodeOption
						if tolerant {
							options = append(options, WithTolerance(&reports))
						}
						options = profile.track(options)
						original, err := decodeOptions(options)
						if err != nil {
							t.Fatal(err)
						}

						var value runtime.External
						n := len(wire)
						if implicit {
							value, err = DecodeExternalValue(contents, options...)
						} else {
							value, n, err = DecodeExternal(wire, options...)
						}
						if err != nil || n != len(wire) || len(reports.Snapshot()) != 0 {
							t.Fatalf("implicit=%t n=%d err=%v reports=%+v", implicit, n, err, reports.Snapshot())
						}
						if !implicit {
							out, err := EncodeExternal(value)
							if err != nil || !bytes.Equal(out, wire) {
								t.Fatalf("replay=%x err=%v", out, err)
							}
						} else {
							out, err := EncodeExternal(value)
							_, _, replayContents, framingErr := DecodeTLV(out)
							if err != nil || framingErr != nil || !bytes.Equal(replayContents, contents) && text != "280906810130a003040141" && text != "2809060130a08103040141" {
								t.Fatalf("implicit replay=%x err=%v framing=%v", replayContents, err, framingErr)
							}
						}
						after, err := decodeOptions(options)
						if err != nil {
							t.Fatal(err)
						}
						if after.profile != original.profile || after.profileType != original.profileType || after.profileSource != original.profileSource {
							t.Fatal("caller profile changed")
						}
					}
				})
			}
		}
	}
}

// Keep X.690 failures and tolerant UTF-8 reports at the same coordinates
// even when a protocol profile marker is present on the caller's options.
func TestExternalProfileDiagnostics(t *testing.T) {
	for _, text := range []string{"280b060130a006300430303030", "2808060130a0030c01ff"} {
		wire := structureWire(t, text)
		for _, profile := range externalTestProfiles() {
			for _, tolerant := range []bool{false, true} {
				var control, actual ViolationLog
				var a, b []DecodeOption
				if tolerant {
					a = []DecodeOption{WithTolerance(&control)}
					b = []DecodeOption{WithTolerance(&actual)}
				}
				want := ValidateBERElement(wire, a...)
				_, _, got := DecodeExternal(wire, profile.track(b)...)
				if want != nil {
					assertExternalStructureError(t, got, want)
				} else if got != nil {
					t.Fatal(got)
				}
				if !reflect.DeepEqual(actual.Snapshot(), control.Snapshot()) {
					t.Fatalf("%s tolerant=%t reports=%+v want=%+v", profile.name, tolerant, actual.Snapshot(), control.Snapshot())
				}
			}
		}
	}
}

type externalTestProfile struct {
	name  string
	track func([]DecodeOption) []DecodeOption
}

func externalTestProfiles() []externalTestProfile {
	profiles := []externalTestProfile{{"BER", func(o []DecodeOption) []DecodeOption { return o }}}
	for _, root := range []string{"External", "DialoguePortion", "UserInformation", "DialoguePDU"} {
		profiles = append(profiles, externalTestProfile{root, func(o []DecodeOption) []DecodeOption { return TrackTCAPForm(o, root) }})
	}
	return profiles
}
