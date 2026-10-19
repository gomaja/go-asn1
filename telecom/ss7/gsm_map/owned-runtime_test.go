// Code generated from MAP runtime regression contract. DO NOT EDIT.

package gsm_map

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/ros"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

func opaqueWire(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// X.690 (02/2021) §§8.15, 10, 11: an opaque element that already
// meets the DER checks needs no schema-dependent rewriting (#156).
func TestFreshCanonicalOpaqueValues(t *testing.T) {
	for _, tc := range []struct {
		name, wire, want string
		value            interface {
			UnmarshalBER([]byte, ...ber.DecodeOption) error
			MarshalBER(...ber.EncodeOption) ([]byte, error)
			MarshalDER() ([]byte, error)
		}
	}{
		{"typed control", "3008808101018202f121", "30078001018202f121", &PDPContextInfo{}},
		{"unknown addition", "300a8001018202f1219e01ff", "300a8001018202f1219e01ff", &PDPContextInfo{}},
		{"private open NULL", "300aa008300606022a030500", "300aa008300606022a030500", &ExtensionContainer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, want := opaqueWire(t, tc.wire), opaqueWire(t, tc.want)
			if err := tc.value.UnmarshalBER(wire); err != nil {
				t.Fatal(err)
			}
			if container, ok := tc.value.(*ExtensionContainer); ok {
				if container.PrivateExtensionList == nil || len(container.PrivateExtensionList.Values) != 1 || container.PrivateExtensionList.Values[0].ExtType == nil {
					t.Fatal("lost private open value")
				}
				raw := container.PrivateExtensionList.Values[0].ExtType
				if raw.Class != 0 || raw.Tag != 5 || raw.Constructed {
					t.Fatalf("received NULL identifier: %+v", raw)
				}
			}
			replay, err := tc.value.MarshalBER()
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay=%x: %v", replay, err)
			}
			fresh, err := tc.value.MarshalBER(ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(fresh, want) {
				t.Fatalf("fresh=%x want=%x: %v", fresh, want, err)
			}
			der, err := tc.value.MarshalDER()
			if err != nil || !bytes.Equal(der, want) {
				t.Fatalf("DER=%x want=%x: %v", der, want, err)
			}
		})
	}
}

func TestFreshOpaqueRefusesSchemaDependentRepair(t *testing.T) {
	for _, tc := range []struct {
		wire  string
		value interface {
			UnmarshalBER([]byte, ...ber.DecodeOption) error
			MarshalBER(...ber.EncodeOption) ([]byte, error)
		}
	}{
		{"300b8001018202f1219e8101ff", &PDPContextInfo{}},
		{"300ba009300706022a03058100", &ExtensionContainer{}},
	} {
		wire := opaqueWire(t, tc.wire)
		if err := tc.value.UnmarshalBER(wire); err != nil {
			t.Fatal(err)
		}
		replay, err := tc.value.MarshalBER()
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("opaque replay: %v", err)
		}
		fresh, err := tc.value.MarshalBER(ber.WithoutBERReplay())
		if err == nil || fresh != nil || !errors.Is(err, ber.ErrInvalidValue) {
			t.Fatalf("opaque repair accepted: %x %v", fresh, err)
		}
	}
}

func TestOwnedModesReplayAndEdits(t *testing.T) {
	for _, mode := range []struct {
		name    string
		options []ber.DecodeOption
		replay  bool
	}{
		{"adaptive", nil, true},
		{"light", []ber.DecodeOption{ber.ForceGeneratedBERLightForTesting()}, true},
		{"proof", []ber.DecodeOption{ber.ForceGeneratedBERProofForTesting()}, true},
		{"without capture", []ber.DecodeOption{ber.WithoutReplayCapture()}, false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			wire := opaqueWire(t, "3080808101018202f1210000")
			saved := bytes.Clone(wire)
			var value PDPContextInfo
			if err := value.UnmarshalBER(wire, mode.options...); err != nil {
				t.Fatal(err)
			}
			wire[5] = 0x2a // Caller input storage is not retained as mutable replay authority.
			got, err := value.MarshalBER()
			if err != nil {
				t.Fatal(err)
			}
			want := saved
			if !mode.replay {
				want = opaqueWire(t, "30078001018202f121")
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("received form=%x want=%x", got, want)
			}
			value.PdpContextIdentifier = 2
			edited, err := value.MarshalBER()
			if err != nil || bytes.Equal(edited, saved) {
				t.Fatalf("edit ignored: %x %v", edited, err)
			}
			var back PDPContextInfo
			if err := back.UnmarshalBER(edited); err != nil || back.PdpContextIdentifier != 2 {
				t.Fatalf("edited typed value: %v", err)
			}
			value.PdpContextIdentifier = 1
			got, err = value.MarshalBER()
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("reverted edit=%x want=%x: %v", got, want, err)
			}
			fresh, err := value.MarshalBER(ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(fresh, opaqueWire(t, "30078001018202f121")) {
				t.Fatalf("fresh=%x %v", fresh, err)
			}
		})
	}
}

// Source INTEGER constraint, X.680 (02/2021) §51.4. The MAP §17.1.1
// encoding profile is independent of this check and is not activated here.
func TestOwnedConstraintLocationAndStaging(t *testing.T) {
	valid := opaqueWire(t, "30078001018202f121")
	invalid := opaqueWire(t, "30078001008202f121")
	for _, mode := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}, {ber.WithoutReplayCapture()}} {
		var value PDPContextInfo
		if err := value.UnmarshalBER(valid, mode...); err != nil {
			t.Fatal(err)
		}
		err := value.UnmarshalBER(invalid, mode...)
		var failure *ber.ValidationError
		if !errors.As(err, &failure) || failure.Path != "pdp-ContextIdentifier" || failure.Offset == nil || *failure.Offset != 2 || len(failure.ChildIndexes) != 1 || failure.ChildIndexes[0] != 0 || failure.Rule.Document != "ITU-T X.680" || failure.Rule.Clause == "" || failure.Source != "MAP-MS-DataTypes.PDP-ContextInfo.pdp-ContextIdentifier" {
			t.Fatalf("constraint location: %+v (%v)", failure, err)
		}
		if value.PdpContextIdentifier != 1 {
			t.Fatal("failed decode changed receiver")
		}
		var reports ber.ViolationLog
		options := append(append([]ber.DecodeOption(nil), mode...), ber.WithTolerance(&reports))
		if err := value.UnmarshalBER(invalid, options...); err != nil {
			t.Fatal(err)
		}
		if len(reports.Snapshot()) != 1 {
			t.Fatalf("reports=%d", len(reports.Snapshot()))
		}
		if _, err := value.MarshalBER(); err == nil {
			t.Fatal("strict encode replayed an invalid typed value")
		}
		var encodedReports ber.ViolationLog
		got, err := value.MarshalBER(ber.WithTolerance(&encodedReports))
		if err != nil || !bytes.Equal(got, invalid) || len(encodedReports.Snapshot()) != 1 {
			t.Fatalf("tolerant encode=%x %v records=%d", got, err, len(encodedReports.Snapshot()))
		}
		if err := value.UnmarshalBER(opaqueWire(t, "3003800100"), options...); err == nil {
			t.Fatal("tolerance invented a missing mandatory value")
		}
		if len(reports.Snapshot()) != 1 || value.PdpContextIdentifier != 0 {
			t.Fatal("failed decode published receiver or reports")
		}
	}
}

// RawValue metadata describes the retained identifier: X.690 §§8.1.2.1, 8.1.2.5.
func TestOwnedRawMetadataConsistency(t *testing.T) {
	wire := opaqueWire(t, "300aa008300606022a030500")
	var value ExtensionContainer
	if err := value.UnmarshalBER(wire); err != nil {
		t.Fatal(err)
	}
	raw := value.PrivateExtensionList.Values[0].ExtType
	raw.Tag = 4
	for _, encode := range []func() ([]byte, error){func() ([]byte, error) { return value.MarshalBER() }, func() ([]byte, error) { return value.MarshalBER(ber.WithoutBERReplay()) }, value.MarshalDER} {
		if got, err := encode(); !errors.Is(err, ber.ErrInvalidValue) || got != nil {
			t.Fatalf("inconsistent raw identifier encoded: %x %v", got, err)
		}
	}
	raw.Tag = 5
	if got, err := value.MarshalBER(); err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("consistent raw replay=%x: %v", got, err)
	}
}

// X.690 (02/2021) §8.23.10: each malformed octet is one violation,
// with the identifier's original location even inside an opaque value.
func TestOwnedUTF8ReportLocations(t *testing.T) {
	for _, mode := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}, {ber.WithoutReplayCapture()}} {
		for _, tc := range []struct {
			name, wire, path, source string
			offset                   int
			indexes                  []int
			count                    int
			value                    interface {
				UnmarshalBER([]byte, ...ber.DecodeOption) error
				MarshalBER(...ber.EncodeOption) ([]byte, error)
			}
		}{
			{"typed", "30068001018201ff", "h-gmlc-callBackUri", "SS-DataTypes.LCS-CancelDeferredLocationArg.h-gmlc-callBackUri", 5, []int{1}, 1, &LCSCancelDeferredLocationArg{}},
			{"nested open", "300ba009300706022a030c01ff", "privateExtensionList.element[0].extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 10, []int{0, 0, 1}, 1, &ExtensionContainer{}},
			{"standalone open", "300706022a030c01ff", "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 6, []int{1}, 1, &PrivateExtension{}},
			{"unknown addition", "300a8001018202f1210c01ff", "child[2]", "MAP-MS-DataTypes.PDP-ContextInfo", 9, []int{2}, 1, &PDPContextInfo{}},
			{"two octets", "300806022a030c02fffe", "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 6, []int{1}, 2, &PrivateExtension{}},
			{"constructed open", "300b06022a032c05040361fffe", "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 6, []int{1}, 2, &PrivateExtension{}},
			{"nested opaque", "300906022a0330030c01ff", "extType.child[0]", "MAP-ExtensionDataTypes.PrivateExtension.extType", 8, []int{1, 0}, 1, &PrivateExtension{}},
			{"span end unknown addition", "300ea009300706022a030c01610c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 13, []int{1}, 1, &ExtensionContainer{}},
			{"span end empty pcs", "3005a1000c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 4, []int{1}, 1, &ExtensionContainer{}},
			{"span end pcs", "3007a10205000c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 6, []int{1}, 1, &ExtensionContainer{}},
			{"span end nested pcs", "3010a00b300906022a030c036162630c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 15, []int{1}, 1, &ExtensionContainer{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wire := opaqueWire(t, tc.wire)
				if err := tc.value.UnmarshalBER(wire, mode...); !errors.Is(err, ber.ErrInvalidValue) {
					t.Fatalf("strict: %v", err)
				}
				var log ber.ViolationLog
				opts := append(append([]ber.DecodeOption(nil), mode...), ber.WithTolerance(&log), ber.WithDiagnosticLimits(ber.DiagnosticLimits{MaxRecords: tc.count}))
				if err := tc.value.UnmarshalBER(wire, opts...); err != nil {
					t.Fatal(err)
				}
				records := log.Snapshot()
				if len(records) != tc.count {
					t.Fatalf("records=%+v", records)
				}
				for i, r := range records {
					if r.Path != tc.path || r.Source != tc.source || r.Offset == nil || *r.Offset != tc.offset || !reflect.DeepEqual(r.ChildIndexes, tc.indexes) || r.OctetOffset == nil || *r.OctetOffset != i+map[bool]int{true: 1}[tc.name == "constructed open"] || r.Rule != (ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}) {
						t.Errorf("record %d: %+v", i, r)
					}
				}
			})
		}
	}
}

// X.690 (02/2021) §8.23.10: replaying retained open content and unknown
// additions reports the same source and path as tolerant decoding.
func TestOpaqueEncodeRecordsMatchDecode(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		value      interface {
			UnmarshalBER([]byte, ...ber.DecodeOption) error
			MarshalBER(...ber.EncodeOption) ([]byte, error)
		}
	}{
		{"extType", "300706022a030c01ff", &PrivateExtension{}},
		{"container extType", "300ba009300706022a030c01ff", &ExtensionContainer{}},
		{"nested container", "3011300fa00d300b06022a0330050c0361ff62", &AbsentSubscriberParam{}},
		{"addition", "300a8001018202f1210c01ff", &PDPContextInfo{}},
		{"nested addition", "300f8001018202f121bf200530030c01ff", &PDPContextInfo{}},
		{"ROS argument", "30090201010201020c01ff", &ros.Invoke{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := opaqueWire(t, tc.wire)
			var decoded ber.ViolationLog
			if err := tc.value.UnmarshalBER(wire, ber.WithTolerance(&decoded)); err != nil {
				t.Fatal(err)
			}
			var encoded ber.ViolationLog
			replay, err := tc.value.MarshalBER(ber.WithTolerance(&encoded))
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay=%x err=%v", replay, err)
			}
			d, e := decoded.Snapshot(), encoded.Snapshot()
			if len(d) != 1 || len(e) != 1 {
				t.Fatalf("decoded=%+v encoded=%+v", d, e)
			}
			if e[0].Rule != d[0].Rule || e[0].Source != d[0].Source || e[0].Path != d[0].Path || e[0].Constraint != d[0].Constraint || e[0].ObservedValue != d[0].ObservedValue || e[0].Offset != nil || e[0].OctetOffset != nil || len(e[0].ChildIndexes) != 0 {
				t.Fatalf("decoded=%+v encoded=%+v", d[0], e[0])
			}
		})
	}
}

// X.690 (02/2021) §8.23.10 applies to typed UTF8String values, including
// IMPLICIT fields whose outer tag no longer identifies the string type.
func TestTypedUTF8EncodePolicy(t *testing.T) {
	wire := opaqueWire(t, "30068001018201ff")
	value := &LCSCancelDeferredLocationArg{ReferenceNumberExt: []byte{1}, HGmlcCallBackUri: "\xff"}
	for _, encode := range []func() ([]byte, error){
		func() ([]byte, error) { return value.MarshalBER() },
		func() ([]byte, error) { return value.MarshalBER(ber.WithoutBERReplay()) },
		value.MarshalDER,
		func() ([]byte, error) { return LCSCancelDeferredLocationArgCodec().EncodeBER(*value) },
		func() ([]byte, error) {
			return LCSCancelDeferredLocationArgCodec().EncodeBER(*value, ber.WithoutBERReplay())
		},
		func() ([]byte, error) { return LCSCancelDeferredLocationArgCodec().EncodeDER(*value) },
	} {
		_, err := encode()
		validation, ok := err.(*ber.ValidationError)
		if !ok || !errors.Is(err, ber.ErrInvalidValue) {
			t.Fatalf("strict encode kind: %T %v", err, err)
		}
		if validation.Path != "h-gmlc-callBackUri" || validation.Source != "SS-DataTypes.LCS-CancelDeferredLocationArg.h-gmlc-callBackUri" || validation.Rule.Clause != "8.23.10" || validation.ObservedValue != "ff" || validation.Offset != nil || validation.OctetOffset != nil || len(validation.ChildIndexes) != 0 {
			t.Fatalf("strict encode record: %+v", validation)
		}
	}
	var combined ber.ViolationLog
	if _, err := value.MarshalBER(ber.WithTolerance(&combined), ber.WithoutBERReplay()); !errors.Is(err, ber.ErrInvalidValue) || len(combined.Snapshot()) != 0 {
		t.Fatalf("tolerant fresh refusal: %v records=%+v", err, combined.Snapshot())
	}
	codec := LCSCancelDeferredLocationArgCodec()
	if _, err := codec.EncodeBER(*value, ber.WithTolerance(&combined), ber.WithoutBERReplay()); !errors.Is(err, ber.ErrInvalidValue) || len(combined.Snapshot()) != 0 {
		t.Fatalf("typed tolerant fresh refusal: %v records=%+v", err, combined.Snapshot())
	}
	var encoded ber.ViolationLog
	got, err := value.MarshalBER(ber.WithTolerance(&encoded))
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("tolerant encode=%x err=%v", got, err)
	}
	records := encoded.Snapshot()
	if len(records) != 1 || records[0].Path != "h-gmlc-callBackUri" || records[0].Source != "SS-DataTypes.LCS-CancelDeferredLocationArg.h-gmlc-callBackUri" || records[0].Offset != nil || records[0].OctetOffset != nil || len(records[0].ChildIndexes) != 0 {
		t.Fatalf("records=%+v", records)
	}
	var decoded LCSCancelDeferredLocationArg
	var dlog ber.ViolationLog
	if err := decoded.UnmarshalBER(wire, ber.WithTolerance(&dlog)); err != nil {
		t.Fatal(err)
	}
	encoded.Reset()
	got, err = decoded.MarshalBER(ber.WithTolerance(&encoded))
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("tolerant replay=%x err=%v", got, err)
	}
	if len(encoded.Snapshot()) != 1 {
		t.Fatalf("tolerant replay records=%+v", encoded.Snapshot())
	}
	for _, encode := range []func() ([]byte, error){func() ([]byte, error) { return decoded.MarshalBER() }, func() ([]byte, error) { return decoded.MarshalBER(ber.WithoutBERReplay()) }, decoded.MarshalDER} {
		if _, err := encode(); !errors.Is(err, ber.ErrInvalidValue) {
			t.Fatalf("decoded strict encode: %v", err)
		}
	}
}

func TestLCSPeriodicAndEventUTF8Encode(t *testing.T) {
	bad := "\xff"
	for _, tc := range []struct {
		name  string
		value interface {
			MarshalBER(...ber.EncodeOption) ([]byte, error)
			MarshalDER() ([]byte, error)
		}
	}{
		{"periodic", &LCSPeriodicTriggeredInvokeArg{ReferenceNumber: []byte{1}, HGmlcAddress: []byte{1, 2, 3, 4, 5}, HGmlcCallBackUri: &bad}},
		{"event", &LCSEventReportArg{EventType: EventTypePeriodicEvent, ReferenceNumberExt: []byte{1}, HGmlcCallBackUri: bad}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.value.MarshalBER(); !errors.Is(err, ber.ErrInvalidValue) {
				t.Fatalf("BER: %v", err)
			}
			if _, err := tc.value.MarshalBER(ber.WithoutBERReplay()); !errors.Is(err, ber.ErrInvalidValue) {
				t.Fatalf("fresh BER: %v", err)
			}
			if _, err := tc.value.MarshalDER(); !errors.Is(err, ber.ErrInvalidValue) {
				t.Fatalf("DER: %v", err)
			}
			var log ber.ViolationLog
			got, err := tc.value.MarshalBER(ber.WithTolerance(&log))
			records := log.Snapshot()
			if err != nil || len(got) == 0 || len(records) != 1 || records[0].Rule.Clause != "8.23.10" || records[0].Offset != nil {
				t.Fatalf("tolerant=%x err=%v records=%+v", got, err, records)
			}
		})
	}
}

func TestTolerantReencodeUsesDefaultDiagnosticLimit(t *testing.T) {
	content := append([]byte{0x80, 1, 1, 0x82, 2, 0xf1, 0x21}, bytes.Repeat([]byte{0x0c, 1, 0xff}, 1025)...)
	wire, err := ber.EncodeSequence(content)
	if err != nil {
		t.Fatal(err)
	}
	var value PDPContextInfo
	var decoded ber.ViolationLog
	if err := value.UnmarshalBER(wire, ber.WithTolerance(&decoded), ber.WithDiagnosticLimits(ber.DiagnosticLimits{MaxRecords: 2048})); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Snapshot()) != 1025 {
		t.Fatalf("decode records=%d", len(decoded.Snapshot()))
	}
	var encoded ber.ViolationLog
	if _, err := value.MarshalBER(ber.WithTolerance(&encoded)); !errors.Is(err, ber.ErrResourceLimit) {
		t.Fatalf("re-encode=%v", err)
	}
	if len(encoded.Snapshot()) != 0 {
		t.Fatalf("failed encode published %+v", encoded.Snapshot())
	}
}

// X.680 (02/2021) §51.5: a failed element SIZE constraint identifies the
// received element, including when the collection is nested in a SEQUENCE.
func TestPrimitiveCollectionElementLocations(t *testing.T) {
	for _, tc := range []struct {
		name, wire, path string
		offset           int
		indexes          []int
		decode           func([]byte, ...ber.DecodeOption) error
	}{
		{"HLR-List", "300904031122330402aabb", "element[1]", 7, []int{1}, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERHLRList(w, o...); return e }},
		{"ResetArg.hlr-List", "300e040191300904031122330402aabb", "hlr-List.element[1]", 12, []int{1, 1}, func(w []byte, o ...ber.DecodeOption) error { var v ResetArg; return v.UnmarshalBER(w, o...) }},
		{"ResetArg.reset-Id-List", "300a040191a1050401110400", "reset-Id-List.element[1]", 10, []int{1, 1}, func(w []byte, o ...ber.DecodeOption) error { var v ResetArg; return v.UnmarshalBER(w, o...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := opaqueWire(t, tc.wire)
			for _, tolerant := range []bool{false, true} {
				var reports ber.ViolationLog
				var opts []ber.DecodeOption
				if tolerant {
					opts = append(opts, ber.WithTolerance(&reports))
				}
				err := tc.decode(wire, opts...)
				var got ber.Violation
				if tolerant {
					records := reports.Snapshot()
					if err != nil || len(records) != 1 {
						t.Fatalf("tolerant error=%v records=%+v", err, records)
					}
					got = records[0]
				} else {
					var failure *ber.ValidationError
					if !errors.As(err, &failure) {
						t.Fatalf("strict error=%v", err)
					}
					got = failure.Violation
				}
				if got.Path != tc.path || got.Offset == nil || *got.Offset != tc.offset || !reflect.DeepEqual(got.ChildIndexes, tc.indexes) {
					t.Fatalf("tolerant=%v location=%+v", tolerant, got)
				}
			}
		})
	}
}

// Each emitted primitive collection constraint must locate element[1] at its
// received identifier in both strict and tolerant decoding.
func TestAllPrimitiveCollectionConstraintLocations(t *testing.T) {
	cases := []struct {
		name    string
		minimum int
		integer bool
		decode  func([]byte, ...ber.DecodeOption) error
	}{
		{"Ipv4Addrs", 4, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERIpv4Addrs(w, o...); return e }},
		{"Ipv6Addrs", 16, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERIpv6Addrs(w, o...); return e }},
		{"HLRList", 3, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERHLRList(w, o...); return e }},
		{"EPLMNList", 3, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBEREPLMNList(w, o...); return e }},
		{"AdjacentPLMNList", 3, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERAdjacentPLMNList(w, o...); return e }},
		{"ResetIdList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERResetIdList(w, o...); return e }},
		{"LIPAAllowedAPNList", 2, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERLIPAAllowedAPNList(w, o...); return e }},
		{"GMLCList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERGMLCList(w, o...); return e }},
		{"BearerServiceList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERBearerServiceList(w, o...); return e }},
		{"TeleserviceList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERTeleserviceList(w, o...); return e }},
		{"ZoneCodeList", 2, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERZoneCodeList(w, o...); return e }},
		{"LSAIdentityList", 3, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERLSAIdentityList(w, o...); return e }},
		{"SSEventList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERSSEventList(w, o...); return e }},
		{"DestinationNumberList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := UnmarshalBERDestinationNumberList(w, o...)
			return e
		}},
		{"OCauseValueCriteria", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := UnmarshalBEROCauseValueCriteria(w, o...)
			return e
		}},
		{"TCauseValueCriteria", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := UnmarshalBERTCauseValueCriteria(w, o...)
			return e
		}},
		{"MobilityTriggers", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERMobilityTriggers(w, o...); return e }},
		{"DispatcherList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERDispatcherList(w, o...); return e }},
		{"AdditionalDispatcherList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := UnmarshalBERAdditionalDispatcherList(w, o...)
			return e
		}},
		{"SSList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERSSList(w, o...); return e }},
		{"SSEventSpecification", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := UnmarshalBERSSEventSpecification(w, o...)
			return e
		}},
		{"MDTAllowedPLMNIdList", 3, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := UnmarshalBERMDTAllowedPLMNIdList(w, o...)
			return e
		}},
		{"CGIList", 5, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERCGIList(w, o...); return e }},
		{"EUTRANCGIList", 7, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBEREUTRANCGIList(w, o...); return e }},
		{"RoutingAreaIdList", 6, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERRoutingAreaIdList(w, o...); return e }},
		{"LocationAreaIdList", 5, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERLocationAreaIdList(w, o...); return e }},
		{"TrackingAreaIdList", 5, false, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERTrackingAreaIdList(w, o...); return e }},
		{"ContextIdList", 1, true, func(w []byte, o ...ber.DecodeOption) error { _, e := UnmarshalBERContextIdList(w, o...); return e }},
		{"DestinationNumberLengthList", 1, true, func(w []byte, o ...ber.DecodeOption) error {
			_, e := UnmarshalBERDestinationNumberLengthList(w, o...)
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var first, second []byte
			if tc.integer {
				first = []byte{0x02, 1, 1}
				second = []byte{0x02, 1, 0}
			} else {
				first = append([]byte{0x04, byte(tc.minimum)}, bytes.Repeat([]byte{0x11}, tc.minimum)...)
				second = []byte{0x04, 0}
			}
			wire := append([]byte{0x30, byte(len(first) + len(second))}, first...)
			wire = append(wire, second...)
			offset := 2 + len(first)
			for _, tolerant := range []bool{false, true} {
				var reports ber.ViolationLog
				var options []ber.DecodeOption
				if tolerant {
					options = append(options, ber.WithTolerance(&reports))
				}
				err := tc.decode(wire, options...)
				var got ber.Violation
				if tolerant {
					records := reports.Snapshot()
					if err != nil || len(records) == 0 {
						t.Fatalf("tolerant error=%v records=%+v", err, records)
					}
					for _, r := range records {
						if r.Path != "element[1]" || r.Offset == nil || *r.Offset != offset || !reflect.DeepEqual(r.ChildIndexes, []int{1}) {
							t.Fatalf("tolerant location=%+v want offset %d", r, offset)
						}
					}
					got = records[0]
				} else {
					var failure *ber.ValidationError
					if !errors.As(err, &failure) {
						t.Fatalf("strict error=%v", err)
					}
					got = failure.Violation
				}
				if got.Path != "element[1]" || got.Offset == nil || *got.Offset != offset || !reflect.DeepEqual(got.ChildIndexes, []int{1}) {
					t.Fatalf("tolerant=%v location=%+v want offset %d", tolerant, got, offset)
				}
			}
		})
	}
}

func TestR39StrictOpaqueRefusalPath(t *testing.T) {
	for _, c := range []struct {
		name, wire string
		value      interface {
			UnmarshalBER([]byte, ...ber.DecodeOption) error
			MarshalBER(...ber.EncodeOption) ([]byte, error)
		}
	}{
		{"extType", "300706022a030c01ff", &PrivateExtension{}},
		{"container extType", "300ba009300706022a030c01ff", &ExtensionContainer{}},
		{"addition", "300a8001018202f1210c01ff", &PDPContextInfo{}},
		{"ros argument", "30090201010201020c01ff", &ros.Invoke{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var log ber.ViolationLog
			if err := c.value.UnmarshalBER(opaqueWire(t, c.wire), ber.WithTolerance(&log)); err != nil {
				t.Fatal(err)
			}
			d := log.Snapshot()
			_, err := c.value.MarshalBER()
			ve, bare := err.(*ber.ValidationError)
			if len(d) != 1 || !bare {
				t.Fatalf("records %v err %T %v", d, err, err)
			}
			if ve.Path != d[0].Path || ve.Source != d[0].Source || ve.Rule != d[0].Rule || ve.ObservedValue != d[0].ObservedValue {
				t.Fatalf("strict=%+v decoded=%+v", ve, d[0])
			}
		})
	}
}

// X.680 (02/2021) §§22.7, 51.5: a set bit outside every permitted
// equivalent length is a source SIZE violation, including in builders.
func TestNamedBitSizeEncodeError(t *testing.T) {
	bits := runtime.BitString{Bytes: []byte{0, 0x80}, BitLength: 9}
	value := SGSNCapability{SupportedRATTypesIndicator: &bits}
	codec := SGSNCapabilityCodec()
	for _, encode := range []func() ([]byte, error){
		func() ([]byte, error) { return value.MarshalBER() },
		func() ([]byte, error) { return value.MarshalBER(ber.WithoutBERReplay()) },
		value.MarshalDER,
		func() ([]byte, error) { return codec.EncodeBER(value) },
		func() ([]byte, error) { return codec.EncodeBER(value, ber.WithoutBERReplay()) },
		func() ([]byte, error) { return codec.EncodeDER(value) },
	} {
		_, err := encode()
		ve, ok := err.(*ber.ValidationError)
		if !ok || !errors.Is(err, ber.ErrInvalidValue) {
			t.Fatalf("error type: %T %v", err, err)
		}
		if ve.Constraint != "SIZE (2..8)" || ve.Path != "supportedRAT-TypesIndicator" || ve.Source != "MAP-MS-DataTypes.SGSN-Capability.supportedRAT-TypesIndicator" || ve.Rule.Clause != "51.5" || ve.ObservedLength == nil || *ve.ObservedLength != 9 {
			t.Fatalf("violation: %+v", ve)
		}
	}
	_, err := NewSupportedRATTypes(8)
	ve, ok := err.(*ber.ValidationError)
	if !ok || ve.Path != "" || ve.Source != "MAP-MS-DataTypes.SupportedRAT-Types" || ve.Constraint != "SIZE (2..8)" || ve.Rule.Clause != "51.5" || ve.ObservedLength == nil || *ve.ObservedLength != 9 {
		t.Fatalf("builder: %T %+v", err, err)
	}
	var log ber.ViolationLog
	got, err := value.MarshalBER(ber.WithTolerance(&log))
	if err != nil || !bytes.Equal(got, opaqueWire(t, "30058803070080")) || len(log.Snapshot()) != 1 {
		t.Fatalf("tolerant: %x %v %+v", got, err, log.Snapshot())
	}
	bits.Bytes = nil
	for _, encode := range []func() ([]byte, error){func() ([]byte, error) { return value.MarshalBER() }, func() ([]byte, error) { return value.MarshalBER(ber.WithoutBERReplay()) }, value.MarshalDER} {
		_, err := encode()
		path, ok := err.(interface{ ASN1BERPath() string })
		if !ok || path.ASN1BERPath() != "supportedRAT-TypesIndicator" {
			t.Fatalf("structural field path: %T %v", err, err)
		}
	}
}

// X.690 (02/2021) §§8.9, 8.23.10: retained additions keep their wire
// ordinals, and repeated tolerant failures must not repeatedly scan the prefix.
func TestTolerantOpaqueOrdinalGrowth(t *testing.T) {
	measure := func(k, e int, replay bool) time.Duration {
		large := []byte{0x30, 0x80}
		for range e {
			large = append(large, 5, 0)
		}
		large = append(large, 0, 0)
		value := PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{large}}
		for range k {
			value.ExtData_ = append(value.ExtData_, []byte{12, 1, 255})
		}
		var original []byte
		if replay {
			var log ber.ViolationLog
			var err error
			original, err = value.MarshalBER(ber.WithTolerance(&log))
			if err != nil {
				t.Fatal(err)
			}
			value = PDPContextInfo{}
			log.Reset()
			if err = value.UnmarshalBER(original, ber.WithTolerance(&log), ber.WithDecodeLimits(ber.DecodeLimits{MaxDepth: 64, MaxElements: 1 << 22, MaxWork: 1 << 28})); err != nil {
				t.Fatal(err)
			}
		}
		best := time.Duration(1<<63 - 1)
		// Each sample repeats the encode for at least 100ms, so a coarse clock
		// (about 15.6ms on some Windows hosts) cannot round a fast case to zero.
		for range 3 {
			start := time.Now()
			n := 0
			for {
				var log ber.ViolationLog
				wire, err := value.MarshalBER(ber.WithTolerance(&log))
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					rows := log.Snapshot()
					if len(rows) != k || rows[k-1].Path != fmt.Sprintf("child[%d]", k+2) {
						t.Fatalf("ordinals: %d %+v", len(rows), rows[len(rows)-1])
					}
					if replay && !bytes.Equal(wire, original) {
						t.Fatal("replay changed bytes")
					}
				}
				n++
				if time.Since(start) >= 100*time.Millisecond {
					break
				}
			}
			if perOp := time.Since(start) / time.Duration(n); perOp < best {
				best = perOp
			}
		}
		return best
	}
	// About 16 times the content and failures: linear work grows about 16x, the
	// old per-failure rescan about 250x. The 64x ceiling leaves room for timing
	// noise on a loaded machine on both sides.
	for _, replay := range []bool{false, true} {
		small := measure(64, 1<<13, replay)
		large := measure(1000, 1<<17, replay)
		t.Logf("replay=%v small=%v large=%v ratio=%.2f", replay, small, large, float64(large)/float64(small))
		if large > 64*small {
			t.Errorf("sixteenfold content/failures grew more than 64x: %v -> %v", small, large)
		}
	}
}

func TestDEROpaqueValidationError(t *testing.T) {
	bad := []byte{12, 1, 255}
	pdp := PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{bad}}
	open := PrivateExtension{ExtId: runtime.MustObjectIdentifierFromArcs(1, 2, 3), ExtType: &runtime.RawValue{Class: 0, Tag: 12, Bytes: bad}}
	nested := ExtensionContainer{PrivateExtensionList: &PrivateExtensionList{Values: []PrivateExtension{open}}}
	for _, item := range []struct {
		name string
		ber  func() ([]byte, error)
		der  func() ([]byte, error)
	}{
		{"addition", func() ([]byte, error) { return pdp.MarshalBER() }, pdp.MarshalDER},
		{"addition codec", func() ([]byte, error) { return PDPContextInfoCodec().EncodeBER(pdp) }, func() ([]byte, error) { return PDPContextInfoCodec().EncodeDER(pdp) }},
		{"open", func() ([]byte, error) { return open.MarshalBER() }, open.MarshalDER},
		{"nested open", func() ([]byte, error) { return nested.MarshalBER() }, nested.MarshalDER},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, be := item.ber()
			_, de := item.der()
			want, ok := be.(*ber.ValidationError)
			if !ok {
				t.Fatalf("BER: %T %v", be, be)
			}
			got, ok := de.(*ber.ValidationError)
			if !ok || !errors.Is(de, ber.ErrInvalidValue) {
				t.Fatalf("DER: %T %v", de, de)
			}
			if !reflect.DeepEqual(got.Violation, want.Violation) {
				t.Fatalf("DER=%+v BER=%+v", got, want)
			}
		})
	}
}

// X.680 (02/2021) §22.7: encode-side SIZE diagnostics compare significant
// length; decode-side diagnostics continue to describe the received length.
func TestNamedBitEncodeObservedSignificantLength(t *testing.T) {
	bits := runtime.BitString{Bytes: []byte{0, 0x80}, BitLength: 16}
	v := SGSNCapability{SupportedRATTypesIndicator: &bits}
	c := SGSNCapabilityCodec()
	for _, encode := range []func(...ber.EncodeOption) ([]byte, error){v.MarshalBER, func(o ...ber.EncodeOption) ([]byte, error) { return c.EncodeBER(v, o...) }} {
		for _, fresh := range []bool{false, true} {
			var log ber.ViolationLog
			opts := []ber.EncodeOption{ber.WithTolerance(&log)}
			if fresh {
				opts = append(opts, ber.WithoutBERReplay())
			}
			wire, err := encode(opts...)
			if err != nil {
				t.Fatal(err)
			}
			rows := log.Snapshot()
			if len(rows) != 1 || rows[0].ObservedLength == nil || *rows[0].ObservedLength != 9 {
				t.Fatalf("encode records=%+v", rows)
			}
			var decoded SGSNCapability
			var dlog ber.ViolationLog
			if err := decoded.UnmarshalBER(wire, ber.WithTolerance(&dlog)); err != nil {
				t.Fatal(err)
			}
			rows = dlog.Snapshot()
			if len(rows) != 1 || rows[0].ObservedLength == nil || *rows[0].ObservedLength != 16 {
				t.Fatalf("decode records=%+v", rows)
			}
			_, err = encode()
			ve, ok := err.(*ber.ValidationError)
			if !ok || ve.ObservedLength == nil || *ve.ObservedLength != 9 {
				t.Fatalf("strict: %T %v", err, err)
			}
		}
	}
}
