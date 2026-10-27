// Code generated from MAP runtime regression contract. DO NOT EDIT.

package gsm_map_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	mapvalues "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mapbindings "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/bindings"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/ros"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_lcs_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ms_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_om_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_sm_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
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
		{"typed control", "3008808101018202f121", "30078001018202f121", &mapvalues.PDPContextInfo{}},
		{"unknown addition", "300a8001018202f1219e01ff", "300a8001018202f1219e01ff", &mapvalues.PDPContextInfo{}},
		{"private open NULL", "300aa008300606022a030500", "300aa008300606022a030500", &mapvalues.ExtensionContainer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, want := opaqueWire(t, tc.wire), opaqueWire(t, tc.want)
			var profileReports ber.ViolationLog
			var decodeOptions []ber.DecodeOption
			var encodeOptions []ber.EncodeOption
			if tc.name == "typed control" {
				if err := tc.value.UnmarshalBER(wire); !errors.Is(err, ber.ErrInvalidValue) {
					t.Fatalf("strict MAP length profile: %v", err)
				}
				decodeOptions = []ber.DecodeOption{ber.WithTolerance(&profileReports)}
				encodeOptions = []ber.EncodeOption{ber.WithTolerance(new(ber.ViolationLog))}
			}
			if err := tc.value.UnmarshalBER(wire, decodeOptions...); err != nil {
				t.Fatal(err)
			}
			if tc.name == "typed control" {
				rows := profileReports.Snapshot()
				if len(rows) != 1 || rows[0].Rule.Clause != "17.1.1" {
					t.Fatalf("MAP profile records=%+v", rows)
				}
			}
			if container, ok := tc.value.(*mapvalues.ExtensionContainer); ok {
				if container.PrivateExtensionList == nil || len(container.PrivateExtensionList.Values) != 1 || container.PrivateExtensionList.Values[0].ExtType == nil {
					t.Fatal("lost private open value")
				}
				raw := container.PrivateExtensionList.Values[0].ExtType
				if raw.Class != 0 || raw.Tag != 5 || raw.Constructed {
					t.Fatalf("received NULL identifier: %+v", raw)
				}
			}
			replay, err := tc.value.MarshalBER(encodeOptions...)
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
		{"300b8001018202f1219e8101ff", &mapvalues.PDPContextInfo{}},
		{"300ba009300706022a03058100", &mapvalues.ExtensionContainer{}},
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
			wire := opaqueWire(t, "30808001018202f1210000")
			saved := bytes.Clone(wire)
			var value mapvalues.PDPContextInfo
			if err := value.UnmarshalBER(wire, mode.options...); err != nil {
				t.Fatal(err)
			}
			wire[4] = 0x2a // Caller input storage is not retained as mutable replay authority.
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
			var back mapvalues.PDPContextInfo
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
// encoding profile is independent of this source constraint check.
func TestOwnedConstraintLocationAndStaging(t *testing.T) {
	valid := opaqueWire(t, "30078001018202f121")
	invalid := opaqueWire(t, "30078001008202f121")
	for _, mode := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}, {ber.WithoutReplayCapture()}} {
		var value mapvalues.PDPContextInfo
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
	var value mapvalues.ExtensionContainer
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
			{"typed", "30068001018201ff", "h-gmlc-callBackUri", "SS-DataTypes.LCS-CancelDeferredLocationArg.h-gmlc-callBackUri", 5, []int{1}, 1, &mapvalues.LCSCancelDeferredLocationArg{}},
			{"nested open", "300ba009300706022a030c01ff", "privateExtensionList.element[0].extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 10, []int{0, 0, 1}, 1, &mapvalues.ExtensionContainer{}},
			{"standalone open", "300706022a030c01ff", "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 6, []int{1}, 1, &mapvalues.PrivateExtension{}},
			{"unknown addition", "300a8001018202f1210c01ff", "child[2]", "MAP-MS-DataTypes.PDP-ContextInfo", 9, []int{2}, 1, &mapvalues.PDPContextInfo{}},
			{"two octets", "300806022a030c02fffe", "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 6, []int{1}, 2, &mapvalues.PrivateExtension{}},
			{"constructed open", "300b06022a032c05040361fffe", "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", 6, []int{1}, 2, &mapvalues.PrivateExtension{}},
			{"nested opaque", "300906022a0330030c01ff", "extType.child[0]", "MAP-ExtensionDataTypes.PrivateExtension.extType", 8, []int{1, 0}, 1, &mapvalues.PrivateExtension{}},
			{"span end unknown addition", "300ea009300706022a030c01610c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 13, []int{1}, 1, &mapvalues.ExtensionContainer{}},
			{"span end empty pcs", "3005a1000c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 4, []int{1}, 1, &mapvalues.ExtensionContainer{}},
			{"span end pcs", "3007a10205000c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 6, []int{1}, 1, &mapvalues.ExtensionContainer{}},
			{"span end nested pcs", "3010a00b300906022a030c036162630c01ff", "child[1]", "MAP-ExtensionDataTypes.ExtensionContainer", 15, []int{1}, 1, &mapvalues.ExtensionContainer{}},
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
		{"extType", "300706022a030c01ff", &mapvalues.PrivateExtension{}},
		{"container extType", "300ba009300706022a030c01ff", &mapvalues.ExtensionContainer{}},
		{"nested container", "3011300fa00d300b06022a0330050c0361ff62", &mapvalues.AbsentSubscriberParam{}},
		{"addition", "300a8001018202f1210c01ff", &mapvalues.PDPContextInfo{}},
		{"nested addition", "300f8001018202f121bf200530030c01ff", &mapvalues.PDPContextInfo{}},
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
	value := &mapvalues.LCSCancelDeferredLocationArg{ReferenceNumberExt: []byte{1}, HGmlcCallBackUri: "\xff"}
	for _, encode := range []func() ([]byte, error){
		func() ([]byte, error) { return value.MarshalBER() },
		func() ([]byte, error) { return value.MarshalBER(ber.WithoutBERReplay()) },
		value.MarshalDER,
		func() ([]byte, error) { return mapbindings.LCSCancelDeferredLocationArgCodec().EncodeBER(*value) },
		func() ([]byte, error) {
			return mapbindings.LCSCancelDeferredLocationArgCodec().EncodeBER(*value, ber.WithoutBERReplay())
		},
		func() ([]byte, error) { return mapbindings.LCSCancelDeferredLocationArgCodec().EncodeDER(*value) },
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
	codec := mapbindings.LCSCancelDeferredLocationArgCodec()
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
	var decoded mapvalues.LCSCancelDeferredLocationArg
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
		{"periodic", &mapvalues.LCSPeriodicTriggeredInvokeArg{ReferenceNumber: []byte{1}, HGmlcAddress: []byte{1, 2, 3, 4, 5}, HGmlcCallBackUri: &bad}},
		{"event", &mapvalues.LCSEventReportArg{EventType: mapvalues.EventTypePeriodicEvent, ReferenceNumberExt: []byte{1}, HGmlcCallBackUri: bad}},
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
	var value mapvalues.PDPContextInfo
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
		{"HLR-List", "300904031122330402aabb", "element[1]", 7, []int{1}, func(w []byte, o ...ber.DecodeOption) error { _, e := mapvalues.UnmarshalBERHLRList(w, o...); return e }},
		{"ResetArg.hlr-List", "300e040191300904031122330402aabb", "hlr-List.element[1]", 12, []int{1, 1}, func(w []byte, o ...ber.DecodeOption) error { var v mapvalues.ResetArg; return v.UnmarshalBER(w, o...) }},
		{"ResetArg.reset-Id-List", "300a040191a1050401110400", "reset-Id-List.element[1]", 10, []int{1, 1}, func(w []byte, o ...ber.DecodeOption) error { var v mapvalues.ResetArg; return v.UnmarshalBER(w, o...) }},
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
		{"Ipv4Addrs", 4, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERIpv4Addrs(w, o...)
			return e
		}},
		{"Ipv6Addrs", 16, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERIpv6Addrs(w, o...)
			return e
		}},
		{"HLRList", 3, false, func(w []byte, o ...ber.DecodeOption) error { _, e := mapvalues.UnmarshalBERHLRList(w, o...); return e }},
		{"EPLMNList", 3, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBEREPLMNList(w, o...)
			return e
		}},
		{"AdjacentPLMNList", 3, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERAdjacentPLMNList(w, o...)
			return e
		}},
		{"ResetIdList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERResetIdList(w, o...)
			return e
		}},
		{"LIPAAllowedAPNList", 2, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERLIPAAllowedAPNList(w, o...)
			return e
		}},
		{"GMLCList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := mapvalues.UnmarshalBERGMLCList(w, o...); return e }},
		{"BearerServiceList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERBearerServiceList(w, o...)
			return e
		}},
		{"TeleserviceList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERTeleserviceList(w, o...)
			return e
		}},
		{"ZoneCodeList", 2, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERZoneCodeList(w, o...)
			return e
		}},
		{"LSAIdentityList", 3, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERLSAIdentityList(w, o...)
			return e
		}},
		{"SSEventList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERSSEventList(w, o...)
			return e
		}},
		{"DestinationNumberList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERDestinationNumberList(w, o...)
			return e
		}},
		{"OCauseValueCriteria", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBEROCauseValueCriteria(w, o...)
			return e
		}},
		{"TCauseValueCriteria", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERTCauseValueCriteria(w, o...)
			return e
		}},
		{"MobilityTriggers", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERMobilityTriggers(w, o...)
			return e
		}},
		{"DispatcherList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERDispatcherList(w, o...)
			return e
		}},
		{"AdditionalDispatcherList", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERAdditionalDispatcherList(w, o...)
			return e
		}},
		{"SSList", 1, false, func(w []byte, o ...ber.DecodeOption) error { _, e := mapvalues.UnmarshalBERSSList(w, o...); return e }},
		{"SSEventSpecification", 1, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERSSEventSpecification(w, o...)
			return e
		}},
		{"MDTAllowedPLMNIdList", 3, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERMDTAllowedPLMNIdList(w, o...)
			return e
		}},
		{"CGIList", 5, false, func(w []byte, o ...ber.DecodeOption) error { _, e := mapvalues.UnmarshalBERCGIList(w, o...); return e }},
		{"EUTRANCGIList", 7, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBEREUTRANCGIList(w, o...)
			return e
		}},
		{"RoutingAreaIdList", 6, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERRoutingAreaIdList(w, o...)
			return e
		}},
		{"LocationAreaIdList", 5, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERLocationAreaIdList(w, o...)
			return e
		}},
		{"TrackingAreaIdList", 5, false, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERTrackingAreaIdList(w, o...)
			return e
		}},
		{"ContextIdList", 1, true, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERContextIdList(w, o...)
			return e
		}},
		{"DestinationNumberLengthList", 1, true, func(w []byte, o ...ber.DecodeOption) error {
			_, e := mapvalues.UnmarshalBERDestinationNumberLengthList(w, o...)
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
		{"extType", "300706022a030c01ff", &mapvalues.PrivateExtension{}},
		{"container extType", "300ba009300706022a030c01ff", &mapvalues.ExtensionContainer{}},
		{"addition", "300a8001018202f1210c01ff", &mapvalues.PDPContextInfo{}},
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
	value := mapvalues.SGSNCapability{SupportedRATTypesIndicator: &bits}
	codec := mapbindings.SGSNCapabilityCodec()
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
	_, err := mapvalues.NewSupportedRATTypes(8)
	ve, ok := err.(*ber.ValidationError)
	if !ok || ve.Path != "SupportedRAT-Types" || ve.Source != "MAP-MS-DataTypes.SupportedRAT-Types" || ve.Constraint != "SIZE (2..8)" || ve.Rule.Clause != "51.5" || ve.ObservedLength == nil || *ve.ObservedLength != 9 {
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
	measure := func(k, e int, replay bool) func(bool) {
		large := []byte{0x30, 0x80}
		for range e {
			large = append(large, 5, 0)
		}
		large = append(large, 0, 0)
		value := mapvalues.PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{large}}
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
			value = mapvalues.PDPContextInfo{}
			log.Reset()
			if err = value.UnmarshalBER(original, ber.WithTolerance(&log), ber.WithDecodeLimits(ber.DecodeLimits{MaxDepth: 64, MaxElements: 1 << 22, MaxWork: 1 << 28})); err != nil {
				t.Fatal(err)
			}
		}
		return func(first bool) {
			var log ber.ViolationLog
			wire, err := value.MarshalBER(ber.WithTolerance(&log))
			if err != nil {
				t.Fatal(err)
			}
			if !first {
				return
			}
			rows := log.Snapshot()
			if len(rows) != k || rows[k-1].Path != fmt.Sprintf("child[%d]", k+2) {
				t.Fatalf("ordinals: %d %+v", len(rows), rows[len(rows)-1])
			}
			if replay && !bytes.Equal(wire, original) {
				t.Fatal("replay changed bytes")
			}
		}
	}
	// About 16 times the content and failures: linear work grows about 16x, the
	// old per-failure rescan about 250x. The 64x ceiling leaves room for timing
	// noise on a loaded machine on both sides.
	for _, replay := range []bool{false, true} {
		operations := []func(bool){measure(64, 1<<13, replay), measure(1000, 1<<17, replay)}
		var minima [2]time.Duration
		for sample := range 5 {
			for i, operation := range operations {
				start := time.Now()
				n := 0
				for {
					operation(n == 0)
					n++
					if time.Since(start) >= 100*time.Millisecond {
						break
					}
				}
				perOp := time.Since(start) / time.Duration(n)
				if sample == 0 || perOp < minima[i] {
					minima[i] = perOp
				}
			}
		}
		small, large := minima[0], minima[1]
		t.Logf("replay=%v small=%v large=%v ratio=%.2f", replay, small, large, float64(large)/float64(small))
		if large > 64*small {
			t.Errorf("sixteenfold content/failures grew more than 64x: %v -> %v", small, large)
		}
	}
}

func TestDEROpaqueValidationError(t *testing.T) {
	bad := []byte{12, 1, 255}
	pdp := mapvalues.PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{bad}}
	later := mapvalues.PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{{5, 0}, {2, 1, 1}, bad}}
	open := mapvalues.PrivateExtension{ExtId: runtime.MustObjectIdentifierFromArcs(1, 2, 3), ExtType: &runtime.RawValue{Class: 0, Tag: 12, Bytes: bad}}
	nested := mapvalues.ExtensionContainer{PrivateExtensionList: &mapvalues.PrivateExtensionList{Values: []mapvalues.PrivateExtension{open}}}
	for _, item := range []struct {
		name string
		ber  func() ([]byte, error)
		der  func() ([]byte, error)
	}{
		{"addition", func() ([]byte, error) { return pdp.MarshalBER() }, pdp.MarshalDER},
		{"addition i=2", func() ([]byte, error) { return later.MarshalBER() }, later.MarshalDER},
		{"addition codec", func() ([]byte, error) { return mapbindings.PDPContextInfoCodec().EncodeBER(pdp) }, func() ([]byte, error) { return mapbindings.PDPContextInfoCodec().EncodeDER(pdp) }},
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
	v := mapvalues.SGSNCapability{SupportedRATTypesIndicator: &bits}
	c := mapbindings.SGSNCapabilityCodec()
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
			var decoded mapvalues.SGSNCapability
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

// Refusal rescans retain one UTF-8 finding while still checking later structure.
func TestOpaqueRefusalAfterUTF8(t *testing.T) {
	for _, tc := range []struct {
		name          string
		wire          []byte
		structural    bool
		offset, index int
		suffix        string
	}{
		{"later BOOLEAN", []byte{0x30, 7, 12, 1, 255, 1, 2, 0, 0}, true, 5, 1, ""},
		{"over budget", append([]byte{12, 0x82, 4, 1}, bytes.Repeat([]byte{255}, 1025)...), false, 0, 0, ""},
		{"many strings", append([]byte{0x30, 0x82, 0x0c, 3}, bytes.Repeat([]byte{12, 1, 255}, 1025)...), false, 0, 0, ".child[0]"},
		{"structure past budget", append(append([]byte{0x30, 0x82, 0x0c, 7}, bytes.Repeat([]byte{12, 1, 255}, 1025)...), 1, 2, 0, 0), true, 3079, 1025, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag := int(tc.wire[0] & 31)
			open := &mapvalues.PrivateExtension{ExtId: runtime.MustObjectIdentifierFromArcs(1, 2, 3), ExtType: &runtime.RawValue{Tag: tag, Constructed: tc.wire[0]&32 != 0, Bytes: tc.wire}}
			addition := &mapvalues.PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{tc.wire}}
			for _, shape := range []struct {
				name, path, source string
				value              interface {
					MarshalBER(...ber.EncodeOption) ([]byte, error)
					MarshalDER() ([]byte, error)
				}
			}{
				{"open", "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType", open},
				{"addition", "child[2]", "MAP-MS-DataTypes.PDP-ContextInfo", addition},
			} {
				t.Run(shape.name, func(t *testing.T) {
					for _, mode := range []struct {
						name   string
						encode func() ([]byte, error)
					}{
						{"BER", func() ([]byte, error) { return shape.value.MarshalBER() }},
						{"fresh", func() ([]byte, error) { return shape.value.MarshalBER(ber.WithoutBERReplay()) }},
						{"DER", shape.value.MarshalDER},
					} {
						t.Run(mode.name, func(t *testing.T) {
							wire, err := mode.encode()
							var ve *ber.ValidationError
							if len(wire) != 0 || err == nil {
								t.Fatalf("accepted: %x %v", wire, err)
							}
							if tc.structural {
								var ee *ber.ElementError
								if errors.As(err, &ve) || !strings.Contains(err.Error(), "BOOLEAN") || !errors.As(err, &ee) || ee.Offset() != tc.offset || !reflect.DeepEqual(ee.ChildIndexes(), []int{tc.index}) {
									t.Fatalf("structural: %T %v", err, err)
								}
							} else {
								if !errors.As(err, &ve) || ve.Path != shape.path+tc.suffix || ve.Source != shape.source || ve.Rule.Clause != "8.23.10" {
									t.Fatalf("UTF-8: %T %+v", err, err)
								}
							}
						})
					}
				})
			}
		})
	}
}

// Standalone builders use the ASN.1 assignment name as the abstract root path;
// inline builders retain the component suffix. Cover current and version-21 codecs.
type compactBitCase struct {
	name, source, path string
	maximum            int
	encode             func(runtime.BitString, ...ber.EncodeOption) ([]byte, error)
	der                func(runtime.BitString) ([]byte, error)
	build              func(...int) (runtime.BitString, error)
}

func compactBitCaseFor[T any](name, source, path string, maximum int, codec interface {
	EncodeBER(T, ...ber.EncodeOption) ([]byte, error)
	EncodeDER(T) ([]byte, error)
}, wrap func(runtime.BitString) T, build func(...int) (runtime.BitString, error)) compactBitCase {
	return compactBitCase{name, source, path, maximum, func(v runtime.BitString, o ...ber.EncodeOption) ([]byte, error) {
		return codec.EncodeBER(wrap(v), o...)
	}, func(v runtime.BitString) ([]byte, error) { return codec.EncodeDER(wrap(v)) }, build}
}
func TestCompactNamedBitRefusalLocations(t *testing.T) {
	for _, tc := range []compactBitCase{
		compactBitCaseFor("v21_map_lcs_datatypes.LCSDeferredLocationEventType", "MAP-LCS-DataTypes.DeferredLocationEventType", "DeferredLocationEventType", 16, v21_map_lcs_datatypes.LCSDeferredLocationEventTypeCodec(), func(v runtime.BitString) v21_map_lcs_datatypes.BERValue[v21_map_lcs_datatypes.LCSDeferredLocationEventType] {
			return v21_map_lcs_datatypes.BERValue[v21_map_lcs_datatypes.LCSDeferredLocationEventType]{Value: v}
		}, v21_map_lcs_datatypes.NewLCSDeferredLocationEventType),
		compactBitCaseFor("v21_map_lcs_datatypes.LCSSupportedGADShapes", "MAP-LCS-DataTypes.SupportedGADShapes", "SupportedGADShapes", 16, v21_map_lcs_datatypes.LCSSupportedGADShapesCodec(), func(v runtime.BitString) v21_map_lcs_datatypes.BERValue[v21_map_lcs_datatypes.LCSSupportedGADShapes] {
			return v21_map_lcs_datatypes.BERValue[v21_map_lcs_datatypes.LCSSupportedGADShapes]{Value: v}
		}, v21_map_lcs_datatypes.NewLCSSupportedGADShapes),
		compactBitCaseFor("v21_map_ms_datatypes.MSSupportedRATTypes", "MAP-MS-DataTypes.SupportedRAT-Types", "SupportedRAT-Types", 8, v21_map_ms_datatypes.MSSupportedRATTypesCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedRATTypes] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedRATTypes]{Value: v}
		}, v21_map_ms_datatypes.NewMSSupportedRATTypes),
		compactBitCaseFor("v21_map_ms_datatypes.MSSupportedLCSCapabilitySets", "MAP-MS-DataTypes.SupportedLCS-CapabilitySets", "SupportedLCS-CapabilitySets", 16, v21_map_ms_datatypes.MSSupportedLCSCapabilitySetsCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedLCSCapabilitySets] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedLCSCapabilitySets]{Value: v}
		}, v21_map_ms_datatypes.NewMSSupportedLCSCapabilitySets),
		compactBitCaseFor("v21_map_ms_datatypes.MSISRInformation", "MAP-MS-DataTypes.ISR-Information", "ISR-Information", 8, v21_map_ms_datatypes.MSISRInformationCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSISRInformation] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSISRInformation]{Value: v}
		}, v21_map_ms_datatypes.NewMSISRInformation),
		compactBitCaseFor("v21_map_ms_datatypes.MSSupportedFeatures", "MAP-MS-DataTypes.SupportedFeatures", "SupportedFeatures", 40, v21_map_ms_datatypes.MSSupportedFeaturesCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedFeatures] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedFeatures]{Value: v}
		}, v21_map_ms_datatypes.NewMSSupportedFeatures),
		compactBitCaseFor("v21_map_ms_datatypes.MSExtSupportedFeatures", "MAP-MS-DataTypes.Ext-SupportedFeatures", "Ext-SupportedFeatures", 40, v21_map_ms_datatypes.MSExtSupportedFeaturesCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSExtSupportedFeatures] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSExtSupportedFeatures]{Value: v}
		}, v21_map_ms_datatypes.NewMSExtSupportedFeatures),
		compactBitCaseFor("v21_map_ms_datatypes.MSLCLSNegotiation", "MAP-MS-DataTypes.LCLS-Negotiation", "LCLS-Negotiation", 8, v21_map_ms_datatypes.MSLCLSNegotiationCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSLCLSNegotiation] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSLCLSNegotiation]{Value: v}
		}, v21_map_ms_datatypes.NewMSLCLSNegotiation),
		compactBitCaseFor("v21_map_ms_datatypes.MSLCLSConfigurationPreference", "MAP-MS-DataTypes.LCLS-ConfigurationPreference", "LCLS-ConfigurationPreference", 8, v21_map_ms_datatypes.MSLCLSConfigurationPreferenceCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSLCLSConfigurationPreference] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSLCLSConfigurationPreference]{Value: v}
		}, v21_map_ms_datatypes.NewMSLCLSConfigurationPreference),
		compactBitCaseFor("v21_map_ms_datatypes.MSRequestedEquipmentInfo", "MAP-MS-DataTypes.RequestedEquipmentInfo", "RequestedEquipmentInfo", 8, v21_map_ms_datatypes.MSRequestedEquipmentInfoCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSRequestedEquipmentInfo] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSRequestedEquipmentInfo]{Value: v}
		}, v21_map_ms_datatypes.NewMSRequestedEquipmentInfo),
		compactBitCaseFor("v21_map_ms_datatypes.MSAccessRestrictionData", "MAP-MS-DataTypes.AccessRestrictionData", "AccessRestrictionData", 8, v21_map_ms_datatypes.MSAccessRestrictionDataCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSAccessRestrictionData] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSAccessRestrictionData]{Value: v}
		}, v21_map_ms_datatypes.NewMSAccessRestrictionData),
		compactBitCaseFor("v21_map_ms_datatypes.MSExtAccessRestrictionData", "MAP-MS-DataTypes.Ext-AccessRestrictionData", "Ext-AccessRestrictionData", 32, v21_map_ms_datatypes.MSExtAccessRestrictionDataCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSExtAccessRestrictionData] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSExtAccessRestrictionData]{Value: v}
		}, v21_map_ms_datatypes.NewMSExtAccessRestrictionData),
		compactBitCaseFor("v21_map_ms_datatypes.MSODBGeneralData", "MAP-MS-DataTypes.ODB-GeneralData", "ODB-GeneralData", 32, v21_map_ms_datatypes.MSODBGeneralDataCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSODBGeneralData] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSODBGeneralData]{Value: v}
		}, v21_map_ms_datatypes.NewMSODBGeneralData),
		compactBitCaseFor("v21_map_ms_datatypes.MSODBHPLMNData", "MAP-MS-DataTypes.ODB-HPLMN-Data", "ODB-HPLMN-Data", 32, v21_map_ms_datatypes.MSODBHPLMNDataCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSODBHPLMNData] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSODBHPLMNData]{Value: v}
		}, v21_map_ms_datatypes.NewMSODBHPLMNData),
		compactBitCaseFor("v21_map_ms_datatypes.MSSpecificCSIWithdraw", "MAP-MS-DataTypes.SpecificCSI-Withdraw", "SpecificCSI-Withdraw", 32, v21_map_ms_datatypes.MSSpecificCSIWithdrawCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSpecificCSIWithdraw] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSpecificCSIWithdraw]{Value: v}
		}, v21_map_ms_datatypes.NewMSSpecificCSIWithdraw),
		compactBitCaseFor("v21_map_ms_datatypes.MSSupportedCamelPhases", "MAP-MS-DataTypes.SupportedCamelPhases", "SupportedCamelPhases", 16, v21_map_ms_datatypes.MSSupportedCamelPhasesCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedCamelPhases] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSSupportedCamelPhases]{Value: v}
		}, v21_map_ms_datatypes.NewMSSupportedCamelPhases),
		compactBitCaseFor("v21_map_ms_datatypes.MSOfferedCamel4CSIs", "MAP-MS-DataTypes.OfferedCamel4CSIs", "OfferedCamel4CSIs", 16, v21_map_ms_datatypes.MSOfferedCamel4CSIsCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSOfferedCamel4CSIs] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSOfferedCamel4CSIs]{Value: v}
		}, v21_map_ms_datatypes.NewMSOfferedCamel4CSIs),
		compactBitCaseFor("v21_map_ms_datatypes.MSOfferedCamel4Functionalities", "MAP-MS-DataTypes.OfferedCamel4Functionalities", "OfferedCamel4Functionalities", 64, v21_map_ms_datatypes.MSOfferedCamel4FunctionalitiesCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSOfferedCamel4Functionalities] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSOfferedCamel4Functionalities]{Value: v}
		}, v21_map_ms_datatypes.NewMSOfferedCamel4Functionalities),
		compactBitCaseFor("v21_map_ms_datatypes.MSAdditionalSubscriptions", "MAP-MS-DataTypes.AdditionalSubscriptions", "AdditionalSubscriptions", 8, v21_map_ms_datatypes.MSAdditionalSubscriptionsCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSAdditionalSubscriptions] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSAdditionalSubscriptions]{Value: v}
		}, v21_map_ms_datatypes.NewMSAdditionalSubscriptions),
		compactBitCaseFor("v21_map_ms_datatypes.MSRequestedNodes", "MAP-MS-DataTypes.RequestedNodes", "RequestedNodes", 8, v21_map_ms_datatypes.MSRequestedNodesCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSRequestedNodes] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSRequestedNodes]{Value: v}
		}, v21_map_ms_datatypes.NewMSRequestedNodes),
		compactBitCaseFor("v21_map_ms_datatypes.MSRequestedServingNode", "MAP-MS-DataTypes.RequestedServingNode", "RequestedServingNode", 8, v21_map_ms_datatypes.MSRequestedServingNodeCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSRequestedServingNode] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSRequestedServingNode]{Value: v}
		}, v21_map_ms_datatypes.NewMSRequestedServingNode),
		compactBitCaseFor("v21_map_ms_datatypes.MSServingNode", "MAP-MS-DataTypes.ServingNode", "ServingNode", 8, v21_map_ms_datatypes.MSServingNodeCodec(), func(v runtime.BitString) v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSServingNode] {
			return v21_map_ms_datatypes.BERValue[v21_map_ms_datatypes.MSServingNode]{Value: v}
		}, v21_map_ms_datatypes.NewMSServingNode),
		compactBitCaseFor("v21_map_om_datatypes.OMTraceNETypeList", "MAP-OM-DataTypes.TraceNE-TypeList", "TraceNE-TypeList", 16, v21_map_om_datatypes.OMTraceNETypeListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMTraceNETypeList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMTraceNETypeList]{Value: v}
		}, v21_map_om_datatypes.NewOMTraceNETypeList),
		compactBitCaseFor("v21_map_om_datatypes.OMMSCSInterfaceList", "MAP-OM-DataTypes.MSC-S-InterfaceList", "MSC-S-InterfaceList", 16, v21_map_om_datatypes.OMMSCSInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMSCSInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMSCSInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMMSCSInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMMGWInterfaceList", "MAP-OM-DataTypes.MGW-InterfaceList", "MGW-InterfaceList", 8, v21_map_om_datatypes.OMMGWInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMGWInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMGWInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMMGWInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMSGSNInterfaceList", "MAP-OM-DataTypes.SGSN-InterfaceList", "SGSN-InterfaceList", 16, v21_map_om_datatypes.OMSGSNInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGSNInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGSNInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMSGSNInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMGGSNInterfaceList", "MAP-OM-DataTypes.GGSN-InterfaceList", "GGSN-InterfaceList", 8, v21_map_om_datatypes.OMGGSNInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMGGSNInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMGGSNInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMGGSNInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMRNCInterfaceList", "MAP-OM-DataTypes.RNC-InterfaceList", "RNC-InterfaceList", 8, v21_map_om_datatypes.OMRNCInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMRNCInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMRNCInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMRNCInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMBMSCInterfaceList", "MAP-OM-DataTypes.BMSC-InterfaceList", "BMSC-InterfaceList", 8, v21_map_om_datatypes.OMBMSCInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMBMSCInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMBMSCInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMBMSCInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMMMEInterfaceList", "MAP-OM-DataTypes.MME-InterfaceList", "MME-InterfaceList", 8, v21_map_om_datatypes.OMMMEInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMMEInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMMEInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMMMEInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMSGWInterfaceList", "MAP-OM-DataTypes.SGW-InterfaceList", "SGW-InterfaceList", 8, v21_map_om_datatypes.OMSGWInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGWInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGWInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMSGWInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMPGWInterfaceList", "MAP-OM-DataTypes.PGW-InterfaceList", "PGW-InterfaceList", 16, v21_map_om_datatypes.OMPGWInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMPGWInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMPGWInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMPGWInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMENBInterfaceList", "MAP-OM-DataTypes.ENB-InterfaceList", "ENB-InterfaceList", 8, v21_map_om_datatypes.OMENBInterfaceListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMENBInterfaceList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMENBInterfaceList]{Value: v}
		}, v21_map_om_datatypes.NewOMENBInterfaceList),
		compactBitCaseFor("v21_map_om_datatypes.OMMSCSEventList", "MAP-OM-DataTypes.MSC-S-EventList", "MSC-S-EventList", 16, v21_map_om_datatypes.OMMSCSEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMSCSEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMSCSEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMMSCSEventList),
		compactBitCaseFor("v21_map_om_datatypes.OMMGWEventList", "MAP-OM-DataTypes.MGW-EventList", "MGW-EventList", 8, v21_map_om_datatypes.OMMGWEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMGWEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMGWEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMMGWEventList),
		compactBitCaseFor("v21_map_om_datatypes.OMSGSNEventList", "MAP-OM-DataTypes.SGSN-EventList", "SGSN-EventList", 16, v21_map_om_datatypes.OMSGSNEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGSNEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGSNEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMSGSNEventList),
		compactBitCaseFor("v21_map_om_datatypes.OMGGSNEventList", "MAP-OM-DataTypes.GGSN-EventList", "GGSN-EventList", 8, v21_map_om_datatypes.OMGGSNEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMGGSNEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMGGSNEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMGGSNEventList),
		compactBitCaseFor("v21_map_om_datatypes.OMBMSCEventList", "MAP-OM-DataTypes.BMSC-EventList", "BMSC-EventList", 8, v21_map_om_datatypes.OMBMSCEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMBMSCEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMBMSCEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMBMSCEventList),
		compactBitCaseFor("v21_map_om_datatypes.OMMMEEventList", "MAP-OM-DataTypes.MME-EventList", "MME-EventList", 8, v21_map_om_datatypes.OMMMEEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMMEEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMMMEEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMMMEEventList),
		compactBitCaseFor("v21_map_om_datatypes.OMSGWEventList", "MAP-OM-DataTypes.SGW-EventList", "SGW-EventList", 8, v21_map_om_datatypes.OMSGWEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGWEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMSGWEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMSGWEventList),
		compactBitCaseFor("v21_map_om_datatypes.OMPGWEventList", "MAP-OM-DataTypes.PGW-EventList", "PGW-EventList", 8, v21_map_om_datatypes.OMPGWEventListCodec(), func(v runtime.BitString) v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMPGWEventList] {
			return v21_map_om_datatypes.BERValue[v21_map_om_datatypes.OMPGWEventList]{Value: v}
		}, v21_map_om_datatypes.NewOMPGWEventList),
		compactBitCaseFor("v21_map_sm_datatypes.SMMWStatus", "MAP-SM-DataTypes.MW-Status", "MW-Status", 16, v21_map_sm_datatypes.SMMWStatusCodec(), func(v runtime.BitString) v21_map_sm_datatypes.BERValue[v21_map_sm_datatypes.SMMWStatus] {
			return v21_map_sm_datatypes.BERValue[v21_map_sm_datatypes.SMMWStatus]{Value: v}
		}, v21_map_sm_datatypes.NewSMMWStatus),
		compactBitCaseFor("v21_map_ss_datatypes.SSServiceIndicator", "MAP-SS-DataTypes.ServiceIndicator", "ServiceIndicator", 32, v21_map_ss_datatypes.SSServiceIndicatorCodec(), func(v runtime.BitString) v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSServiceIndicator] {
			return v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSServiceIndicator]{Value: v}
		}, v21_map_ss_datatypes.NewSSServiceIndicator),
		compactBitCaseFor("ServiceIndicator", "MAP-SS-DataTypes.ServiceIndicator", "ServiceIndicator", 32, mapvalues.ServiceIndicatorCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ServiceIndicator] {
			return mapvalues.BERValue[mapvalues.ServiceIndicator]{Value: v}
		}, mapvalues.NewServiceIndicator),
		compactBitCaseFor("TraceNETypeList", "MAP-OM-DataTypes.TraceNE-TypeList", "TraceNE-TypeList", 16, mapvalues.TraceNETypeListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.TraceNETypeList] {
			return mapvalues.BERValue[mapvalues.TraceNETypeList]{Value: v}
		}, mapvalues.NewTraceNETypeList),
		compactBitCaseFor("MSCSInterfaceList", "MAP-OM-DataTypes.MSC-S-InterfaceList", "MSC-S-InterfaceList", 16, mapvalues.MSCSInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.MSCSInterfaceList] {
			return mapvalues.BERValue[mapvalues.MSCSInterfaceList]{Value: v}
		}, mapvalues.NewMSCSInterfaceList),
		compactBitCaseFor("MGWInterfaceList", "MAP-OM-DataTypes.MGW-InterfaceList", "MGW-InterfaceList", 8, mapvalues.MGWInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.MGWInterfaceList] {
			return mapvalues.BERValue[mapvalues.MGWInterfaceList]{Value: v}
		}, mapvalues.NewMGWInterfaceList),
		compactBitCaseFor("SGSNInterfaceList", "MAP-OM-DataTypes.SGSN-InterfaceList", "SGSN-InterfaceList", 16, mapvalues.SGSNInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SGSNInterfaceList] {
			return mapvalues.BERValue[mapvalues.SGSNInterfaceList]{Value: v}
		}, mapvalues.NewSGSNInterfaceList),
		compactBitCaseFor("GGSNInterfaceList", "MAP-OM-DataTypes.GGSN-InterfaceList", "GGSN-InterfaceList", 8, mapvalues.GGSNInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.GGSNInterfaceList] {
			return mapvalues.BERValue[mapvalues.GGSNInterfaceList]{Value: v}
		}, mapvalues.NewGGSNInterfaceList),
		compactBitCaseFor("RNCInterfaceList", "MAP-OM-DataTypes.RNC-InterfaceList", "RNC-InterfaceList", 8, mapvalues.RNCInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.RNCInterfaceList] {
			return mapvalues.BERValue[mapvalues.RNCInterfaceList]{Value: v}
		}, mapvalues.NewRNCInterfaceList),
		compactBitCaseFor("BMSCInterfaceList", "MAP-OM-DataTypes.BMSC-InterfaceList", "BMSC-InterfaceList", 8, mapvalues.BMSCInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.BMSCInterfaceList] {
			return mapvalues.BERValue[mapvalues.BMSCInterfaceList]{Value: v}
		}, mapvalues.NewBMSCInterfaceList),
		compactBitCaseFor("MMEInterfaceList", "MAP-OM-DataTypes.MME-InterfaceList", "MME-InterfaceList", 8, mapvalues.MMEInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.MMEInterfaceList] {
			return mapvalues.BERValue[mapvalues.MMEInterfaceList]{Value: v}
		}, mapvalues.NewMMEInterfaceList),
		compactBitCaseFor("SGWInterfaceList", "MAP-OM-DataTypes.SGW-InterfaceList", "SGW-InterfaceList", 8, mapvalues.SGWInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SGWInterfaceList] {
			return mapvalues.BERValue[mapvalues.SGWInterfaceList]{Value: v}
		}, mapvalues.NewSGWInterfaceList),
		compactBitCaseFor("PGWInterfaceList", "MAP-OM-DataTypes.PGW-InterfaceList", "PGW-InterfaceList", 16, mapvalues.PGWInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.PGWInterfaceList] {
			return mapvalues.BERValue[mapvalues.PGWInterfaceList]{Value: v}
		}, mapvalues.NewPGWInterfaceList),
		compactBitCaseFor("ENBInterfaceList", "MAP-OM-DataTypes.ENB-InterfaceList", "ENB-InterfaceList", 8, mapvalues.ENBInterfaceListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ENBInterfaceList] {
			return mapvalues.BERValue[mapvalues.ENBInterfaceList]{Value: v}
		}, mapvalues.NewENBInterfaceList),
		compactBitCaseFor("MSCSEventList", "MAP-OM-DataTypes.MSC-S-EventList", "MSC-S-EventList", 16, mapvalues.MSCSEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.MSCSEventList] {
			return mapvalues.BERValue[mapvalues.MSCSEventList]{Value: v}
		}, mapvalues.NewMSCSEventList),
		compactBitCaseFor("MGWEventList", "MAP-OM-DataTypes.MGW-EventList", "MGW-EventList", 8, mapvalues.MGWEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.MGWEventList] {
			return mapvalues.BERValue[mapvalues.MGWEventList]{Value: v}
		}, mapvalues.NewMGWEventList),
		compactBitCaseFor("SGSNEventList", "MAP-OM-DataTypes.SGSN-EventList", "SGSN-EventList", 16, mapvalues.SGSNEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SGSNEventList] {
			return mapvalues.BERValue[mapvalues.SGSNEventList]{Value: v}
		}, mapvalues.NewSGSNEventList),
		compactBitCaseFor("GGSNEventList", "MAP-OM-DataTypes.GGSN-EventList", "GGSN-EventList", 8, mapvalues.GGSNEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.GGSNEventList] {
			return mapvalues.BERValue[mapvalues.GGSNEventList]{Value: v}
		}, mapvalues.NewGGSNEventList),
		compactBitCaseFor("BMSCEventList", "MAP-OM-DataTypes.BMSC-EventList", "BMSC-EventList", 8, mapvalues.BMSCEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.BMSCEventList] {
			return mapvalues.BERValue[mapvalues.BMSCEventList]{Value: v}
		}, mapvalues.NewBMSCEventList),
		compactBitCaseFor("MMEEventList", "MAP-OM-DataTypes.MME-EventList", "MME-EventList", 8, mapvalues.MMEEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.MMEEventList] {
			return mapvalues.BERValue[mapvalues.MMEEventList]{Value: v}
		}, mapvalues.NewMMEEventList),
		compactBitCaseFor("SGWEventList", "MAP-OM-DataTypes.SGW-EventList", "SGW-EventList", 8, mapvalues.SGWEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SGWEventList] {
			return mapvalues.BERValue[mapvalues.SGWEventList]{Value: v}
		}, mapvalues.NewSGWEventList),
		compactBitCaseFor("PGWEventList", "MAP-OM-DataTypes.PGW-EventList", "PGW-EventList", 8, mapvalues.PGWEventListCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.PGWEventList] {
			return mapvalues.BERValue[mapvalues.PGWEventList]{Value: v}
		}, mapvalues.NewPGWEventList),
		compactBitCaseFor("SupportedRATTypes", "MAP-MS-DataTypes.SupportedRAT-Types", "SupportedRAT-Types", 8, mapvalues.SupportedRATTypesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SupportedRATTypes] {
			return mapvalues.BERValue[mapvalues.SupportedRATTypes]{Value: v}
		}, mapvalues.NewSupportedRATTypes),
		compactBitCaseFor("SupportedLCSCapabilitySets", "MAP-MS-DataTypes.SupportedLCS-CapabilitySets", "SupportedLCS-CapabilitySets", 16, mapvalues.SupportedLCSCapabilitySetsCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SupportedLCSCapabilitySets] {
			return mapvalues.BERValue[mapvalues.SupportedLCSCapabilitySets]{Value: v}
		}, mapvalues.NewSupportedLCSCapabilitySets),
		compactBitCaseFor("ISRInformation", "MAP-MS-DataTypes.ISR-Information", "ISR-Information", 8, mapvalues.ISRInformationCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ISRInformation] {
			return mapvalues.BERValue[mapvalues.ISRInformation]{Value: v}
		}, mapvalues.NewISRInformation),
		compactBitCaseFor("SupportedFeatures", "MAP-MS-DataTypes.SupportedFeatures", "SupportedFeatures", 40, mapvalues.SupportedFeaturesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SupportedFeatures] {
			return mapvalues.BERValue[mapvalues.SupportedFeatures]{Value: v}
		}, mapvalues.NewSupportedFeatures),
		compactBitCaseFor("ExtSupportedFeatures", "MAP-MS-DataTypes.Ext-SupportedFeatures", "Ext-SupportedFeatures", 40, mapvalues.ExtSupportedFeaturesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ExtSupportedFeatures] {
			return mapvalues.BERValue[mapvalues.ExtSupportedFeatures]{Value: v}
		}, mapvalues.NewExtSupportedFeatures),
		compactBitCaseFor("LCLSNegotiation", "MAP-MS-DataTypes.LCLS-Negotiation", "LCLS-Negotiation", 8, mapvalues.LCLSNegotiationCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.LCLSNegotiation] {
			return mapvalues.BERValue[mapvalues.LCLSNegotiation]{Value: v}
		}, mapvalues.NewLCLSNegotiation),
		compactBitCaseFor("LCLSConfigurationPreference", "MAP-MS-DataTypes.LCLS-ConfigurationPreference", "LCLS-ConfigurationPreference", 8, mapvalues.LCLSConfigurationPreferenceCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.LCLSConfigurationPreference] {
			return mapvalues.BERValue[mapvalues.LCLSConfigurationPreference]{Value: v}
		}, mapvalues.NewLCLSConfigurationPreference),
		compactBitCaseFor("RequestedEquipmentInfo", "MAP-MS-DataTypes.RequestedEquipmentInfo", "RequestedEquipmentInfo", 8, mapvalues.RequestedEquipmentInfoCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.RequestedEquipmentInfo] {
			return mapvalues.BERValue[mapvalues.RequestedEquipmentInfo]{Value: v}
		}, mapvalues.NewRequestedEquipmentInfo),
		compactBitCaseFor("AccessRestrictionData", "MAP-MS-DataTypes.AccessRestrictionData", "AccessRestrictionData", 8, mapvalues.AccessRestrictionDataCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.AccessRestrictionData] {
			return mapvalues.BERValue[mapvalues.AccessRestrictionData]{Value: v}
		}, mapvalues.NewAccessRestrictionData),
		compactBitCaseFor("ExtAccessRestrictionData", "MAP-MS-DataTypes.Ext-AccessRestrictionData", "Ext-AccessRestrictionData", 32, mapvalues.ExtAccessRestrictionDataCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ExtAccessRestrictionData] {
			return mapvalues.BERValue[mapvalues.ExtAccessRestrictionData]{Value: v}
		}, mapvalues.NewExtAccessRestrictionData),
		compactBitCaseFor("ODBGeneralData", "MAP-MS-DataTypes.ODB-GeneralData", "ODB-GeneralData", 32, mapvalues.ODBGeneralDataCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ODBGeneralData] {
			return mapvalues.BERValue[mapvalues.ODBGeneralData]{Value: v}
		}, mapvalues.NewODBGeneralData),
		compactBitCaseFor("ODBHPLMNData", "MAP-MS-DataTypes.ODB-HPLMN-Data", "ODB-HPLMN-Data", 32, mapvalues.ODBHPLMNDataCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ODBHPLMNData] {
			return mapvalues.BERValue[mapvalues.ODBHPLMNData]{Value: v}
		}, mapvalues.NewODBHPLMNData),
		compactBitCaseFor("SpecificCSIWithdraw", "MAP-MS-DataTypes.SpecificCSI-Withdraw", "SpecificCSI-Withdraw", 32, mapvalues.SpecificCSIWithdrawCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SpecificCSIWithdraw] {
			return mapvalues.BERValue[mapvalues.SpecificCSIWithdraw]{Value: v}
		}, mapvalues.NewSpecificCSIWithdraw),
		compactBitCaseFor("SupportedCamelPhases", "MAP-MS-DataTypes.SupportedCamelPhases", "SupportedCamelPhases", 16, mapvalues.SupportedCamelPhasesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SupportedCamelPhases] {
			return mapvalues.BERValue[mapvalues.SupportedCamelPhases]{Value: v}
		}, mapvalues.NewSupportedCamelPhases),
		compactBitCaseFor("OfferedCamel4CSIs", "MAP-MS-DataTypes.OfferedCamel4CSIs", "OfferedCamel4CSIs", 16, mapvalues.OfferedCamel4CSIsCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.OfferedCamel4CSIs] {
			return mapvalues.BERValue[mapvalues.OfferedCamel4CSIs]{Value: v}
		}, mapvalues.NewOfferedCamel4CSIs),
		compactBitCaseFor("OfferedCamel4Functionalities", "MAP-MS-DataTypes.OfferedCamel4Functionalities", "OfferedCamel4Functionalities", 64, mapvalues.OfferedCamel4FunctionalitiesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.OfferedCamel4Functionalities] {
			return mapvalues.BERValue[mapvalues.OfferedCamel4Functionalities]{Value: v}
		}, mapvalues.NewOfferedCamel4Functionalities),
		compactBitCaseFor("AdditionalSubscriptions", "MAP-MS-DataTypes.AdditionalSubscriptions", "AdditionalSubscriptions", 8, mapvalues.AdditionalSubscriptionsCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.AdditionalSubscriptions] {
			return mapvalues.BERValue[mapvalues.AdditionalSubscriptions]{Value: v}
		}, mapvalues.NewAdditionalSubscriptions),
		compactBitCaseFor("RequestedNodes", "MAP-MS-DataTypes.RequestedNodes", "RequestedNodes", 8, mapvalues.RequestedNodesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.RequestedNodes] {
			return mapvalues.BERValue[mapvalues.RequestedNodes]{Value: v}
		}, mapvalues.NewRequestedNodes),
		compactBitCaseFor("RequestedServingNode", "MAP-MS-DataTypes.RequestedServingNode", "RequestedServingNode", 8, mapvalues.RequestedServingNodeCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.RequestedServingNode] {
			return mapvalues.BERValue[mapvalues.RequestedServingNode]{Value: v}
		}, mapvalues.NewRequestedServingNode),
		compactBitCaseFor("ServingNode", "MAP-MS-DataTypes.ServingNode", "ServingNode", 8, mapvalues.ServingNodeCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ServingNode] {
			return mapvalues.BERValue[mapvalues.ServingNode]{Value: v}
		}, mapvalues.NewServingNode),
		compactBitCaseFor("SuppressMTSS", "MAP-CH-DataTypes.SuppressMTSS", "SuppressMTSS", 16, mapvalues.SuppressMTSSCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SuppressMTSS] {
			return mapvalues.BERValue[mapvalues.SuppressMTSS]{Value: v}
		}, mapvalues.NewSuppressMTSS),
		compactBitCaseFor("AllowedServices", "MAP-CH-DataTypes.AllowedServices", "AllowedServices", 8, mapvalues.AllowedServicesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.AllowedServices] {
			return mapvalues.BERValue[mapvalues.AllowedServices]{Value: v}
		}, mapvalues.NewAllowedServices),
		compactBitCaseFor("MWStatus", "MAP-SM-DataTypes.MW-Status", "MW-Status", 16, mapvalues.MWStatusCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.MWStatus] {
			return mapvalues.BERValue[mapvalues.MWStatus]{Value: v}
		}, mapvalues.NewMWStatus),
		compactBitCaseFor("DeferredLocationEventType", "MAP-LCS-DataTypes.DeferredLocationEventType", "DeferredLocationEventType", 16, mapvalues.DeferredLocationEventTypeCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.DeferredLocationEventType] {
			return mapvalues.BERValue[mapvalues.DeferredLocationEventType]{Value: v}
		}, mapvalues.NewDeferredLocationEventType),
		compactBitCaseFor("SupportedGADShapes", "MAP-LCS-DataTypes.SupportedGADShapes", "SupportedGADShapes", 16, mapvalues.SupportedGADShapesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.SupportedGADShapes] {
			return mapvalues.BERValue[mapvalues.SupportedGADShapes]{Value: v}
		}, mapvalues.NewSupportedGADShapes),
		compactBitCaseFor("DeferredLocationExt", "SS-DataTypes.DeferredLocationExt", "DeferredLocationExt", 16, mapvalues.DeferredLocationExtCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.DeferredLocationExt] {
			return mapvalues.BERValue[mapvalues.DeferredLocationExt]{Value: v}
		}, mapvalues.NewDeferredLocationExt),
		compactBitCaseFor("RangingSlExt", "SS-DataTypes.RangingSlExt", "RangingSlExt", 16, mapvalues.RangingSlExtCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.RangingSlExt] {
			return mapvalues.BERValue[mapvalues.RangingSlExt]{Value: v}
		}, mapvalues.NewRangingSlExt),
		compactBitCaseFor("LocationInfo", "SS-DataTypes.LocationInfo", "LocationInfo", 32, mapvalues.LocationInfoCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.LocationInfo] {
			return mapvalues.BERValue[mapvalues.LocationInfo]{Value: v}
		}, mapvalues.NewLocationInfo),
		compactBitCaseFor("ReportingAccessTypes", "SS-DataTypes.ReportingAccessTypes", "ReportingAccessTypes", 16, mapvalues.ReportingAccessTypesCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.ReportingAccessTypes] {
			return mapvalues.BERValue[mapvalues.ReportingAccessTypes]{Value: v}
		}, mapvalues.NewReportingAccessTypes),
		compactBitCaseFor("LCSPruUpdateTrigger", "SS-DataTypes.LCS-PruUpdateTrigger", "LCS-PruUpdateTrigger", 16, mapvalues.LCSPruUpdateTriggerCodec(), func(v runtime.BitString) mapvalues.BERValue[mapvalues.LCSPruUpdateTrigger] {
			return mapvalues.BERValue[mapvalues.LCSPruUpdateTrigger]{Value: v}
		}, mapvalues.NewLCSPruUpdateTrigger),
	} {
		t.Run(tc.name, func(t *testing.T) {
			bits := runtime.BitString{Bytes: make([]byte, (tc.maximum+8)/8), BitLength: tc.maximum + 1}
			bits.Bytes[tc.maximum/8] = byte(0x80 >> uint(tc.maximum%8))
			var log ber.ViolationLog
			if _, err := tc.encode(bits, ber.WithTolerance(&log)); err != nil {
				t.Fatal(err)
			}
			records := log.Snapshot()
			if len(records) != 1 {
				t.Fatalf("records=%+v", records)
			}
			want := records[0]
			if want.Source != tc.source || want.Path != tc.path {
				t.Fatalf("tolerant=%+v", want)
			}
			for _, mode := range []struct {
				name   string
				encode func() ([]byte, error)
			}{
				{"BER", func() ([]byte, error) { return tc.encode(bits) }},
				{"fresh", func() ([]byte, error) { return tc.encode(bits, ber.WithoutBERReplay()) }},
				{"DER", func() ([]byte, error) { return tc.der(bits) }},
				{"builder", func() ([]byte, error) { _, err := tc.build(tc.maximum); return nil, err }},
			} {
				t.Run(mode.name, func(t *testing.T) {
					_, err := mode.encode()
					ve, ok := err.(*ber.ValidationError)
					if !ok || !reflect.DeepEqual(ve.Violation, want) {
						t.Fatalf("refusal %T %+v; tolerant %+v", err, err, want)
					}
				})
			}
		})
	}
}

func TestAliasedOpaqueEncodeRecords(t *testing.T) {
	shared := []byte{12, 1, 255}
	raw := &runtime.RawValue{Class: 0, Tag: 12, Bytes: shared}
	oid := runtime.MustObjectIdentifierFromArcs(1, 2, 3)
	for _, tc := range []struct {
		name  string
		value interface {
			MarshalBER(...ber.EncodeOption) ([]byte, error)
			MarshalDER() ([]byte, error)
		}
		paths []string
	}{
		{"shared additions", &mapvalues.PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{shared, shared}}, []string{"child[2]", "child[3]"}},
		{"copied additions", &mapvalues.PDPContextInfo{PdpContextIdentifier: 1, PdpType: []byte{0xf1, 0x21}, ExtData_: [][]byte{{12, 1, 255}, {12, 1, 255}}}, []string{"child[2]", "child[3]"}},
		{"shared opens", &mapvalues.ExtensionContainer{PrivateExtensionList: &mapvalues.PrivateExtensionList{Values: []mapvalues.PrivateExtension{{ExtId: oid, ExtType: raw}, {ExtId: oid, ExtType: raw}}}}, []string{"privateExtensionList.element[0].extType", "privateExtensionList.element[1].extType"}},
		{"copied opens", &mapvalues.ExtensionContainer{PrivateExtensionList: &mapvalues.PrivateExtensionList{Values: []mapvalues.PrivateExtension{{ExtId: oid, ExtType: &runtime.RawValue{Tag: 12, Bytes: []byte{12, 1, 255}}}, {ExtId: oid, ExtType: &runtime.RawValue{Tag: 12, Bytes: []byte{12, 1, 255}}}}}}, []string{"privateExtensionList.element[0].extType", "privateExtensionList.element[1].extType"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log ber.ViolationLog
			wire, err := tc.value.MarshalBER(ber.WithTolerance(&log))
			if err != nil {
				t.Fatal(err)
			}
			records := log.Snapshot()
			var paths []string
			for _, record := range records {
				paths = append(paths, record.Path)
				if record.Offset != nil || record.OctetOffset != nil || record.ChildIndexes != nil {
					t.Fatalf("encode coordinates=%+v", record)
				}
			}
			if !reflect.DeepEqual(paths, tc.paths) {
				t.Fatalf("paths=%v want %v", paths, tc.paths)
			}
			// Decode uses received octets and keeps both findings; replay is exact.
			var decoded interface {
				UnmarshalBER([]byte, ...ber.DecodeOption) error
				MarshalBER(...ber.EncodeOption) ([]byte, error)
			}
			switch tc.value.(type) {
			case *mapvalues.PDPContextInfo:
				decoded = &mapvalues.PDPContextInfo{}
			default:
				decoded = &mapvalues.ExtensionContainer{}
			}
			var dlog, rlog ber.ViolationLog
			if err := decoded.UnmarshalBER(wire, ber.WithTolerance(&dlog)); err != nil {
				t.Fatal(err)
			}
			again, err := decoded.MarshalBER(ber.WithTolerance(&rlog))
			if err != nil || !bytes.Equal(wire, again) || len(dlog.Snapshot()) != 2 || len(rlog.Snapshot()) != 2 {
				t.Fatalf("replay=%v decode=%+v encode=%+v", err, dlog.Snapshot(), rlog.Snapshot())
			}
			for _, encode := range []func() ([]byte, error){func() ([]byte, error) { return tc.value.MarshalBER() }, func() ([]byte, error) { return tc.value.MarshalBER(ber.WithoutBERReplay()) }, tc.value.MarshalDER} {
				_, err := encode()
				ve, ok := err.(*ber.ValidationError)
				if !ok || ve.Path != tc.paths[0] {
					t.Fatalf("strict: %T %+v", err, err)
				}
			}
		})
	}
}
