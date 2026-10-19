// Code generated from MAP runtime regression contract. DO NOT EDIT.

package gsm_map

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

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
