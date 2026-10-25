// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bufio "bufio"
	bytes "bytes"
	sha256 "crypto/sha256"
	hex "encoding/hex"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	io "io"
	os "os"
	reflect "reflect"
	strings "strings"
	testing "testing"
)

type replayAllocationOps struct {
	decode func() error
	encode func() ([]byte, error)
}

func replayAllocationNeed(err error) {
	if err != nil {
		panic(err)
	}
}
func TestReplaySyntheticAllocationBounds(t *testing.T) {
	cases := []struct {
		name, kind, hex string
		decode, encode  float64
	}{
		{"wire/s1ap/envelope/s1ap/capture.pcap:1", "S1APPDU", "001240140000030000000200010008000200020002400126", 21, 1},
		{"s1ap-61-baseline", "S1APPDU", "4011000e0000020002400200000041400120", 15, 1},
		{"s1ap-61-timetowait-nonzero-padding", "S1APPDU", "4011000e000002000240020000004140012f", 15, 1},
		{"s1ap-61-cause-nonzero-padding", "S1APPDU", "4011000e0000020002400200010041400120", 15, 1},
		{"s1ap-61-mme-ue-s1ap-id-baseline", "S1APPDU", "2017000f00000200004002002a000840020007", 17, 1},
		{"s1ap-63-cause-zero-padding", "Cause", "0000", 1, 1},
		{"s1ap-63-cause-nonzero-padding", "Cause", "0005", 1, 1},
		{"ue-context-release-request-cause-nas", "S1APPDU", "001240140000030000000200010008000200020002400126", 21, 1},
		{"cause-nas-root-extension-boundary", "Cause", "26", 1, 1},
		{"erab-information-daps-extension-recursive", "ERABInformationListItem", "250000013d400100", 16, 1},
		{"erab-information-unknown-extension-preserved", "ERABInformationListItem", "250000fffc4004deadbeef", 10, 1},
		{"protocol-ie-field-constrained-header", "ProtocolIEField", "12344001aa", 2, 1},
		{"paging-tai-list-recursive", "Paging", "000001002e400b00002f40060001f0101234", 12, 1},
		{"paging-procedure-recursive", "S1APPDU", "000a4012000001002e400b00002f40060001f0101234", 16, 1},
		{"reset-acknowledge-connection-list-recursive", "ResetAcknowledge", "000001005d400900005b000460070009", 12, 1},
		{"event-trigger-empty-choice-extension-set", "EventTrigger", "80fffc4004deadbeef", 3, 1},
		{"measurement-threshold-empty-choice-extension-set", "MeasurementThresholdL1LoggedMDT", "80fffc4004deadbeef", 3, 1},
		{"sensor-name-empty-choice-extension-set", "SensorNameConfig", "80fffc4004deadbeef", 3, 1},
		{"target-transparent-container-daps-recursive", "TargeteNBToSourceeNBTransparentContainer", "4001010000013e401100013f400c4a000000fffc4004deadbeef", 20, 1},
		{"target-transparent-container-unknown-extension", "TargeteNBToSourceeNBTransparentContainer", "4001010000fffc4004deadbeef", 4, 1},
		{"target-transparent-container-direct-extension-field", "DirectExtension", "00013f400c4a000000fffc4004deadbeef", 18, 1},
		{"tai-item-direct-protocol-ie-field", "DirectIE", "0001f0101234", 8, 1},
	}
	if len(cases) != 22 {
		t.Fatalf("accepted allocation cases=%d", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatal(err)
			}
			if tc.kind == "DirectExtension" {
				raw = replayWrapPayload(raw, 318)
			}
			if tc.kind == "DirectIE" {
				raw = replayWrapPayload(raw, 47)
			}
			op := replayMakeOps(tc.kind, raw)
			if err := op.decode(); err != nil {
				if strings.Contains(tc.name, "nonzero-padding") && errors.Is(err, aper.ErrSyntax) {
					return
				}
				t.Fatal(err)
			}
			decoded := testing.AllocsPerRun(20, func() { replayAllocationNeed(op.decode()) })
			encoded := testing.AllocsPerRun(20, func() {
				wire, err := op.encode()
				replayAllocationNeed(err)
				if !bytes.Equal(wire, raw) {
					panic("replay differs")
				}
			})
			if decoded > tc.decode || encoded > tc.encode {
				t.Fatalf("allocations decode=%.0f/%.0f encode=%.0f/%.0f", decoded, tc.decode, encoded, tc.encode)
			}
		})
	}
}
func TestReplayCaptureAllocationBounds(t *testing.T) {
	file := os.Getenv("ASN1_S1AP_CAPTURE")
	if file == "" {
		t.Skip("set ASN1_S1AP_CAPTURE for private capture validation")
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	hash := sha256.New()
	scan := bufio.NewScanner(io.TeeReader(f, hash))
	scan.Buffer(make([]byte, 65536), 8<<20)
	var inputs [][]byte
	for scan.Scan() {
		var record struct {
			Hex string `json:"pdu_hex"`
		}
		if err := json.Unmarshal(scan.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		wire, err := hex.DecodeString(record.Hex)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, wire)
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 24378 {
		t.Fatalf("capture count=%d", len(inputs))
	}
	if actual := fmt.Sprintf("%x", hash.Sum(nil)); actual != "3df48606bde420ade36fbbe2bd3e43f54b72cb9d75a65325a8d65d8a4420cdee" {
		t.Fatal("capture pin differs")
	}
	decode := testing.AllocsPerRun(1, func() {
		for _, wire := range inputs {
			var v s52.S1APPDU
			_, err := v.UnmarshalAPER(wire)
			replayAllocationNeed(err)
		}
	})
	values := make([]s52.S1APPDU, len(inputs))
	for i, wire := range inputs {
		if _, err := values[i].UnmarshalAPER(wire); err != nil {
			t.Fatal(err)
		}
	}
	for i := range values {
		selectedObserve(reflect.ValueOf(&values[i]))
	}
	encode := testing.AllocsPerRun(1, func() {
		for i := range values {
			wire, err := values[i].MarshalAPER()
			replayAllocationNeed(err)
			if !bytes.Equal(wire, inputs[i]) {
				panic("capture replay differs")
			}
		}
	})
	if decode > 732736 || encode > 24378 {
		t.Fatalf("capture allocations decode=%.0f/732736 encode=%.0f/24378", decode, encode)
	}
	t.Logf("records=%d decode_allocations=%.0f encode_allocations=%.0f", len(inputs), decode, encode)
}
func replayMakeOps(kind string, raw []byte) replayAllocationOps {
	switch kind {
	case "S1APPDU":
		var v s52.S1APPDU
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s52.S1APPDU; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "Cause":
		var v s14.Cause
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s14.Cause; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "ERABInformationListItem":
		var v s29.ERABInformationListItem
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s29.ERABInformationListItem; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "Paging":
		var v s49.Paging
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s49.Paging; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "ResetAcknowledge":
		var v s44.ResetAcknowledge
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s44.ResetAcknowledge; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "EventTrigger":
		var v s19.EventTrigger
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s19.EventTrigger; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "MeasurementThresholdL1LoggedMDT":
		var v s19.MeasurementThresholdL1LoggedMDT
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s19.MeasurementThresholdL1LoggedMDT; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "SensorNameConfig":
		var v s30.SensorNameConfig
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s30.SensorNameConfig; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "TargeteNBToSourceeNBTransparentContainer":
		var v s39.TargeteNBToSourceeNBTransparentContainer
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error {
			var v s39.TargeteNBToSourceeNBTransparentContainer
			_, err := v.UnmarshalAPER(raw)
			return err
		}, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "TAIItem":
		var v s33.TAIItem
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s33.TAIItem; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "DAPSResponseInfoList":
		var v s38.DAPSResponseInfoListComplete
		_, _ = v.UnmarshalAPER(raw)
		return replayAllocationOps{decode: func() error { var v s38.DAPSResponseInfoListComplete; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}
	case "ProtocolIEField":
		c := s13.EventTriggerExtIEValueIEFieldTableCodec(s09.EventTriggerExtIEs().Table())
		v, _, _ := c.DecodeAPER(raw)
		return replayAllocationOps{decode: func() error { _, _, err := c.DecodeAPER(raw); return err }, encode: func() ([]byte, error) { return c.EncodeAPER(v) }}
	case "DirectExtension":
		c := s39.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionFieldTableCodec(s39.TargeteNBToSourceeNBTransparentContainerExtIEs().Table())
		v, _, _ := c.DecodeAPER(raw)
		return replayAllocationOps{decode: func() error { _, _, err := c.DecodeAPER(raw); return err }, encode: func() ([]byte, error) { return c.EncodeAPER(v) }}
	case "DirectIE":
		c := s33.TAIItemIEValueIEFieldTableCodec(s33.TAIItemIEs().Table())
		v, _, _ := c.DecodeAPER(raw)
		return replayAllocationOps{decode: func() error { _, _, err := c.DecodeAPER(raw); return err }, encode: func() ([]byte, error) { return c.EncodeAPER(v) }}
	default:
		panic(kind)
	}
}
func replayWrapPayload(payload []byte, id int64) []byte {
	bb := aper.NewBitBuffer()
	min, max := int64(0), int64(65535)
	replayAllocationNeed(aper.EncodeIntegerAligned(bb, id, &min, &max, false))
	replayAllocationNeed(aper.EncodeEnumeratedAligned(bb, 0, 3, false))
	replayAllocationNeed(aper.EncodeOpenTypeAligned(bb, payload))
	return bb.Bytes()
}
