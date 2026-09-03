package s1ap

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func asn1VectorHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func asn1VectorHexForFuzz(input string) []byte {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return decoded
}

func TestASN1VectorPathRejectsNegativeIndex(t *testing.T) {
	if _, err := asn1VectorValueAtPath(reflect.ValueOf([]int{1}), "[-1]"); err == nil {
		t.Fatal("asn1VectorValueAtPath accepted a negative index")
	}
}

func TestASN1VectorPathRejectsEmptySegments(t *testing.T) {
	value := reflect.ValueOf(struct{ Field int }{Field: 1})
	for _, path := range []string{"", ".Field", "Field.", "Field..Nested"} {
		if _, err := asn1VectorValueAtPath(value, path); err == nil {
			t.Errorf("asn1VectorValueAtPath accepted malformed path %q", path)
		}
	}
}

func asn1VectorAssertPath(t *testing.T, value any, path, expectedJSON string) {
	t.Helper()
	actual, err := asn1VectorValueAtPath(reflect.ValueOf(value), path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != expectedJSON {
		t.Fatalf("%s = %s, want %s", path, encoded, expectedJSON)
	}
}

func asn1VectorValueAtPath(current reflect.Value, path string) (any, error) {
	if path == "$" {
		return asn1VectorInterface(current)
	}
	segments := strings.Split(path, ".")
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("path %s: malformed empty segment", path)
		}
	}
	for _, segment := range segments {
		var err error
		current, err = asn1VectorDereference(current)
		if err != nil {
			return nil, fmt.Errorf("path %s: %w", path, err)
		}
		fieldEnd := strings.IndexByte(segment, '[')
		if fieldEnd == -1 {
			fieldEnd = len(segment)
		}
		field := segment[:fieldEnd]
		if field != "" {
			if current.Kind() != reflect.Struct {
				return nil, fmt.Errorf("path %s: %s is not a struct", path, field)
			}
			current = current.FieldByName(field)
			if !current.IsValid() {
				return nil, fmt.Errorf("path %s: field %s is absent", path, field)
			}
		}
		for suffix := segment[fieldEnd:]; suffix != ""; {
			closeIndex := strings.IndexByte(suffix, ']')
			if closeIndex < 2 || suffix[0] != '[' {
				return nil, fmt.Errorf("path %s: malformed index", path)
			}
			index, err := strconv.Atoi(suffix[1:closeIndex])
			if err != nil {
				return nil, fmt.Errorf("path %s: malformed index: %w", path, err)
			}
			current, err = asn1VectorDereference(current)
			if err != nil {
				return nil, fmt.Errorf("path %s: %w", path, err)
			}
			if current.Kind() != reflect.Array && current.Kind() != reflect.Slice {
				return nil, fmt.Errorf("path %s: indexed value is not a list", path)
			}
			if index < 0 {
				return nil, fmt.Errorf("path %s: index %d is negative", path, index)
			}
			if index >= current.Len() {
				return nil, fmt.Errorf("path %s: index %d exceeds length %d", path, index, current.Len())
			}
			current = current.Index(index)
			suffix = suffix[closeIndex+1:]
		}
	}
	return asn1VectorInterface(current)
}

func asn1VectorDereference(value reflect.Value) (reflect.Value, error) {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return reflect.Value{}, fmt.Errorf("encountered nil")
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return reflect.Value{}, fmt.Errorf("encountered invalid value")
	}
	return value, nil
}

func asn1VectorInterface(value reflect.Value) (any, error) {
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, nil
		}
		value = value.Elem()
	}
	if value.IsValid() && value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, nil
	}
	if !value.IsValid() || !value.CanInterface() {
		return nil, fmt.Errorf("value is not accessible")
	}
	return value.Interface(), nil
}

// TestVectorUeContextReleaseRequestCauseNas verifies 3GPP TS 36.413 V19.2.0 (2026-07), sections 9.1.5.1 and 9.3.4; CauseNas has four root values before the extension marker.
func TestVectorUeContextReleaseRequestCauseNas(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "001240140000030000000200010008000200020002400126")
	var decoded S1APPDU
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := decoded.DecodeValueRecursive()
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[2].Value.Choice", "3")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[2].Value.Nas", "3")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorCauseNasRootExtensionBoundary verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4, Cause and CauseNas.
// Regression: go-asn1-v0.4.2.s1ap.cause-nas-root-boundary
func TestVectorCauseNasRootExtensionBoundary(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "26")
	var decoded Cause
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "3")
	asn1VectorAssertPath(t, decoded, "Nas", "3")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorErabInformationDapsExtensionRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4; id-DAPSRequestInfo 317.
func TestVectorErabInformationDapsExtensionRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "250000013d400100")
	var decoded ERABInformationListItem
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolExtensionsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].Path", "\"ERABInformationListItem.IEExtensions[0]\"")
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"E-RABInformationListItem-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Value.DAPSIndicator", "0")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorErabInformationUnknownExtensionPreserved verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4; unknown/private ProtocolExtensionField values remain raw.
func TestVectorErabInformationUnknownExtensionPreserved(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "250000fffc4004deadbeef")
	var decoded ERABInformationListItem
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolExtensionsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].Field.Id", "65532")
	asn1VectorAssertPath(t, recursive, "[0].Field.ExtensionValue.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, recursive, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorErabInformationMalformedDapsFullPath verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4; malformed DAPS extension diagnostics retain the complete containing path.
func TestVectorErabInformationMalformedDapsFullPath(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "250000013d4001ff")
	var decoded ERABInformationListItem
	err := decoded.UnmarshalAPER(input)
	if err == nil {
		_, err = DecodeProtocolExtensionsRecursive(&decoded)
	}
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "per: data truncated") {
		t.Fatalf("decode error = %q, want substring %q", err, "per: data truncated")
	}
	if !strings.Contains(err.Error(), "ERABInformationListItem.IEExtensions[0]") {
		t.Fatalf("decode error = %q, want path %q", err, "ERABInformationListItem.IEExtensions[0]")
	}
}

// TestVectorProtocolIeFieldConstrainedHeader verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.2.1.1; ProtocolIE-Field APER constrained header.
// Regression: go-asn1-v0.4.2.s1ap.protocol-ie-field-aper-header
func TestVectorProtocolIeFieldConstrainedHeader(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "12344001aa")
	var decoded ProtocolIEField
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Id", "4660")
	asn1VectorAssertPath(t, decoded, "Criticality", "1")
	asn1VectorAssertPath(t, decoded, "Value.Bytes", "\"qg==\"")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorS1apPduConstrainedHeader verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.1; S1AP-PDU APER constrained header.
// Regression: go-asn1-v0.4.2.s1ap.pdu-aper-header
func TestVectorS1apPduConstrainedHeader(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "002e0002bbcc")
	var decoded S1APPDU
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "1")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.ProcedureCode", "46")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.Criticality", "0")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.Value.Bytes", "\"u8w=\"")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorPagingTaiListRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-07), sections 9.1.6 and 9.3.3; Paging TAIList applies TAIItemIEs recursively.
// Regression: go-asn1-v0.4.2.s1ap.paging-tai-list
func TestVectorPagingTaiListRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000001002e400b00002f40060001f0101234")
	var decoded Paging
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolIEsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"PagingIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Children[0].ObjectSet", "\"TAIItemIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Children[0].Value.TAI.PLMNidentity", "\"AfAQ\"")
	asn1VectorAssertPath(t, recursive, "[0].Children[0].Value.TAI.TAC", "\"EjQ=\"")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorPagingProcedureRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.1.6; initiating Paging procedure recursively resolves its argument and nested TAI items.
// Regression: go-asn1-v0.4.2.s1ap.paging-procedure
func TestVectorPagingProcedureRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000a4012000001002e400b00002f40060001f0101234")
	var decoded S1APPDU
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := decoded.DecodeValueRecursive()
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[0].ObjectSet", "\"PagingIEs\"")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[0].Children[0].ObjectSet", "\"TAIItemIEs\"")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorResetAcknowledgeConnectionListRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.1.9; ResetAcknowledge recursively resolves UE-associated logical S1 connections.
// Regression: go-asn1-v0.4.2.s1ap.reset-acknowledge-connection-list
func TestVectorResetAcknowledgeConnectionListRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000001005d400900005b000460070009")
	var decoded ResetAcknowledge
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolIEsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"ResetAcknowledgeIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Children[0].ObjectSet", "\"UE-associatedLogicalS1-ConnectionItemResAck\"")
	asn1VectorAssertPath(t, recursive, "[0].Children[0].Value.MMEUES1APID", "7")
	asn1VectorAssertPath(t, recursive, "[0].Children[0].Value.ENBUES1APID", "9")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorEventTriggerEmptyChoiceExtensionSet verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.5; empty extensible EventTrigger-ExtIEs preserves private values.
// Regression: go-asn1-v0.4.2.s1ap.empty-choice-extension.event-trigger
func TestVectorEventTriggerEmptyChoiceExtensionSet(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "80fffc4004deadbeef")
	var decoded EventTrigger
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolIEsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].Path", "\"EventTrigger.ChoiceExtensions[0]\"")
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"EventTrigger-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Field.Value.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, recursive, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorMeasurementThresholdEmptyChoiceExtensionSet verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.5; empty extensible MeasurementThresholdL1LoggedMDT-ExtIEs preserves private values.
// Regression: go-asn1-v0.4.2.s1ap.empty-choice-extension.measurement-threshold
func TestVectorMeasurementThresholdEmptyChoiceExtensionSet(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "80fffc4004deadbeef")
	var decoded MeasurementThresholdL1LoggedMDT
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolIEsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].Path", "\"MeasurementThresholdL1LoggedMDT.ChoiceExtensions[0]\"")
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"MeasurementThresholdL1LoggedMDT-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Field.Value.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, recursive, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorSensorNameEmptyChoiceExtensionSet verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.5; empty extensible SensorNameConfig-ExtIEs preserves private values.
// Regression: go-asn1-v0.4.2.s1ap.empty-choice-extension.sensor-name
func TestVectorSensorNameEmptyChoiceExtensionSet(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "80fffc4004deadbeef")
	var decoded SensorNameConfig
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolIEsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].Path", "\"SensorNameConfig.ChoiceExtensions[0]\"")
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"SensorNameConfig-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Field.Value.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, recursive, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorTargetTransparentContainerDapsRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4; target transparent container DAPS response list and nested private extension.
// Regression: go-asn1-v0.4.2.s1ap.target-transparent-container-daps
func TestVectorTargetTransparentContainerDapsRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "4001010000013e401100013f400c4a000000fffc4004deadbeef")
	var decoded TargeteNBToSourceeNBTransparentContainer
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolExtensionsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].ProtocolIEs[0].ObjectSet", "\"DAPSResponseInfoListIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].ProtocolIEs[0].Value.ERABID", "5")
	asn1VectorAssertPath(t, recursive, "[0].ProtocolIEs[0].Value.DAPSResponseInfo.Dapsresponseindicator", "0")
	asn1VectorAssertPath(t, recursive, "[0].ProtocolIEs[0].Extensions[0].ObjectSet", "\"DAPSResponseInfoItem-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].ProtocolIEs[0].Extensions[0].Field.ExtensionValue.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, recursive, "[0].ProtocolIEs[0].Extensions[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorTargetTransparentContainerUnknownExtension verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4; unknown target transparent container extension remains raw.
// Regression: go-asn1-v0.4.2.s1ap.target-transparent-container-unknown-extension
func TestVectorTargetTransparentContainerUnknownExtension(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "4001010000fffc4004deadbeef")
	var decoded TargeteNBToSourceeNBTransparentContainer
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolExtensionsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Field.Id", "65532")
	asn1VectorAssertPath(t, recursive, "[0].Field.ExtensionValue.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, recursive, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorTargetTransparentContainerMalformedDapsPath verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4; malformed DAPS response list reports full containing path and identifier.
// Regression: go-asn1-v0.4.2.s1ap.target-transparent-container-malformed-daps
func TestVectorTargetTransparentContainerMalformedDapsPath(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "4001010000013e4000")
	var decoded TargeteNBToSourceeNBTransparentContainer
	err := decoded.UnmarshalAPER(input)
	if err == nil {
		_, err = DecodeProtocolExtensionsRecursive(&decoded)
	}
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "extension 318") {
		t.Fatalf("decode error = %q, want substring %q", err, "extension 318")
	}
	if !strings.Contains(err.Error(), "TargeteNBToSourceeNBTransparentContainer.IEExtensions[0]") {
		t.Fatalf("decode error = %q, want path %q", err, "TargeteNBToSourceeNBTransparentContainer.IEExtensions[0]")
	}
}

// TestVectorTargetTransparentContainerDirectExtensionField verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.4; direct recursive ProtocolExtensionField DAPS decoding and fuzz boundary.
// Regression: go-asn1-v0.4.2.s1ap.protocol-extension-field-fuzz
func TestVectorTargetTransparentContainerDirectExtensionField(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "00013f400c4a000000fffc4004deadbeef")
	field := ProtocolExtensionField{Id: 318}
	field.ExtensionValue.Bytes = input
	decoded, err := DecodeProtocolExtensionFieldsRecursive("TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs", []ProtocolExtensionField{field})
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "[0].ObjectSet", "\"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs\"")
	asn1VectorAssertPath(t, decoded, "[0].ProtocolIEs[0].ObjectSet", "\"DAPSResponseInfoListIEs\"")
}

// TestVectorTaiItemDirectProtocolIeField verifies 3GPP TS 36.413 V19.2.0 (2026-07), section 9.3.3; direct recursive TAIItem ProtocolIE-Field decoding and fuzz boundary.
// Regression: go-asn1-v0.4.2.s1ap.protocol-ie-field-fuzz
func TestVectorTaiItemDirectProtocolIeField(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "0001f0101234")
	field := ProtocolIEField{Id: 47}
	field.Value.Bytes = input
	decoded, err := DecodeProtocolIEFieldsRecursive("TAIItemIEs", []ProtocolIEField{field})
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "[0].ObjectSet", "\"TAIItemIEs\"")
	asn1VectorAssertPath(t, decoded, "[0].Value.TAI.PLMNidentity", "\"AfAQ\"")
	asn1VectorAssertPath(t, decoded, "[0].Value.TAI.TAC", "\"EjQ=\"")
}

func FuzzAPERS1APPDUProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("001240140000030000000200010008000200020002400126"))
	f.Add(asn1VectorHexForFuzz("000a4012000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded S1APPDU
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = decoded.DecodeValueRecursive()
		}
	})
}

func FuzzAPERCause(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("26"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded Cause
		_ = decoded.UnmarshalAPER(input)
	})
}

func FuzzAPERERABInformationListItemProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("250000013d400100"))
	f.Add(asn1VectorHexForFuzz("250000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("250000013d4001ff"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ERABInformationListItem
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolExtensionsRecursive(&decoded)
		}
	})
}

func FuzzAPERProtocolIEField(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("12344001aa"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ProtocolIEField
		_ = decoded.UnmarshalAPER(input)
	})
}

func FuzzAPERS1APPDU(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded S1APPDU
		_ = decoded.UnmarshalAPER(input)
	})
}

func FuzzAPERPagingProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded Paging
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolIEsRecursive(&decoded)
		}
	})
}

func FuzzAPERResetAcknowledgeProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001005d400900005b000460070009"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ResetAcknowledge
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolIEsRecursive(&decoded)
		}
	})
}

func FuzzAPEREventTriggerProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded EventTrigger
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolIEsRecursive(&decoded)
		}
	})
}

func FuzzAPERMeasurementThresholdL1LoggedMDTProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded MeasurementThresholdL1LoggedMDT
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolIEsRecursive(&decoded)
		}
	})
}

func FuzzAPERSensorNameConfigProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded SensorNameConfig
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolIEsRecursive(&decoded)
		}
	})
}

func FuzzAPERTargeteNBToSourceeNBTransparentContainerProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("4001010000013e401100013f400c4a000000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("4001010000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("4001010000013e4000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded TargeteNBToSourceeNBTransparentContainer
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolExtensionsRecursive(&decoded)
		}
	})
}

func FuzzAPERDispatchProtocolExtensionRecursiveFieldTargeteNBToSourceeNBTransparentContainerExtIEsID318(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("00013f400c4a000000fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		field := ProtocolExtensionField{Id: 318}
		field.ExtensionValue.Bytes = input
		_, _ = DecodeProtocolExtensionFieldsRecursive("TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs", []ProtocolExtensionField{field})
	})
}

func FuzzAPERDispatchProtocolIeRecursiveFieldTAIItemIEsID47(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		field := ProtocolIEField{Id: 47}
		field.Value.Bytes = input
		_, _ = DecodeProtocolIEFieldsRecursive("TAIItemIEs", []ProtocolIEField{field})
	})
}
