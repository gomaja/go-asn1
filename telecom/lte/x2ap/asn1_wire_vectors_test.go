package x2ap

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
	for _, segment := range strings.Split(path, ".") {
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

// TestVectorHandoverRequestUeHistoryRecursive verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.1.1, 9.2.38, 9.2.39, and 9.2.40; HandoverRequest includes mandatory id-UE-HistoryInformation 15.
func TestVectorHandoverRequestUeHistoryRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "0000007b000006000a00020001000540020000000b00080021f35412345670001700070021f354000101000e004100010000000000000000000000000000000000000000000000000000000000000000000000000000010001000004400e4500060401f0c000020100000001020000000f400c000021f35412345670000005")
	var decoded X2APPDU
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := decoded.DecodeValueRecursive()
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[5].Value[0].Choice", "1")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[5].Value[0].EUTRANCell.GlobalCellID.PLMNIdentity", "\"IfNU\"")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[5].Value[0].EUTRANCell.CellType.CellSize", "0")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[5].Value[0].EUTRANCell.TimeUEStayedInCell", "5")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorHandoverRequestUeHistoryIe15 verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.1.1, 9.2.38, 9.2.39, and 9.2.40; id-UE-HistoryInformation 15.
// Regression: go-asn1-v0.2.3.x2ap.handover-request-ie-15
func TestVectorHandoverRequestUeHistoryIe15(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000021f35412345670000005")
	dispatched, err := DecodeIEFieldValue("HandoverRequest-IEs", 15, input)
	if err != nil {
		t.Fatal(err)
	}
	decodedPointer, ok := dispatched.(*UEHistoryInformation)
	if !ok {
		t.Fatalf("dispatch type = %T, want typed pointer", dispatched)
	}
	decoded := *decodedPointer
	asn1VectorAssertPath(t, decoded, "[0].Choice", "1")
	asn1VectorAssertPath(t, decoded, "[0].EUTRANCell.GlobalCellID.PLMNIdentity", "\"IfNU\"")
	asn1VectorAssertPath(t, decoded, "[0].EUTRANCell.GlobalCellID.EUTRANcellIdentifier.BitLength", "28")
	asn1VectorAssertPath(t, decoded, "[0].EUTRANCell.CellType.CellSize", "0")
	asn1VectorAssertPath(t, decoded, "[0].EUTRANCell.TimeUEStayedInCell", "5")
	wire, err := MarshalAPERUEHistoryInformation(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorProtocolIeFieldHeader verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2.4; ProtocolIE-Field APER header and open-type payload.
// Regression: go-asn1-v0.4.2.x2ap.protocol-ie-field-header
func TestVectorProtocolIeFieldHeader(t *testing.T) {
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

// TestVectorX2apPduHeader verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1 and 9.2.3; X2AP-PDU initiating-message APER header.
// Regression: go-asn1-v0.4.2.x2ap.pdu-header
func TestVectorX2apPduHeader(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "002e0002bbcc")
	var decoded X2APPDU
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

// TestVectorHandoverRequestNineVisitedCells verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.2.38 through 9.2.40; UE-HistoryInformation permits up to 16 visited cells.
// Regression: go-asn1-v0.4.2.x2ap.ue-history-nine-cells
func TestVectorHandoverRequestNineVisitedCells(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "800006f730010840b10000050006f730010220c10000020006f730010840b10000010006f730010220c10000120006f730010840b10000070006f730010220c100000d0006f730010840b100001a0006f730010220c10000030006f730010840b1000062")
	dispatched, err := DecodeIEFieldValue("HandoverRequest-IEs", 15, input)
	if err != nil {
		t.Fatal(err)
	}
	decodedPointer, ok := dispatched.(*UEHistoryInformation)
	if !ok {
		t.Fatalf("dispatch type = %T, want typed pointer", dispatched)
	}
	decoded := *decodedPointer
	asn1VectorAssertPath(t, decoded, "[0].EUTRANCell.TimeUEStayedInCell", "5")
	asn1VectorAssertPath(t, decoded, "[1].EUTRANCell.TimeUEStayedInCell", "2")
	asn1VectorAssertPath(t, decoded, "[3].EUTRANCell.TimeUEStayedInCell", "18")
	asn1VectorAssertPath(t, decoded, "[8].EUTRANCell.TimeUEStayedInCell", "98")
	wire, err := MarshalAPERUEHistoryInformation(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorHandoverRequestOldEnbUeId verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.1.1 and 9.2.24; HandoverRequest id-Old-eNB-UE-X2AP-ID.
// Regression: go-asn1-v0.4.2.x2ap.handover-request-old-enb-ue-id
func TestVectorHandoverRequestOldEnbUeId(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "0007")
	dispatched, err := DecodeIEFieldValue("HandoverRequest-IEs", 10, input)
	if err != nil {
		t.Fatal(err)
	}
	decodedPointer, ok := dispatched.(*UEX2APID)
	if !ok {
		t.Fatalf("dispatch type = %T, want typed pointer", dispatched)
	}
	decoded := *decodedPointer
	asn1VectorAssertPath(t, decoded, "$", "7")
}

// TestVectorErabSetupItemRecursiveIe verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.1.1 and 9.2.1; nested E-RAB open types retain their ASN.1 object-set context.
// Regression: go-asn1-v0.4.2.x2ap.nested-erab-open-type
func TestVectorErabSetupItemRecursiveIe(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "4500060701f00afd0055037806f5")
	field := ProtocolIEField{Id: 4}
	field.Value.Bytes = input
	decoded, err := DecodeProtocolIEFieldsRecursive("E-RABs-ToBeSetup-ItemIEs", []ProtocolIEField{field})
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "[0].Path", "\"E-RABs-ToBeSetup-ItemIEs[0]\"")
	asn1VectorAssertPath(t, decoded, "[0].ObjectSet", "\"E-RABs-ToBeSetup-ItemIEs\"")
	asn1VectorAssertPath(t, decoded, "[0].Value.ERABID", "5")
	asn1VectorAssertPath(t, decoded, "[0].Value.ERABLevelQoSParameters.QCI", "6")
	asn1VectorAssertPath(t, decoded, "[0].Value.ERABLevelQoSParameters.AllocationAndRetentionPriority.PriorityLevel", "1")
	asn1VectorAssertPath(t, decoded, "[0].Value.DLForwarding", "0")
	asn1VectorAssertPath(t, decoded, "[0].Value.ULGTPtunnelEndpoint.TransportLayerAddress.BitLength", "32")
	asn1VectorAssertPath(t, decoded, "[0].Value.ULGTPtunnelEndpoint.GTPTEID", "\"A3gG9Q==\"")
}

// TestVectorNrraReportRecursive verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.11 and 9.2; recursive NRRA report open-type decoding.
// Regression: go-asn1-v0.4.2.x2ap.nrra-report
func TestVectorNrraReportRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000001019e4009000006040000000000")
	var decoded AccessAndMobilityIndication
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolIEsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"AccessAndMobilityIndication-IEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Field.Id", "414")
	asn1VectorAssertPath(t, recursive, "[0].Value[0].NRRAReport", "\"BAAAAAAA\"")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorErabSetupPrivateIePreserved verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2.4; unknown and private ProtocolIE-Field values remain raw.
// Regression: go-asn1-v0.4.2.x2ap.unknown-private-ie
func TestVectorErabSetupPrivateIePreserved(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "deadbeef")
	field := ProtocolIEField{Id: 65532}
	field.Value.Bytes = input
	decoded, err := DecodeProtocolIEFieldsRecursive("E-RABs-ToBeSetup-ItemIEs", []ProtocolIEField{field})
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "[0].Field.Id", "65532")
	asn1VectorAssertPath(t, decoded, "[0].Field.Value.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, decoded, "[0].Value", "null")
}

// TestVectorErabSetupMalformedIePath verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2.4; malformed nested open-type diagnostics retain the full field path.
// Regression: go-asn1-v0.4.2.x2ap.malformed-nested-ie
func TestVectorErabSetupMalformedIePath(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "00")
	field := ProtocolIEField{Id: 4}
	field.Value.Bytes = input
	_, err := DecodeProtocolIEFieldsRecursive("E-RABs-ToBeSetup-ItemIEs", []ProtocolIEField{field})
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "per: data truncated") {
		t.Fatalf("decode error = %q, want substring %q", err, "per: data truncated")
	}
	if !strings.Contains(err.Error(), "E-RABs-ToBeSetup-ItemIEs[0]") {
		t.Fatalf("decode error = %q, want path %q", err, "E-RABs-ToBeSetup-ItemIEs[0]")
	}
}

// TestVectorErabSetupDapsExtensionRecursive verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.3.4, 9.3.5, and 9.3.7; id-DAPSRequestInfo 363.
func TestVectorErabSetupDapsExtensionRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "2500093c03e00a000001deadbeef0000016b400100")
	var decoded ERABsToBeSetupItem
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := DecodeProtocolExtensionsRecursive(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "[0].Path", "\"ERABsToBeSetupItem.IEExtensions[0]\"")
	asn1VectorAssertPath(t, recursive, "[0].ObjectSet", "\"E-RABs-ToBeSetup-ItemExtIEs\"")
	asn1VectorAssertPath(t, recursive, "[0].Value.DAPSIndicator", "0")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorSuccessfulOutcomeDapsExtensionRecursive verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.1.2 and 9.3.7; DAPS response extensions remain recursively reachable from the procedure value.
// Regression: go-asn1-v0.4.2.x2ap.daps-extension-reachable
func TestVectorSuccessfulOutcomeDapsExtensionRecursive(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000027000004000a400200070009400200080001400e000000400912800000016e000100000c400201aa")
	var decoded SuccessfulOutcome
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := decoded.DecodeValueRecursive()
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[2].Children[0].Extensions[0].Path", "\"HandoverRequestAcknowledge.ProtocolIEs[2][0].IEExtensions[0]\"")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[2].Children[0].Extensions[0].ObjectSet", "\"E-RABs-Admitted-Item-ExtIEs\"")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[2].Children[0].Extensions[0].Value.DAPSResponseIndicator", "0")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorAdmittedItemUnknownExtensionField verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.2.4 and 9.3.8; unknown ProtocolExtensionField values remain raw.
// Regression: go-asn1-v0.4.2.x2ap.unknown-extension-field
func TestVectorAdmittedItemUnknownExtensionField(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	decoded, err := DecodeProtocolExtensionFieldsRecursive("E-RABs-Admitted-Item-ExtIEs", []ProtocolExtensionField{field})
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "[0].ObjectSet", "\"E-RABs-Admitted-Item-ExtIEs\"")
	asn1VectorAssertPath(t, decoded, "[0].Field.Id", "65532")
	asn1VectorAssertPath(t, decoded, "[0].Field.ExtensionValue.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, decoded, "[0].Value", "null")
}

// TestVectorAdmittedItemDapsExtensionValue verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.3.7 and 9.3.8; published E-RAB admitted-item extension object-set dispatch.
// Regression: go-asn1-v0.4.2.x2ap.admitted-item-object-set
func TestVectorAdmittedItemDapsExtensionValue(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "00")
	dispatched, err := DecodeExtensionFieldValue("E-RABs-Admitted-Item-ExtIEs", 366, input)
	if err != nil {
		t.Fatal(err)
	}
	decodedPointer, ok := dispatched.(*DAPSResponseInfo)
	if !ok {
		t.Fatalf("dispatch type = %T, want typed pointer", dispatched)
	}
	decoded := *decodedPointer
	asn1VectorAssertPath(t, decoded, "DAPSResponseIndicator", "0")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorAdmittedItemMalformedDapsPath verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.3.7 and 9.3.8; malformed DAPS diagnostics retain the complete containing path.
// Regression: go-asn1-v0.4.2.x2ap.malformed-daps-extension
func TestVectorAdmittedItemMalformedDapsPath(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "12800000016e0000")
	var decoded ERABsAdmittedItem
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
	if !strings.Contains(err.Error(), "ERABsAdmittedItem.IEExtensions[0]") {
		t.Fatalf("decode error = %q, want path %q", err, "ERABsAdmittedItem.IEExtensions[0]")
	}
}

// TestVectorErabSetupUnknownExtensionPreserved verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.3.4 and 9.3.8; unknown/private ProtocolExtensionField values remain raw.
func TestVectorErabSetupUnknownExtensionPreserved(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "2500093c03e00a000001deadbeef0000fffc4004deadbeef")
	var decoded ERABsToBeSetupItem
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

// TestVectorErabSetupMalformedDapsFullPath verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.3.4, 9.3.5, and 9.3.7; malformed DAPS extension diagnostics retain the complete containing path.
func TestVectorErabSetupMalformedDapsFullPath(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "2500093c03e00a000001deadbeef0000016b4001ff")
	var decoded ERABsToBeSetupItem
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
	if !strings.Contains(err.Error(), "ERABsToBeSetupItem.IEExtensions[0]") {
		t.Fatalf("decode error = %q, want path %q", err, "ERABsToBeSetupItem.IEExtensions[0]")
	}
}

func FuzzAPERX2APPDUProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0000007b000006000a00020001000540020000000b00080021f35412345670001700070021f354000101000e004100010000000000000000000000000000000000000000000000000000000000000000000000000000010001000004400e4500060401f0c000020100000001020000000f400c000021f35412345670000005"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded X2APPDU
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = decoded.DecodeValueRecursive()
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

func FuzzAPERX2APPDU(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded X2APPDU
		_ = decoded.UnmarshalAPER(input)
	})
}

func FuzzAPERAccessAndMobilityIndicationProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001019e4009000006040000000000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded AccessAndMobilityIndication
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolIEsRecursive(&decoded)
		}
	})
}

func FuzzAPERERABsToBeSetupItemProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("2500093c03e00a000001deadbeef0000016b400100"))
	f.Add(asn1VectorHexForFuzz("2500093c03e00a000001deadbeef0000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("2500093c03e00a000001deadbeef0000016b4001ff"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ERABsToBeSetupItem
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolExtensionsRecursive(&decoded)
		}
	})
}

func FuzzAPERSuccessfulOutcomeProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000027000004000a400200070009400200080001400e000000400912800000016e000100000c400201aa"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded SuccessfulOutcome
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = decoded.DecodeValueRecursive()
		}
	})
}

func FuzzAPERERABsAdmittedItemProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("12800000016e0000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ERABsAdmittedItem
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = DecodeProtocolExtensionsRecursive(&decoded)
		}
	})
}

func FuzzAPERDispatchProtocolIeValueHandoverRequestIEsID15(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000021f35412345670000005"))
	f.Add(asn1VectorHexForFuzz("800006f730010840b10000050006f730010220c10000020006f730010840b10000010006f730010220c10000120006f730010840b10000070006f730010220c100000d0006f730010840b100001a0006f730010220c10000030006f730010840b1000062"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeIEFieldValue("HandoverRequest-IEs", 15, input)
	})
}

func FuzzAPERDispatchProtocolIeValueHandoverRequestIEsID10(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0007"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeIEFieldValue("HandoverRequest-IEs", 10, input)
	})
}

func FuzzAPERDispatchProtocolIeRecursiveFieldERABsToBeSetupItemIEsID4(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("4500060701f00afd0055037806f5"))
	f.Add(asn1VectorHexForFuzz("00"))
	f.Fuzz(func(t *testing.T, input []byte) {
		field := ProtocolIEField{Id: 4}
		field.Value.Bytes = input
		_, _ = DecodeProtocolIEFieldsRecursive("E-RABs-ToBeSetup-ItemIEs", []ProtocolIEField{field})
	})
}

func FuzzAPERDispatchProtocolIeRecursiveFieldERABsToBeSetupItemIEsID65532(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		field := ProtocolIEField{Id: 65532}
		field.Value.Bytes = input
		_, _ = DecodeProtocolIEFieldsRecursive("E-RABs-ToBeSetup-ItemIEs", []ProtocolIEField{field})
	})
}

func FuzzAPERDispatchProtocolExtensionRecursiveFieldERABsAdmittedItemExtIEsID65532(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		field := ProtocolExtensionField{Id: 65532}
		field.ExtensionValue.Bytes = input
		_, _ = DecodeProtocolExtensionFieldsRecursive("E-RABs-Admitted-Item-ExtIEs", []ProtocolExtensionField{field})
	})
}

func FuzzAPERDispatchProtocolExtensionValueERABsAdmittedItemExtIEsID366(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("00"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeExtensionFieldValue("E-RABs-Admitted-Item-ExtIEs", 366, input)
	})
}
