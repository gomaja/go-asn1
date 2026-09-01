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
func TestVectorHandoverRequestUeHistoryIe15(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000021f35412345670000005")
	dispatched, err := DecodeIEFieldValue("HandoverRequest", 15, input)
	decodedPointer, ok := dispatched.(*UEHistoryInformation)
	if !ok {
		t.Fatalf("dispatch type = %T, want typed pointer", dispatched)
	}
	decoded := *decodedPointer
	if err != nil {
		t.Fatal(err)
	}
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

func FuzzAPERUEHistoryInformation(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000021f35412345670000005"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = UnmarshalAPERUEHistoryInformation(input)
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

func FuzzAPERDispatchHandoverRequestIE15(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000021f35412345670000005"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeIEFieldValue("HandoverRequest", 15, input)
	})
}
