package lppa

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

// TestVectorEcidMeasurementIdDispatch verifies 3GPP TS 36.455 V19.0.0 clause 9.3, LPPA-PDU, E-CIDMeasurementInitiationRequest and E-CIDMeasurementInitiationRequest-IEs.
func TestVectorEcidMeasurementIdDispatch(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "0002000000080000010002000100")
	var decoded LPPAPDU
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	recursive, err := decoded.DecodeValueRecursive()
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[0].Field.Id", "2")
	asn1VectorAssertPath(t, recursive, "ProtocolIEs[0].Value", "1")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorEcidMeasurementIdHeader verifies 3GPP TS 36.455 V19.0.0 clause 9.3, LPPA-PDU and E-CIDMeasurementInitiationRequest.
func TestVectorEcidMeasurementIdHeader(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "0002000000080000010002000100")
	var decoded LPPAPDU
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "1")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.ProcedureCode", "2")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.Criticality", "0")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.LppatransactionID", "0")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorErrorIndicationEmpty verifies 3GPP TS 36.455 V19.0.0 clause 9.3, LPPA-PDU and ErrorIndication.
func TestVectorErrorIndicationEmpty(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000040000003000000")
	var decoded LPPAPDU
	err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "1")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.ProcedureCode", "0")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.Criticality", "1")
	asn1VectorAssertPath(t, decoded, "InitiatingMessage.LppatransactionID", "0")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorTruncatedEcidPdu verifies 3GPP TS 36.455 V19.0.0 clause 9.3, truncated LPPA-PDU open type.
func TestVectorTruncatedEcidPdu(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "00020000000800000100020001")
	var decoded LPPAPDU
	err := decoded.UnmarshalAPER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "per: data truncated") {
		t.Fatalf("decode error = %q, want substring %q", err, "per: data truncated")
	}
	if !strings.Contains(err.Error(), "LPPAPDU.InitiatingMessage.Value") {
		t.Fatalf("decode error = %q, want path %q", err, "LPPAPDU.InitiatingMessage.Value")
	}
}

func FuzzAPERLPPAPDUProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0002000000080000010002000100"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded LPPAPDU
		if err := decoded.UnmarshalAPER(input); err == nil {
			_, _ = decoded.DecodeValueRecursive()
		}
	})
}

func FuzzAPERLPPAPDU(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0002000000080000010002000100"))
	f.Add(asn1VectorHexForFuzz("000040000003000000"))
	f.Add(asn1VectorHexForFuzz("00020000000800000100020001"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded LPPAPDU
		_ = decoded.UnmarshalAPER(input)
	})
}
