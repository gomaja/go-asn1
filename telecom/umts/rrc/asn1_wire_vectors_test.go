package rrc

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
			// Generated BER collections own their slice and wire provenance.
			// Treat their Values field as the indexed abstract value.
			if current.Kind() == reflect.Struct {
				_, hasOriginal := current.Type().FieldByName("berOriginal_")
				_, hasSnapshot := current.Type().FieldByName("berSnapshot_")
				if hasOriginal && hasSnapshot {
					current = current.FieldByName("Values")
				}
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

// TestVectorInterRatHandoverAllAbsent verifies 3GPP TS 25.331 V19.0.1 section 11.2, InterRATHandoverInfo; independently encoded and decoded by pycrate 0.7.11.
func TestVectorInterRatHandoverAllAbsent(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "00")
	var decoded InterRATHandoverInfo
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "PredefinedConfigStatusList.Choice", "1")
	asn1VectorAssertPath(t, decoded, "UESecurityInformation.Choice", "1")
	asn1VectorAssertPath(t, decoded, "UeCapabilityContainer.Choice", "1")
	asn1VectorAssertPath(t, decoded, "V390NonCriticalExtensions.Choice", "1")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorInterRatHandoverSecurity verifies 3GPP TS 25.331 V19.0.1 section 11.2, InterRATHandoverInfo; start-CS 0xabcde encoded and decoded by pycrate 0.7.11.
func TestVectorInterRatHandoverSecurity(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "6af378")
	var decoded InterRATHandoverInfo
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "UESecurityInformation.Choice", "2")
	asn1VectorAssertPath(t, decoded, "UESecurityInformation.Present.StartCS.BitLength", "20")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorInterRatHandoverV390 verifies 3GPP TS 25.331 V19.0.1 section 11.2, InterRATHandoverInfo v390 extension; independently encoded and decoded by pycrate 0.7.11.
func TestVectorInterRatHandoverV390(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "10")
	var decoded InterRATHandoverInfo
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "V390NonCriticalExtensions.Choice", "2")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorInterRatHandoverContainedR3 verifies 3GPP TS 25.331 V19.0.1 section 11.2, InterRATHandoverInfo-r3-add-ext; ITU-T X.691 (02/2021) section 11.1.3.2; independently decoded by tshark 4.6.8.
func TestVectorInterRatHandoverContainedR3(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "194020")
	var decoded InterRATHandoverInfo
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "PredefinedConfigStatusList.Choice", "1")
	asn1VectorAssertPath(t, decoded, "UESecurityInformation.Choice", "1")
	asn1VectorAssertPath(t, decoded, "UeCapabilityContainer.Choice", "1")
	asn1VectorAssertPath(t, decoded, "V390NonCriticalExtensions.Choice", "2")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorInterRatHandoverTruncatedSecurity verifies 3GPP TS 25.331 V19.0.1 section 11.2, InterRATHandoverInfo start-CS requires 20 bits.
func TestVectorInterRatHandoverTruncatedSecurity(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "6af3")
	var decoded InterRATHandoverInfo
	err := decoded.UnmarshalUPER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "per: data truncated") {
		t.Fatalf("decode error = %q, want substring %q", err, "per: data truncated")
	}
	if !strings.Contains(err.Error(), "InterRATHandoverInfo.UESecurityInformation.Present.StartCS") {
		t.Fatalf("decode error = %q, want path %q", err, "InterRATHandoverInfo.UESecurityInformation.Present.StartCS")
	}
}

// TestVectorInterRatHandoverInvalidContainedPadding verifies ITU-T X.691 (02/2021) sections 11.1.1(b) and 11.1.3.2; complete UPER inside BIT STRING has no trailing padding.
func TestVectorInterRatHandoverInvalidContainedPadding(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "19408000")
	var decoded InterRATHandoverInfo
	err := decoded.UnmarshalUPER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "6 trailing bits") {
		t.Fatalf("decode error = %q, want substring %q", err, "6 trailing bits")
	}
	if !strings.Contains(err.Error(), "InterRATHandoverInfo.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions") {
		t.Fatalf("decode error = %q, want path %q", err, "InterRATHandoverInfo.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions")
	}
}

func FuzzUPERInterRATHandoverInfo(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("00"))
	f.Add(asn1VectorHexForFuzz("6af378"))
	f.Add(asn1VectorHexForFuzz("10"))
	f.Add(asn1VectorHexForFuzz("194020"))
	f.Add(asn1VectorHexForFuzz("6af3"))
	f.Add(asn1VectorHexForFuzz("19408000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded InterRATHandoverInfo
		_ = decoded.UnmarshalUPER(input)
	})
}
