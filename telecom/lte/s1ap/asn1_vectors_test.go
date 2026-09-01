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
			if index < 0 || index >= current.Len() {
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

func FuzzAPERS1APPDUProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("001240140000030000000200010008000200020002400126"))
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
