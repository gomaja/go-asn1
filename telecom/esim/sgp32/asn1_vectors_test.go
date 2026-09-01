package sgp32

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

// TestVectorGetCertsResponseCertificates verifies GSMA SGP.32 V1.3 (2026-05-22), section 5.9.10 and normative Annex C; RFC 5280 section 4.1 and Appendix A.1.
func TestVectorGetCertsResponseCertificates(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf5682020ca0820208a58201003081b3a003020102020101300506032b65703020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72301e170d3236303130313030303030305a170d3237303130313030303030305a3020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664a3123010300e0603551d0f0101ff040403020780300506032b657003410068ba274f6ca267f6c3ee16f952c62b403f8e7c6c5d3416c85b12677f24a53edda0b32fb98e5b0e3cfdcf0c4ce51d906eb3c24fb77858ffaf55271d58f6ef9a03a68201003081b3a003020102020101300506032b65703020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72301e170d3236303130313030303030305a170d3237303130313030303030305a3020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664a3123010300e0603551d0f0101ff040403020780300506032b657003410068ba274f6ca267f6c3ee16f952c62b403f8e7c6c5d3416c85b12677f24a53edda0b32fb98e5b0e3cfdcf0c4ce51d906eb3c24fb77858ffaf55271d58f6ef9a03")
	var decoded GetCertsResponse
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "1")
	asn1VectorAssertPath(t, decoded, "Certs.EumCertificate.TbsCertificate.SerialNumber", "1")
	asn1VectorAssertPath(t, decoded, "Certs.EuiccCertificate.TbsCertificate.SerialNumber", "1")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

func FuzzBERGetCertsResponse(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf5682020ca0820208a58201003081b3a003020102020101300506032b65703020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72301e170d3236303130313030303030305a170d3237303130313030303030305a3020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664a3123010300e0603551d0f0101ff040403020780300506032b657003410068ba274f6ca267f6c3ee16f952c62b403f8e7c6c5d3416c85b12677f24a53edda0b32fb98e5b0e3cfdcf0c4ce51d906eb3c24fb77858ffaf55271d58f6ef9a03a68201003081b3a003020102020101300506032b65703020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72301e170d3236303130313030303030305a170d3237303130313030303030305a3020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664a3123010300e0603551d0f0101ff040403020780300506032b657003410068ba274f6ca267f6c3ee16f952c62b403f8e7c6c5d3416c85b12677f24a53edda0b32fb98e5b0e3cfdcf0c4ce51d906eb3c24fb77858ffaf55271d58f6ef9a03"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded GetCertsResponse
		_ = decoded.UnmarshalBER(input)
	})
}
