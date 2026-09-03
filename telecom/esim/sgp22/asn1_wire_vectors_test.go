package sgp22

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

// TestVectorExpirationDateUtcTime verifies GSMA SGP.22 V2.7 (2026-04-24), section 2.8 and RFC 5280 section 4.1.2.5; certificate expiration dates retain the imported Time CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.expiration-date-time-alias
func TestVectorExpirationDateUtcTime(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "170d3439313233313233353935395a")
	var decoded ExpirationDate
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "1")
	asn1VectorAssertPath(t, decoded, "UtcTime", "\"2049-12-31T23:59:59Z\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorPrepareDownloadCertificate verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.5 and normative Annex H; RFC 5280 section 4.1 and Appendix A.1.
func TestVectorPrepareDownloadCertificate(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf2182015e30158010000102030405060708090a0b0c0d0e0f0101005f3740a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5308201003081b3a003020102020101300506032b65703020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72301e170d3236303130313030303030305a170d3237303130313030303030305a3020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664a3123010300e0603551d0f0101ff040403020780300506032b657003410068ba274f6ca267f6c3ee16f952c62b403f8e7c6c5d3416c85b12677f24a53edda0b32fb98e5b0e3cfdcf0c4ce51d906eb3c24fb77858ffaf55271d58f6ef9a03")
	var decoded PrepareDownloadRequest
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "SmdpSigned2.TransactionId", "\"AAECAwQFBgcICQoLDA0ODw==\"")
	asn1VectorAssertPath(t, decoded, "SmdpSigned2.CcRequiredFlag", "false")
	asn1VectorAssertPath(t, decoded, "SmdpCertificate.TbsCertificate.SerialNumber", "1")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorPrepareDownloadResponseOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.5; PrepareDownloadResponse requires application tag BF21 around its CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.prepare-download-response-outer-tag
func TestVectorPrepareDownloadResponseOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf210aa1088003010203020104")
	var decoded PrepareDownloadResponse
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorPrepareDownloadResponseMissingOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.5; an unwrapped CHOICE alternative is not a PrepareDownloadResponse.
// Regression: go-asn1-v0.4.2.sgp22.prepare-download-response-inner-rejected
func TestVectorPrepareDownloadResponseMissingOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "a1088003010203020104")
	var decoded PrepareDownloadResponse
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [CONTEXT 33]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [CONTEXT 33]")
	}
}

// TestVectorAuthenticateServerResponseOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.6.4; AuthenticateServerResponse requires application tag BF38 around its CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.authenticate-server-response-outer-tag
func TestVectorAuthenticateServerResponseOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf380aa1088003010203020104")
	var decoded AuthenticateServerResponse
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorAuthenticateServerResponseMissingOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.6.4; an unwrapped CHOICE alternative is not an AuthenticateServerResponse.
// Regression: go-asn1-v0.4.2.sgp22.authenticate-server-response-inner-rejected
func TestVectorAuthenticateServerResponseMissingOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "a1088003010203020104")
	var decoded AuthenticateServerResponse
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [CONTEXT 56]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [CONTEXT 56]")
	}
}

// TestVectorCancelSessionResponseOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.11; CancelSessionResponse requires application tag BF41 around its CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.cancel-session-response-outer-tag
func TestVectorCancelSessionResponseOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf410381017f")
	var decoded CancelSessionResponse
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorCancelSessionResponseMissingOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.11; an unwrapped CHOICE alternative is not a CancelSessionResponse.
// Regression: go-asn1-v0.4.2.sgp22.cancel-session-response-inner-rejected
func TestVectorCancelSessionResponseMissingOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "81017f")
	var decoded CancelSessionResponse
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [CONTEXT 65]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [CONTEXT 65]")
	}
}

// TestVectorAuthenticateClientEs9ResponseOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.6.3; ES9+ AuthenticateClientResponse requires application tag BF3B around its CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.authenticate-client-es9-response-outer-tag
func TestVectorAuthenticateClientEs9ResponseOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf3b0381017f")
	var decoded AuthenticateClientResponseEs9
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorAuthenticateClientEs9ResponseMissingOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.6.3; an unwrapped CHOICE alternative is not an ES9+ AuthenticateClientResponse.
// Regression: go-asn1-v0.4.2.sgp22.authenticate-client-es9-response-inner-rejected
func TestVectorAuthenticateClientEs9ResponseMissingOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "81017f")
	var decoded AuthenticateClientResponseEs9
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [CONTEXT 59]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [CONTEXT 59]")
	}
}

// TestVectorGetBoundProfilePackageResponseOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.6; GetBoundProfilePackageResponse requires application tag BF3A around its CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.get-bound-profile-package-response-outer-tag
func TestVectorGetBoundProfilePackageResponseOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf3a0381017f")
	var decoded GetBoundProfilePackageResponse
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorGetBoundProfilePackageResponseMissingOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.6; an unwrapped CHOICE alternative is not a GetBoundProfilePackageResponse.
// Regression: go-asn1-v0.4.2.sgp22.get-bound-profile-package-response-inner-rejected
func TestVectorGetBoundProfilePackageResponseMissingOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "81017f")
	var decoded GetBoundProfilePackageResponse
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [CONTEXT 58]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [CONTEXT 58]")
	}
}

// TestVectorCancelSessionEs9ResponseOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.11; ES9+ CancelSessionResponse requires application tag BF41 around its CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.cancel-session-es9-response-outer-tag
func TestVectorCancelSessionEs9ResponseOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf410381017f")
	var decoded CancelSessionResponseEs9
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorCancelSessionEs9ResponseMissingOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 5.7.11; an unwrapped CHOICE alternative is not an ES9+ CancelSessionResponse.
// Regression: go-asn1-v0.4.2.sgp22.cancel-session-es9-response-inner-rejected
func TestVectorCancelSessionEs9ResponseMissingOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "81017f")
	var decoded CancelSessionResponseEs9
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [CONTEXT 65]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [CONTEXT 65]")
	}
}

// TestVectorAuthenticateClientEs11ResponseOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 6.3.2; ES11 AuthenticateClientResponse requires application tag BF40 around its CHOICE.
// Regression: go-asn1-v0.4.2.sgp22.authenticate-client-es11-response-outer-tag
func TestVectorAuthenticateClientEs11ResponseOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "bf400381017f")
	var decoded AuthenticateClientResponseEs11
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorAuthenticateClientEs11ResponseMissingOuterTag verifies GSMA SGP.22 V2.7 (2026-04-24), section 6.3.2; an unwrapped CHOICE alternative is not an ES11 AuthenticateClientResponse.
// Regression: go-asn1-v0.4.2.sgp22.authenticate-client-es11-response-inner-rejected
func TestVectorAuthenticateClientEs11ResponseMissingOuterTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "81017f")
	var decoded AuthenticateClientResponseEs11
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [CONTEXT 64]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [CONTEXT 64]")
	}
}

func FuzzBERExpirationDate(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("170d3439313233313233353935395a"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ExpirationDate
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERPrepareDownloadRequest(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf2182015e30158010000102030405060708090a0b0c0d0e0f0101005f3740a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5308201003081b3a003020102020101300506032b65703020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72301e170d3236303130313030303030305a170d3237303130313030303030305a3020311e301c0603550403131541534e2e3120436f6d70696c657220566563746f72302a300506032b657003210079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664a3123010300e0603551d0f0101ff040403020780300506032b657003410068ba274f6ca267f6c3ee16f952c62b403f8e7c6c5d3416c85b12677f24a53edda0b32fb98e5b0e3cfdcf0c4ce51d906eb3c24fb77858ffaf55271d58f6ef9a03"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded PrepareDownloadRequest
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERPrepareDownloadResponse(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf210aa1088003010203020104"))
	f.Add(asn1VectorHexForFuzz("a1088003010203020104"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded PrepareDownloadResponse
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERAuthenticateServerResponse(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf380aa1088003010203020104"))
	f.Add(asn1VectorHexForFuzz("a1088003010203020104"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded AuthenticateServerResponse
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERCancelSessionResponse(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf410381017f"))
	f.Add(asn1VectorHexForFuzz("81017f"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded CancelSessionResponse
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERAuthenticateClientResponseEs9(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf3b0381017f"))
	f.Add(asn1VectorHexForFuzz("81017f"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded AuthenticateClientResponseEs9
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERGetBoundProfilePackageResponse(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf3a0381017f"))
	f.Add(asn1VectorHexForFuzz("81017f"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded GetBoundProfilePackageResponse
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERCancelSessionResponseEs9(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf410381017f"))
	f.Add(asn1VectorHexForFuzz("81017f"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded CancelSessionResponseEs9
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERAuthenticateClientResponseEs11(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("bf400381017f"))
	f.Add(asn1VectorHexForFuzz("81017f"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded AuthenticateClientResponseEs11
		_ = decoded.UnmarshalBER(input)
	})
}
