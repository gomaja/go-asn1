package gsm_map

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

// TestVectorSendRoutingInfoRealCapture verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.2, SendRoutingInfoArg; argument bytes extracted from a real SCCP/TCAP/MAP capture.
func TestVectorSendRoutingInfoRealCapture(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3015800791795210325476830100860791795213111111")
	var decoded SendRoutingInfoArg
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Msisdn", "\"kXlSEDJUdg==\"")
	asn1VectorAssertPath(t, decoded, "InterrogationType", "0")
	asn1VectorAssertPath(t, decoded, "GmscOrGsmSCFAddress", "\"kXlSExEREQ==\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorSendAuthenticationInfoEpsOnly verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.1, SendAuthenticationInfoRes and EPS-AuthenticationSetList.
// Regression: go-asn1-v0.1.9.gsm-map.eps-only-authentication-set
func TestVectorSendAuthenticationInfoEpsOnly(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "a350a24e304c0410000102030405060708090a0b0c0d0e0f0404aabbccdd0410101112131415161718191a1b1c1d1e1f0420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	var decoded SendAuthenticationInfoRes
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "EpsAuthenticationSetList[0].Rand", "\"AAECAwQFBgcICQoLDA0ODw==\"")
	asn1VectorAssertPath(t, decoded, "EpsAuthenticationSetList[0].Xres", "\"qrvM3Q==\"")
	asn1VectorAssertPath(t, decoded, "EpsAuthenticationSetList[0].Autn", "\"EBESExQVFhcYGRobHB0eHw==\"")
	asn1VectorAssertPath(t, decoded, "EpsAuthenticationSetList[0].Kasme", "\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorSendAuthenticationInfoOptionalChoice verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.1, SendAuthenticationInfoRes and AuthenticationSetList.
// Regression: go-asn1-v0.1.9.gsm-map.optional-choice-tag-guard
func TestVectorSendAuthenticationInfoOptionalChoice(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "a326a02430220410000102030405060708090a0b0c0d0e0f0404aabbccdd04081011121314151617")
	var decoded SendAuthenticationInfoRes
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "AuthenticationSetList.Choice", "1")
	asn1VectorAssertPath(t, decoded, "AuthenticationSetList.TripletList[0].Rand", "\"AAECAwQFBgcICQoLDA0ODw==\"")
	asn1VectorAssertPath(t, decoded, "AuthenticationSetList.TripletList[0].Sres", "\"qrvM3Q==\"")
	asn1VectorAssertPath(t, decoded, "AuthenticationSetList.TripletList[0].Kc", "\"EBESExQVFhc=\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorSendAuthenticationInfoMixedOptionals verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.1; optional root and extension authentication fields decode in ASN.1 tag order.
// Regression: go-asn1-v0.4.2.gsm-map.mixed-authentication-optionals
func TestVectorSendAuthenticationInfoMixedOptionals(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "a37ca02430220410000102030405060708090a0b0c0d0e0f0404aabbccdd04081011121314151617a24e304c0410000102030405060708090a0b0c0d0e0f0404aabbccdd0410101112131415161718191a1b1c1d1e1f0420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f830409080706")
	var decoded SendAuthenticationInfoRes
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "AuthenticationSetList.Choice", "1")
	asn1VectorAssertPath(t, decoded, "AuthenticationSetList.TripletList[0].Rand", "\"AAECAwQFBgcICQoLDA0ODw==\"")
	asn1VectorAssertPath(t, decoded, "EpsAuthenticationSetList[0].Rand", "\"AAECAwQFBgcICQoLDA0ODw==\"")
	asn1VectorAssertPath(t, decoded, "EpsAuthenticationSetList[0].Kasme", "\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\"")
	asn1VectorAssertPath(t, decoded, "UeUsageType", "\"CQgHBg==\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorPcsExtensionsPreserveUnknownExtension verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.11; unknown SEQUENCE extension additions are preserved byte-exactly.
// Regression: go-asn1-v0.4.2.gsm-map.pcs-extension-preservation
func TestVectorPcsExtensionsPreserveUnknownExtension(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3003800100")
	var decoded PCSExtensions
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "ExtData_[0]", "\"gAEA\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorShortTermDenialPreserveUnknownExtension verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.6.2; unknown ShortTermDenialParam extension additions are preserved byte-exactly.
// Regression: go-asn1-v0.4.2.gsm-map.short-term-denial-extension-preservation
func TestVectorShortTermDenialPreserveUnknownExtension(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3003800100")
	var decoded ShortTermDenialParam
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "ExtData_[0]", "\"gAEA\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorLongTermDenialPreserveUnknownExtension verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.6.2; unknown LongTermDenialParam extension additions are preserved byte-exactly.
// Regression: go-asn1-v0.4.2.gsm-map.long-term-denial-extension-preservation
func TestVectorLongTermDenialPreserveUnknownExtension(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3003800100")
	var decoded LongTermDenialParam
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "ExtData_[0]", "\"gAEA\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorForwardSmRawAsMo verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.6, MO-ForwardSM-Arg; raw ASN.1 requires caller context for MO versus MT classification.
func TestVectorForwardSmRawAsMo(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "300785008500040100")
	var decoded MOForwardSMArg
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "SmRPDA.Choice", "4")
	asn1VectorAssertPath(t, decoded, "SmRPOA.Choice", "3")
	asn1VectorAssertPath(t, decoded, "SmRPUI", "\"AA==\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorForwardSmRawAsMt verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.6, MT-ForwardSM-Arg; raw ASN.1 requires caller context for MO versus MT classification.
func TestVectorForwardSmRawAsMt(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "300785008500040100")
	var decoded MTForwardSMArg
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "SmRPDA.Choice", "4")
	asn1VectorAssertPath(t, decoded, "SmRPOA.Choice", "3")
	asn1VectorAssertPath(t, decoded, "SmRPUI", "\"AA==\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorReportSmDeliveryStatusFailedServingNodes verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.6; ReportSM-DeliveryStatusArg failedSMServingNodes and both SMServingNodeAddress alternatives.
// Regression: go-asn1-v0.4.2.gsm-map.release-19-failed-serving-nodes
func TestVectorReportSmDeliveryStatusFailedServingNodes(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "302a04029121040291430a0102b21d80029165a117800c736d73662e6578616d706c6581076578616d706c65")
	var decoded ReportSMDeliveryStatusArg
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "FailedSMServingNodes[0].Choice", "1")
	asn1VectorAssertPath(t, decoded, "FailedSMServingNodes[0].NetworkNodeNumber", "\"kWU=\"")
	asn1VectorAssertPath(t, decoded, "FailedSMServingNodes[1].Choice", "2")
	asn1VectorAssertPath(t, decoded, "FailedSMServingNodes[1].DiameterAddress.DiameterName", "\"c21zZi5leGFtcGxl\"")
	asn1VectorAssertPath(t, decoded, "FailedSMServingNodes[1].DiameterAddress.DiameterRealm", "\"ZXhhbXBsZQ==\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorReportSmDeliveryStatusRegisteredServingNodesMax verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.6; ReportSM-DeliveryStatusRes registeredSMServingNodes at maxNumOfSMServingNodeAddresses 5.
// Regression: go-asn1-v0.4.2.gsm-map.release-19-registered-serving-nodes
// Regression: go-asn1-v0.4.2.gsm-map.sm-serving-node-list-upper-bound
func TestVectorReportSmDeliveryStatusRegisteredServingNodesMax(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3011a00f800191800192800193800194800195")
	var decoded ReportSMDeliveryStatusRes
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "RegisteredSMServingNodes[0].NetworkNodeNumber", "\"kQ==\"")
	asn1VectorAssertPath(t, decoded, "RegisteredSMServingNodes[4].NetworkNodeNumber", "\"lQ==\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorSmServingNodeListEmpty verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.6; SMServingNodeAddressList requires at least one element.
// Regression: go-asn1-v0.4.2.gsm-map.sm-serving-node-list-lower-bound
func TestVectorSmServingNodeListEmpty(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3002a000")
	var decoded ReportSMDeliveryStatusRes
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "SIZE (1..5)") {
		t.Fatalf("decode error = %q, want substring %q", err, "SIZE (1..5)")
	}
}

// TestVectorSmServingNodeListOverMaximum verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.6; SMServingNodeAddressList rejects more than maxNumOfSMServingNodeAddresses 5.
// Regression: go-asn1-v0.4.2.gsm-map.sm-serving-node-list-over-maximum
func TestVectorSmServingNodeListOverMaximum(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3014a012800191800192800193800194800195800196")
	var decoded ReportSMDeliveryStatusRes
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "SIZE (1..5)") {
		t.Fatalf("decode error = %q, want substring %q", err, "SIZE (1..5)")
	}
}

// TestVectorSmServingNodeDiameterAddressMissingRealm verifies 3GPP TS 29.002 V19.1.0 (2026-02), sections 17.7.6 and 17.7.8; NetworkNodeDiameterAddress requires both diameterName and diameterRealm.
// Regression: go-asn1-v0.4.2.gsm-map.sm-serving-node-diameter-address-malformed
func TestVectorSmServingNodeDiameterAddressMissingRealm(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "301d04029121040291430a0102b210a10e800c736d73662e6578616d706c65")
	var decoded ReportSMDeliveryStatusArg
	err := decoded.UnmarshalBER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "diameter-Realm") {
		t.Fatalf("decode error = %q, want substring %q", err, "diameter-Realm")
	}
}

// TestVectorReportSmDeliveryStatusUnknownExtension verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.6; unknown ReportSM-DeliveryStatusRes extension additions remain byte-exact.
// Regression: go-asn1-v0.4.2.gsm-map.report-status-extension-preservation
func TestVectorReportSmDeliveryStatusUnknownExtension(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3003810100")
	var decoded ReportSMDeliveryStatusRes
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "ExtData_[0]", "\"gQEA\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

func FuzzBERSendRoutingInfoArg(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("3015800791795210325476830100860791795213111111"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded SendRoutingInfoArg
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERSendAuthenticationInfoRes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("a350a24e304c0410000102030405060708090a0b0c0d0e0f0404aabbccdd0410101112131415161718191a1b1c1d1e1f0420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
	f.Add(asn1VectorHexForFuzz("a326a02430220410000102030405060708090a0b0c0d0e0f0404aabbccdd04081011121314151617"))
	f.Add(asn1VectorHexForFuzz("a37ca02430220410000102030405060708090a0b0c0d0e0f0404aabbccdd04081011121314151617a24e304c0410000102030405060708090a0b0c0d0e0f0404aabbccdd0410101112131415161718191a1b1c1d1e1f0420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f830409080706"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded SendAuthenticationInfoRes
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERPCSExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("3003800100"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded PCSExtensions
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERShortTermDenialParam(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("3003800100"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ShortTermDenialParam
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERLongTermDenialParam(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("3003800100"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded LongTermDenialParam
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERMOForwardSMArg(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("300785008500040100"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded MOForwardSMArg
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERMTForwardSMArg(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("300785008500040100"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded MTForwardSMArg
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERReportSMDeliveryStatusArg(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("302a04029121040291430a0102b21d80029165a117800c736d73662e6578616d706c6581076578616d706c65"))
	f.Add(asn1VectorHexForFuzz("301d04029121040291430a0102b210a10e800c736d73662e6578616d706c65"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ReportSMDeliveryStatusArg
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERReportSMDeliveryStatusRes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("3011a00f800191800192800193800194800195"))
	f.Add(asn1VectorHexForFuzz("3002a000"))
	f.Add(asn1VectorHexForFuzz("3014a012800191800192800193800194800195800196"))
	f.Add(asn1VectorHexForFuzz("3003810100"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ReportSMDeliveryStatusRes
		_ = decoded.UnmarshalBER(input)
	})
}
