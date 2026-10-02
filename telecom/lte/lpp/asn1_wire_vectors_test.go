package lpp

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

// TestVectorStandaloneEllipsoidPoint verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, Ellipsoid-Point.
func TestVectorStandaloneEllipsoidPoint(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "400000400000")
	var decoded EllipsoidPoint
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneEllipsoidPointWithUncertaintyCircle verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, Ellipsoid-PointWithUncertaintyCircle.
func TestVectorStandaloneEllipsoidPointWithUncertaintyCircle(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "40000040000036")
	var decoded EllipsoidPointWithUncertaintyCircle
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneEllipsoidPointWithUncertaintyEllipse verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, EllipsoidPointWithUncertaintyEllipse.
func TestVectorStandaloneEllipsoidPointWithUncertaintyEllipse(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "4000004000000a0d6a20")
	var decoded EllipsoidPointWithUncertaintyEllipse
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneEllipsoidPointWithAltitude verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, EllipsoidPointWithAltitude.
func TestVectorStandaloneEllipsoidPointWithAltitude(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "40000040000004d2")
	var decoded EllipsoidPointWithAltitude
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneEllipsoidPointWithAltitudeAndUncertaintyEllipsoid verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, EllipsoidPointWithAltitudeAndUncertaintyEllipsoid.
func TestVectorStandaloneEllipsoidPointWithAltitudeAndUncertaintyEllipsoid(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "40000040000084d20a0d685440")
	var decoded EllipsoidPointWithAltitudeAndUncertaintyEllipsoid
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneEllipsoidArc verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, EllipsoidArc.
func TestVectorStandaloneEllipsoidArc(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "40000040000003e80e5ab510")
	var decoded EllipsoidArc
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneHorizontalVelocity verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, HorizontalVelocity.
func TestVectorStandaloneHorizontalVelocity(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "2d2000")
	var decoded HorizontalVelocity
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneHorizontalWithVerticalVelocity verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, HorizontalWithVerticalVelocity.
func TestVectorStandaloneHorizontalWithVerticalVelocity(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "2d200320")
	var decoded HorizontalWithVerticalVelocity
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneHorizontalVelocityWithUncertainty verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, HorizontalVelocityWithUncertainty.
func TestVectorStandaloneHorizontalVelocityWithUncertainty(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "2d200070")
	var decoded HorizontalVelocityWithUncertainty
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorStandaloneHorizontalWithVerticalVelocityAndUncertainty verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, HorizontalWithVerticalVelocityAndUncertainty.
func TestVectorStandaloneHorizontalWithVerticalVelocityAndUncertainty(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "2d200b203858")
	var decoded HorizontalWithVerticalVelocityAndUncertainty
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassRequestCapabilities verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class requestCapabilities.
func TestVectorFullClassRequestCapabilities(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "100000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "1")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassProvideCapabilities verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class provideCapabilities.
func TestVectorFullClassProvideCapabilities(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "104000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "2")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassRequestAssistanceData verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class requestAssistanceData.
func TestVectorFullClassRequestAssistanceData(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "108000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "3")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassProvideAssistanceData verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class provideAssistanceData.
func TestVectorFullClassProvideAssistanceData(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "10c000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "4")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassRequestLocationInformation verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class requestLocationInformation.
func TestVectorFullClassRequestLocationInformation(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "110000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "5")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassProvideLocationInformation verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class provideLocationInformation.
func TestVectorFullClassProvideLocationInformation(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "114000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassAbort verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class abort.
func TestVectorFullClassAbort(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "1180")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "7")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullClassError verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, class error.
func TestVectorFullClassError(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "11c0")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "8")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullShapeEllipsoidPoint verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, shape Ellipsoid Point.
func TestVectorFullShapeEllipsoidPoint(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "11420808000008000000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.EllipsoidPoint.DegreesLatitude", "4194304")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.EllipsoidPoint.DegreesLongitude", "-4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullShapeEllipsoidPointWithUncertaintyCircle verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, shape Ellipsoid PointWithUncertaintyCircle.
func TestVectorFullShapeEllipsoidPointWithUncertaintyCircle(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "11420828000008000006c0")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.EllipsoidPointWithUncertaintyCircle.DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullShapeEllipsoidPointWithUncertaintyEllipse verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, shape EllipsoidPointWithUncertaintyEllipse.
func TestVectorFullShapeEllipsoidPointWithUncertaintyEllipse(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "1142084800000800000141ad44")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.EllipsoidPointWithUncertaintyEllipse.DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullShapeEllipsoidPointWithAltitude verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, shape EllipsoidPointWithAltitude.
func TestVectorFullShapeEllipsoidPointWithAltitude(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "114208880000080000009a40")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.EllipsoidPointWithAltitude.DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullShapeEllipsoidPointWithAltitudeAndUncertaintyEllipsoid verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, shape EllipsoidPointWithAltitudeAndUncertaintyEllipsoid.
func TestVectorFullShapeEllipsoidPointWithAltitudeAndUncertaintyEllipsoid(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "114208a80000080000109a4141ad0a88")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.EllipsoidPointWithAltitudeAndUncertaintyEllipsoid.DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullShapeEllipsoidArc verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, shape EllipsoidArc.
func TestVectorFullShapeEllipsoidArc(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "114208c80000080000007d01cb56a200")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.EllipsoidArc.DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullShapePolygon verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, shape Polygon.
func TestVectorFullShapePolygon(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "114208608000008000011e848125ad0e989680800000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.LocationEstimate.Polygon[0].DegreesLatitude", "4194304")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullVelocityHorizontalVelocity verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, velocity HorizontalVelocity.
func TestVectorFullVelocityHorizontalVelocity(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "1142040b4800")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.VelocityEstimate.HorizontalVelocity.HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullVelocityHorizontalWithVerticalVelocity verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, velocity HorizontalWithVerticalVelocity.
func TestVectorFullVelocityHorizontalWithVerticalVelocity(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "1142044b4800c8")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.VelocityEstimate.HorizontalWithVerticalVelocity.HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullVelocityHorizontalVelocityWithUncertainty verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, velocity HorizontalVelocityWithUncertainty.
func TestVectorFullVelocityHorizontalVelocityWithUncertainty(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "1142048b48001c")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.VelocityEstimate.HorizontalVelocityWithUncertainty.HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullVelocityHorizontalWithVerticalVelocityAndUncertainty verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, velocity HorizontalWithVerticalVelocityAndUncertainty.
func TestVectorFullVelocityHorizontalWithVerticalVelocityAndUncertainty(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "114204cb4802c80e16")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.VelocityEstimate.HorizontalWithVerticalVelocityAndUncertainty.HorizontalSpeed", "512")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullGnssTodMsec verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, gnss TOD msec.
func TestVectorFullGnssTodMsec(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "11410804b5a1c0000000001780000000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.AGnssProvideLocationInformation.GnssSignalMeasurementInformation.MeasurementReferenceTime.GnssTODMsec", "1234567")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorFullExtensionEarlyFixReport verifies 3GPP TS 37.355 V19.3.0 (Release 19) clause 6.2, CommonIEsProvideLocationInformation extension additions; ITU-T X.691 (02/2021) clauses 11.9.3.4 and 19.8.
func TestVectorFullExtensionEarlyFixReport(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "1142100e006000")
	var decoded LPPMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.Choice", "6")
	asn1VectorAssertPath(t, decoded, "LppMessageBody.C1.ProvideLocationInformation.CriticalExtensions.C1.ProvideLocationInformationR9.CommonIEsProvideLocationInformation.EarlyFixReportR12", "0")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

func FuzzUPEREllipsoidPoint(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("400000400000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded EllipsoidPoint
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPEREllipsoidPointWithUncertaintyCircle(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("40000040000036"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded EllipsoidPointWithUncertaintyCircle
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPEREllipsoidPointWithUncertaintyEllipse(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("4000004000000a0d6a20"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded EllipsoidPointWithUncertaintyEllipse
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPEREllipsoidPointWithAltitude(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("40000040000004d2"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded EllipsoidPointWithAltitude
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPEREllipsoidPointWithAltitudeAndUncertaintyEllipsoid(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("40000040000084d20a0d685440"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded EllipsoidPointWithAltitudeAndUncertaintyEllipsoid
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPEREllipsoidArc(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("40000040000003e80e5ab510"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded EllipsoidArc
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERHorizontalVelocity(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("2d2000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded HorizontalVelocity
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERHorizontalWithVerticalVelocity(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("2d200320"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded HorizontalWithVerticalVelocity
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERHorizontalVelocityWithUncertainty(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("2d200070"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded HorizontalVelocityWithUncertainty
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERHorizontalWithVerticalVelocityAndUncertainty(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("2d200b203858"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded HorizontalWithVerticalVelocityAndUncertainty
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERLPPMessage(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("100000"))
	f.Add(asn1VectorHexForFuzz("104000"))
	f.Add(asn1VectorHexForFuzz("108000"))
	f.Add(asn1VectorHexForFuzz("10c000"))
	f.Add(asn1VectorHexForFuzz("110000"))
	f.Add(asn1VectorHexForFuzz("114000"))
	f.Add(asn1VectorHexForFuzz("1180"))
	f.Add(asn1VectorHexForFuzz("11c0"))
	f.Add(asn1VectorHexForFuzz("11420808000008000000"))
	f.Add(asn1VectorHexForFuzz("11420828000008000006c0"))
	f.Add(asn1VectorHexForFuzz("1142084800000800000141ad44"))
	f.Add(asn1VectorHexForFuzz("114208880000080000009a40"))
	f.Add(asn1VectorHexForFuzz("114208a80000080000109a4141ad0a88"))
	f.Add(asn1VectorHexForFuzz("114208c80000080000007d01cb56a200"))
	f.Add(asn1VectorHexForFuzz("114208608000008000011e848125ad0e989680800000"))
	f.Add(asn1VectorHexForFuzz("1142040b4800"))
	f.Add(asn1VectorHexForFuzz("1142044b4800c8"))
	f.Add(asn1VectorHexForFuzz("1142048b48001c"))
	f.Add(asn1VectorHexForFuzz("114204cb4802c80e16"))
	f.Add(asn1VectorHexForFuzz("11410804b5a1c0000000001780000000"))
	f.Add(asn1VectorHexForFuzz("1142100e006000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded LPPMessage
		_ = decoded.UnmarshalUPER(input)
	})
}
