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

// TestVectorUlDcchMeasurementReport verifies 3GPP TS 36.331 V19.3.0 (2026-08), sections 5.5.5 and 6.2.2; UL-DCCH MeasurementReport with serving and E-UTRA neighbour measurements.
func TestVectorUlDcchMeasurementReport(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "083024342625237d91f0011f1080064a2900491000")
	var decoded ULDCCHMessage
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Message.Choice", "1")
	asn1VectorAssertPath(t, decoded, "Message.C1.Choice", "2")
	asn1VectorAssertPath(t, decoded, "Message.C1.MeasurementReport.CriticalExtensions.C1.MeasurementReportR8.MeasResults.MeasId", "1")
	asn1VectorAssertPath(t, decoded, "Message.C1.MeasurementReport.CriticalExtensions.C1.MeasurementReportR8.MeasResults.MeasResultPCell.RsrpResult", "36")
	asn1VectorAssertPath(t, decoded, "Message.C1.MeasurementReport.CriticalExtensions.C1.MeasurementReportR8.MeasResults.MeasResultNeighCells.MeasResultListEUTRA[0].PhysCellId", "393")
	asn1VectorAssertPath(t, decoded, "Message.C1.MeasurementReport.CriticalExtensions.C1.MeasurementReportR8.MeasResults.MeasResultNeighCells.MeasResultListEUTRA[0].MeasResult.RsrpResult", "35")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorLoggedMeasurementConfigurationV1800 verifies 3GPP TS 36.331 V19.3.0 (2026-08), section 6.2.2, LoggedMeasurementConfiguration-v1800-IEs.
func TestVectorLoggedMeasurementConfigurationV1800(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "80")
	var decoded LoggedMeasurementConfigurationV1800IEs
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "SigLoggedMeasTypeR18", "0")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorReconfigurationCompleteV1800 verifies 3GPP TS 36.331 V19.3.0 (2026-08), section 6.2.2, RRCConnectionReconfigurationComplete-v1800-IEs.
func TestVectorReconfigurationCompleteV1800(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "a8")
	var decoded RRCConnectionReconfigurationCompleteV1800IEs
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "GnssPositionFixDurationR18", "10")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorSystemInformationBlockType33R18 verifies 3GPP TS 36.331 V19.3.0 (2026-08), section 6.3.1, SystemInformationBlockType33-r18.
func TestVectorSystemInformationBlockType33R18(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "21")
	var decoded SystemInformationBlockType33R18
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "NeighValidityDurationR18", "1")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorNtnParametersNbV1800 verifies 3GPP TS 36.331 V19.3.0 (2026-08), section 6.7.3.6, NTN-Parameters-NB-v1800.
func TestVectorNtnParametersNbV1800(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "000180")
	var decoded NTNParametersNBV1800
	err := decoded.UnmarshalUPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "NtnGNSSEnhScenarioSupportR18", "1")
	wire, err := decoded.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

func FuzzUPERULDCCHMessage(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("083024342625237d91f0011f1080064a2900491000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded ULDCCHMessage
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERLoggedMeasurementConfigurationV1800IEs(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded LoggedMeasurementConfigurationV1800IEs
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERRRCConnectionReconfigurationCompleteV1800IEs(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("a8"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded RRCConnectionReconfigurationCompleteV1800IEs
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERSystemInformationBlockType33R18(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("21"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded SystemInformationBlockType33R18
		_ = decoded.UnmarshalUPER(input)
	})
}

func FuzzUPERNTNParametersNBV1800(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000180"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded NTNParametersNBV1800
		_ = decoded.UnmarshalUPER(input)
	})
}
