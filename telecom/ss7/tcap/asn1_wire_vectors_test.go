package tcap

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

// TestVectorComponentPortionReturnResult verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, ComponentPortion and returnResultLast.
// Regression: go-asn1-v0.5.0.tcap.component-portion-application-tag
func TestVectorComponentPortionReturnResult(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "6c0fa20d02017f300802012d0403deadbe")
	decoded, err := UnmarshalBERComponentPortion(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "[0].Choice", "1")
	asn1VectorAssertPath(t, decoded, "[0].BasicROS.Choice", "2")
	asn1VectorAssertPath(t, decoded, "[0].BasicROS.ReturnResult.InvokeId.Choice", "1")
	wire, err := MarshalBERComponentPortion(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorEndReturnResult verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, End and ComponentPortion.
// Regression: go-asn1-v0.5.0.tcap.return-result-structured
func TestVectorEndReturnResult(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "64144901016c0fa20d02017f300802012d0403deadbe")
	var decoded TCMessage
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "3")
	asn1VectorAssertPath(t, decoded, "End.Dtid", "\"AQ==\"")
	asn1VectorAssertPath(t, decoded, "End.Components[0].Choice", "1")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorBeginIndefiniteComponentPortion verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, Begin and ComponentPortion; ITU-T X.690 (02/2021), section 8.1.3.6, indefinite form.
// Regression: go-asn1-v0.5.0.tcap.indefinite-component-round-trip
func TestVectorBeginIndefiniteComponentPortion(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "620f4801016c80a10602010002012d0000")
	var decoded TCMessage
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	asn1VectorAssertPath(t, decoded, "Begin.Otid", "\"AQ==\"")
	asn1VectorAssertPath(t, decoded, "Begin.Components[0].Choice", "1")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorBeginDialogueExplicitExternal verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, Begin dialoguePortion [APPLICATION 11] EXPLICIT EXTERNAL.
// Regression: go-asn1-v0.5.0.tcap.begin-dialogue-explicit-external
func TestVectorBeginDialogueExplicitExternal(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "30144801016b0f280d06070011860501010180026000")
	var decoded Begin
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Otid", "\"AQ==\"")
	asn1VectorAssertPath(t, decoded, "DialoguePortion.Bytes", "\"KA0GBwARhgUBAQGAAmAA\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorAbortReasonPAbortApplicationTag verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, Abort-reason p-abortCause [APPLICATION 10].
// Regression: go-asn1-v0.5.0.tcap.abort-reason-p-abort-application-tag
func TestVectorAbortReasonPAbortApplicationTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "4a0102")
	var decoded AbortReason
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "1")
	asn1VectorAssertPath(t, decoded, "PAbortCause", "2")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorAbortReasonUAbortApplicationTag verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, Abort-reason u-abortCause [APPLICATION 11] EXPLICIT EXTERNAL.
// Regression: go-asn1-v0.5.0.tcap.abort-reason-u-abort-application-tag
func TestVectorAbortReasonUAbortApplicationTag(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "6b0f280d06070011860501010180026000")
	var decoded AbortReason
	err := decoded.UnmarshalBER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, decoded, "Choice", "2")
	asn1VectorAssertPath(t, decoded, "UAbortCause.Bytes", "\"KA0GBwARhgUBAQGAAmAA\"")
	wire, err := decoded.MarshalBER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("round trip = %x, want %x", wire, input)
	}
}

// TestVectorComponentPortionEmptyRejected verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, ComponentPortion SIZE (1..MAX).
// Regression: go-asn1-v0.5.0.tcap.component-portion-size-lower-bound
func TestVectorComponentPortionEmptyRejected(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "6c00")
	_, err := UnmarshalBERComponentPortion(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "SIZE (1..MAX)") {
		t.Fatalf("decode error = %q, want substring %q", err, "SIZE (1..MAX)")
	}
}

// TestVectorComponentPortionUniversalSequenceRejected verifies ITU-T Q.773 (06/1997), in force, Annex A TCAPMessages module, ComponentPortion [APPLICATION 12].
// Regression: go-asn1-v0.5.0.tcap.component-portion-universal-tag-rejected
func TestVectorComponentPortionUniversalSequenceRejected(t *testing.T) {
	t.Parallel()
	input := asn1VectorHex(t, "3000")
	_, err := UnmarshalBERComponentPortion(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "expected tag [APPLICATION 12]") {
		t.Fatalf("decode error = %q, want substring %q", err, "expected tag [APPLICATION 12]")
	}
}

func FuzzBERComponentPortion(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("6c0fa20d02017f300802012d0403deadbe"))
	f.Add(asn1VectorHexForFuzz("6c00"))
	f.Add(asn1VectorHexForFuzz("3000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = UnmarshalBERComponentPortion(input)
	})
}

func FuzzBERTCMessage(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("64144901016c0fa20d02017f300802012d0403deadbe"))
	f.Add(asn1VectorHexForFuzz("620f4801016c80a10602010002012d0000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded TCMessage
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERBegin(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("30144801016b0f280d06070011860501010180026000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded Begin
		_ = decoded.UnmarshalBER(input)
	})
}

func FuzzBERAbortReason(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("4a0102"))
	f.Add(asn1VectorHexForFuzz("6b0f280d06070011860501010180026000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded AbortReason
		_ = decoded.UnmarshalBER(input)
	})
}
