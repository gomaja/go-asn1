package ber

import (
	"encoding/hex"
	"errors"
	"testing"
)

// X.690 (02/2021) fixes the form of these universal types: BOOLEAN (§8.2.1),
// INTEGER (§8.3.1), ENUMERATED (§8.4), REAL (§8.5.1), NULL (§8.8.1), OBJECT
// IDENTIFIER (§8.19.1), RELATIVE-OID (§8.20.1), the OID IRI types (§§8.21.1,
// 8.22.1) and the time types (§§8.26.1.1–8.26.5.1) are primitive; SEQUENCE
// and SEQUENCE OF (§§8.9.1, 8.10.1), SET and SET OF (§§8.11.1, 8.12.1),
// EMBEDDED PDV (§8.17.1), EXTERNAL (§8.18.1) and CHARACTER STRING (§8.24.1)
// are constructed. The scanner run by every generated
// entry point must reject the other form with either length form, alone or
// nested.
func TestValidateBERElementUniversalForms(t *testing.T) {
	invalid := map[string]string{
		"constructed BOOLEAN":              "21030101ff",
		"indefinite BOOLEAN":               "21800101ff0000",
		"constructed INTEGER":              "2203020101",
		"indefinite INTEGER":               "22800201010000",
		"constructed ENUMERATED":           "2a030a0101",
		"indefinite ENUMERATED":            "2a800a01010000",
		"constructed REAL":                 "29020900",
		"indefinite REAL":                  "298009000000",
		"constructed NULL":                 "2500",
		"indefinite NULL":                  "25800000",
		"constructed OBJECT IDENTIFIER":    "260306012a",
		"indefinite OBJECT IDENTIFIER":     "268006012a0000",
		"constructed RELATIVE-OID":         "2d030d0101",
		"indefinite RELATIVE-OID":          "2d800d01010000",
		"primitive SEQUENCE":               "1000",
		"primitive SET":                    "1100",
		"primitive EXTERNAL":               "0800",
		"primitive EMBEDDED PDV":           "0b00",
		"primitive CHARACTER STRING":       "1d00",
		"indefinite TIME":                  "2e80" + "0e0130" + "0000",
		"constructed DATE":                 "3f1f00",
		"constructed TIME-OF-DAY":          "3f2000",
		"constructed DATE-TIME":            "3f2100",
		"constructed DURATION":             "3f2200",
		"constructed OID-IRI (tag 35)":     "3f2300",
		"constructed relative OID-IRI":     "3f2400",
		"nested indefinite INTEGER":        "300722800201010000",
		"nested primitive SET":             "30021100",
		"indefinite parent, bad child":     "3080220302010100" + "00",
		"implicit SEQUENCE child, bad INT": "a0072280020101" + "0000",
	}
	for name, wire := range invalid {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBERElement(data); !errors.Is(err, ErrInvalidTag) {
			t.Errorf("%s %s: error = %v, want ErrInvalidTag", name, wire, err)
		}
	}
	valid := []string{
		"0101ff", "020101", "0a0101", "0900", "0500", "06012a", "0d0101",
		"3000", "3100", "30800000", "2800", "2b00", "3d00", "1f230130", "0e0130", "1f1f00", "a2030201ff", "a280020101" + "0000",
		"2403040107", "24800401070000", "300302010a",
	}
	for _, wire := range valid {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBERElement(data); err != nil {
			t.Errorf("valid %s: %v", wire, err)
		}
	}
}

// The typed decoders enforce the same forms after DecodeTLV, which accepts
// an indefinite length on any constructed element.
func TestTypedDecodersRejectIndefiniteConstructedPrimitives(t *testing.T) {
	for name, wire := range map[string]string{
		"DecodeBoolean": "21800101ff0000", "DecodeInteger": "22800201010000", "DecodeUint64": "22800201010000",
		"DecodeBigInt": "22800201010000", "DecodeEnumerated": "2a800a01010000", "DecodeReal": "298009000000",
		"DecodeNull": "25800000", "DecodeObjectIdentifier": "268006012a0000",
	} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := formDecoders[name](data); !errors.Is(err, ErrInvalidTag) {
			t.Errorf("%s(%s) error = %v, want ErrInvalidTag", name, wire, err)
		}
	}
	data, _ := hex.DecodeString("2d800d01010000")
	if _, _, err := DecodeRelativeObjectIdentifier(data); !errors.Is(err, ErrInvalidTag) {
		t.Errorf("DecodeRelativeObjectIdentifier error = %v, want ErrInvalidTag", err)
	}
	data, _ = hex.DecodeString("1000")
	if _, _, err := DecodeSequenceContent(data); !errors.Is(err, ErrInvalidTag) {
		t.Errorf("DecodeSequenceContent(primitive) error = %v, want ErrInvalidTag", err)
	}
	data, _ = hex.DecodeString("0800")
	if _, _, err := DecodeExternal(data); !errors.Is(err, ErrInvalidTag) {
		t.Errorf("DecodeExternal(primitive) error = %v, want ErrInvalidTag", err)
	}
}

// The DER validator applies the same universal forms.
func TestValidateDERElementUniversalForms(t *testing.T) {
	for _, wire := range []string{"1d00", "3f1f00", "3f2000", "3f2100", "3f2200", "3f2300", "3f2400", "2e03" + "0e0130"} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateDEREncodedElement(data); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("DER %s: error = %v, want ErrInvalidValue", wire, err)
		}
	}
	for _, wire := range []string{"3d00", "1f230130", "0e0130", "1f1f00"} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateDEREncodedElement(data); err != nil {
			t.Errorf("DER %s: %v", wire, err)
		}
	}
}
