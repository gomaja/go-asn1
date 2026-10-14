package ber

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
)

func externalOptionEncoder(t *testing.T) func(runtime.External, ...EncodeOption) ([]byte, error) {
	t.Helper()
	encode, ok := any(EncodeExternal).(func(runtime.External, ...EncodeOption) ([]byte, error))
	if !ok {
		t.Fatal("EncodeExternal does not accept encode options")
	}
	return encode
}

// X.690 (02/2021) §§8.18.1, 8.18.9–8.18.11: the runtime's replay
// policy rebuilds typed octet/bit alternatives and refuses opaque open values.
func TestExternalEncodeReplayPolicy(t *testing.T) {
	encode := externalOptionEncoder(t)
	for _, test := range []struct{ wire, rebuilt string }{
		{"2880020101a18004014104014200000000", "280702010181024142"},
		{"28810702010181810141", "2806020101810141"},
		{"2880020101820203af0000", "2807020101820203a8"},
	} {
		t.Run(test.wire, func(t *testing.T) {
			wire := structureWire(t, test.wire)
			value, n, err := DecodeExternal(wire)
			if err != nil || n != len(wire) {
				t.Fatalf("decode n=%d: %v", n, err)
			}
			replay, err := encode(value)
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("default replay %x: %v", replay, err)
			}
			rebuilt, err := encode(value, WithoutBERReplay(), WithoutBERReplay())
			if err != nil || !bytes.Equal(rebuilt, structureWire(t, test.rebuilt)) {
				t.Fatalf("typed rebuild %x: %v", rebuilt, err)
			}
			replay, err = encode(value)
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("policy changed stored provenance: %x %v", replay, err)
			}
			value.IndirectReference.SetInt64(2)
			edited, err := encode(value)
			if err != nil || bytes.Equal(edited, wire) {
				t.Fatalf("edit replayed old value %x: %v", edited, err)
			}
		})
	}
}

func TestExternalEncodeOptionsRejectOpaqueReplay(t *testing.T) {
	encode := externalOptionEncoder(t)
	for _, wireText := range []string{"2880020101a00302012a0000", "2808020101a00302012a"} {
		wire := structureWire(t, wireText)
		value, _, err := DecodeExternal(wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, edit := range []bool{false, true} {
			if edit {
				value.IndirectReference.SetInt64(2)
			}
			var reports ViolationLog
			result, err := encode(value, WithoutBERReplay(), WithConstraintTolerance(&reports))
			if result != nil || !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("opaque edit=%t: %x %v", edit, result, err)
			}
			if len(reports.Snapshot()) != 0 {
				t.Fatal("opaque refusal published reports")
			}
		}
	}
	value := runtime.External{IndirectReference: big.NewInt(1), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: runtime.RawValue{Bytes: structureWire(t, "02012a")}}
	if _, err := encode(value, WithoutBERReplay()); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("new opaque value: %v", err)
	}
}

func TestExternalEncodeValidatesOptionsBeforeReplay(t *testing.T) {
	encode := externalOptionEncoder(t)
	value, _, err := DecodeExternal(structureWire(t, "28800201018101410000"))
	if err != nil {
		t.Fatal(err)
	}
	var reports ViolationLog
	for _, options := range [][]EncodeOption{
		{nil}, {WithConstraintTolerance(nil)},
		{WithConstraintTolerance(&reports), WithConstraintTolerance(&reports)},
		ChildEncodeOptions(nil, "bad.path"), ChildEncodeOptions(nil, ""),
	} {
		want := ValidateEncodeOptions(options...)
		result, got := encode(value, options...)
		if result != nil || got == nil || want == nil || got.Error() != want.Error() {
			t.Fatalf("encode %x %v, validator %v", result, got, want)
		}
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("option failure published reports")
	}
	der, err := EncodeExternalDER(value)
	if err != nil || !bytes.Equal(der, structureWire(t, "2806020101810141")) {
		t.Fatalf("DER %x: %v", der, err)
	}
}
