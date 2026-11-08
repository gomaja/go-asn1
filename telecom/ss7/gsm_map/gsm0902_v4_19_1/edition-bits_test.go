package gsm0902_v4_19_1

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"reflect"
	"strings"
	"testing"
)

// X.208 (11/1988) §§17.10, 37.4.3–37.4.4; X.209 (11/1988) §11.2.
func TestEditionNamedBitLengths(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int
		codec ValueCodec[BERValue[runtime.BitString]]
	}{
		{"ODB-GeneralData", 6, ODBGeneralDataCodec()},
		{"ODB-HPLMN-Data", 4, ODBHPLMNDataCodec()},
		{"MW-Status", 6, MWStatusCodec()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, length := range []int{0, 1, tc.size - 1, tc.size, tc.size + 1, 8, 9, 16} {
				t.Run(fmt.Sprintf("%d-bits", length), func(t *testing.T) {
					storage := make([]byte, (length+7)/8)
					if length > 0 {
						storage[0] = 0x80
					}
					wire, err := ber.EncodeBitString(storage, (8-length%8)%8)
					if err != nil {
						t.Fatal(err)
					}
					value, err := tc.codec.DecodeBER(wire)
					if length == tc.size {
						if err != nil || value.Value.BitLength != length || !bytes.Equal(value.Value.Bytes, storage) {
							t.Fatalf("exact bits changed: length=%d: %v", length, err)
						}
						for _, encode := range []func(BERValue[runtime.BitString]) ([]byte, error){
							func(v BERValue[runtime.BitString]) ([]byte, error) { return tc.codec.EncodeBER(v) },
							func(v BERValue[runtime.BitString]) ([]byte, error) {
								return tc.codec.EncodeBER(v, ber.WithoutBERReplay())
							},
							tc.codec.EncodeDER,
						} {
							got, e := encode(value)
							if e != nil || !bytes.Equal(got, wire) {
								t.Fatalf("received bits not preserved: %v", e)
							}
							got, e = encode(BERValue[runtime.BitString]{Value: value.Value})
							if e != nil || !bytes.Equal(got, wire) {
								t.Fatalf("fresh bits not preserved: %v", e)
							}
						}
						return
					}
					requireEditionBitSizeError(t, err, length)
					var reports ber.ViolationLog
					value, err = tc.codec.DecodeBER(wire, ber.WithTolerance(&reports))
					if err != nil || len(reports.Snapshot()) != 1 || value.Value.BitLength != length || !bytes.Equal(value.Value.Bytes, storage) {
						t.Fatalf("tolerance changed bits length=%d reports=%d: %v", length, len(reports.Snapshot()), err)
					}
					if reports.Snapshot()[0].ObservedLength == nil || *reports.Snapshot()[0].ObservedLength != length || reports.Snapshot()[0].Rule.Edition != "11/1988" {
						t.Fatalf("wrong tolerance finding: %+v", reports.Snapshot()[0])
					}
					replay, e := tc.codec.EncodeBER(value, ber.WithTolerance(&reports))
					if e != nil || !bytes.Equal(replay, wire) {
						t.Fatalf("tolerant replay changed bits: %v", e)
					}
					_, err = tc.codec.EncodeBER(BERValue[runtime.BitString]{Value: runtime.BitString{Bytes: storage, BitLength: length}})
					requireEditionBitSizeError(t, err, length)
					_, err = tc.codec.EncodeDER(BERValue[runtime.BitString]{Value: runtime.BitString{Bytes: storage, BitLength: length}})
					requireEditionBitSizeError(t, err, length)
				})
			}
		})
	}
}
func requireEditionBitSizeError(t *testing.T, err error, length int) {
	t.Helper()
	var v *ber.ValidationError
	if !errors.As(err, &v) || v.ObservedLength == nil || *v.ObservedLength != length || !strings.Contains(v.Constraint, "SIZE") || !strings.Contains(v.Rule.Document, "X.208") || v.Rule.Edition != "11/1988" || !strings.Contains(v.Rule.Clause, "17.10") || !strings.Contains(v.Rule.Clause, "37.4") || !strings.Contains(v.Rule.Clause, "11.2") {
		t.Fatalf("missing historical SIZE finding for %d bits: %+v / %v", length, v, err)
	}
}

func TestEditionNamedBitComponentLengths(t *testing.T) {
	for _, tc := range []struct {
		name               string
		codec              *MacroType
		valid, short, long []byte
	}{
		{"general", newMacroType("MAP-MS-DataTypes", "ODB-Data", "ODBData", ODBDataCodec()), []byte{0x30, 4, 3, 2, 2, 0x80}, []byte{0x30, 4, 3, 2, 3, 0x80}, []byte{0x30, 4, 3, 2, 1, 0x80}},
		{"hplmn", newMacroType("MAP-MS-DataTypes", "ODB-Data", "ODBData", ODBDataCodec()), []byte{0x30, 8, 3, 2, 2, 0x80, 3, 2, 4, 0x80}, []byte{0x30, 8, 3, 2, 2, 0x80, 3, 2, 5, 0x80}, []byte{0x30, 8, 3, 2, 2, 0x80, 3, 2, 3, 0x80}},
		{"message-waiting", newMacroType("MAP-SM-DataTypes", "InformServiceCentreArg", "InformServiceCentreArg", InformServiceCentreArgCodec()), []byte{0x30, 4, 3, 2, 2, 0x80}, []byte{0x30, 4, 3, 2, 3, 0x80}, []byte{0x30, 4, 3, 2, 1, 0x80}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := tc.codec.DecodeBER(tc.valid)
			if err != nil {
				t.Fatal(err)
			}
			fresh := freshTypedFields(t, reflect.ValueOf(value)).Interface()
			got, err := tc.codec.EncodeBER(fresh, ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(got, tc.valid) {
				t.Fatalf("fresh component: %v", err)
			}
			for _, wire := range [][]byte{tc.short, tc.long} {
				if _, err := tc.codec.DecodeBER(wire); err == nil {
					t.Fatal("strict component resized")
				}
				var log ber.ViolationLog
				value, err := tc.codec.DecodeBER(wire, ber.WithTolerance(&log))
				if err != nil || len(log.Snapshot()) != 1 {
					t.Fatalf("component tolerance: %v", err)
				}
				if log.Snapshot()[0].Rule.Edition != "11/1988" {
					t.Fatal("wrong component authority")
				}
				got, err := tc.codec.EncodeBER(value, ber.WithTolerance(&log))
				if err != nil || !bytes.Equal(got, wire) {
					t.Fatalf("component replay: %v", err)
				}
				fresh := freshTypedFields(t, reflect.ValueOf(value)).Interface()
				if _, err := tc.codec.EncodeBER(fresh, ber.WithoutBERReplay()); err == nil {
					t.Fatal("caller component resized")
				}
			}
		})
	}
}
