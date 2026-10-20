package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// TS 29.002 V19.1.0 §§17.7.1, 17.7.11 define the typed PDP context and
// private extension. Canonical opaque elements already accepted by DER must
// also survive fresh BER encoding (#156); no unknown schema is inferred.
func TestMAPWithoutBERReplayCanonicalOpaque(t *testing.T) {
	for _, tc := range []struct {
		name, wire, fresh string
		value             interface {
			UnmarshalBER([]byte, ...mapber.DecodeOption) error
			MarshalBER(...mapber.EncodeOption) ([]byte, error)
			MarshalDER() ([]byte, error)
		}
	}{
		{"typed control", "3008808101018202f121", "30078001018202f121", new(gsm_map.PDPContextInfo)},
		{"unknown addition", "300a8001018202f1219e01ff", "300a8001018202f1219e01ff", new(gsm_map.PDPContextInfo)},
		{"private NULL", "300aa008300606022a030500", "300aa008300606022a030500", new(gsm_map.ExtensionContainer)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tc.fresh)
			if err != nil {
				t.Fatal(err)
			}
			var replayOptions []mapber.EncodeOption
			if tc.name == "typed control" {
				// TS 29.002 V19.1.0 §17.1.1: the typed child must use
				// a short length; unknown complete encodings stay opaque.
				strict := checkMAPShortLengthError(t, tc.value.UnmarshalBER(wire), 2, []int{0})
				var log mapber.ViolationLog
				if err := tc.value.UnmarshalBER(wire, mapber.WithTolerance(&log)); err != nil {
					t.Fatal(err)
				}
				checkMAPShortLengthLog(t, &log, strict)
				var replayLog mapber.ViolationLog
				replayOptions = []mapber.EncodeOption{mapber.WithTolerance(&replayLog)}
			} else if err := tc.value.UnmarshalBER(wire); err != nil {
				t.Fatal(err)
			}
			switch v := tc.value.(type) {
			case *gsm_map.PDPContextInfo:
				if v.PdpContextIdentifier != 1 || !bytes.Equal(v.PdpType, []byte{0xf1, 0x21}) {
					t.Fatalf("typed context = %+v", v)
				}
				count := 0
				if tc.name == "unknown addition" {
					count = 1
				}
				if len(v.ExtData_) != count || count == 1 && !bytes.Equal(v.ExtData_[0], []byte{0x9e, 1, 0xff}) {
					t.Fatalf("extensions = %x", v.ExtData_)
				}
			case *gsm_map.ExtensionContainer:
				if v.PrivateExtensionList == nil || len(v.PrivateExtensionList.Values) != 1 {
					t.Fatalf("private list = %+v", v.PrivateExtensionList)
				}
				private := v.PrivateExtensionList.Values[0]
				if private.ExtId.String() != "1.2.3" || private.ExtType == nil || !bytes.Equal(private.ExtType.Bytes, []byte{5, 0}) {
					t.Fatalf("private extension = %+v", private)
				}
			}
			if replay, err := tc.value.MarshalBER(replayOptions...); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay = %x, %v; want %x", replay, err, wire)
			}
			if der, err := tc.value.MarshalDER(); err != nil || !bytes.Equal(der, want) {
				t.Fatalf("DER = %x, %v; want %x", der, err, want)
			}
			fresh, err := tc.value.MarshalBER(mapber.WithoutBERReplay())
			if err != nil || !bytes.Equal(fresh, want) {
				t.Fatalf("fresh BER = %x, %v; want %x", fresh, err, want)
			}
			if err := tc.value.UnmarshalBER(fresh); err != nil {
				t.Fatalf("fresh decode: %v", err)
			}
			if replay, err := tc.value.MarshalBER(); err != nil || !bytes.Equal(replay, want) {
				t.Fatalf("fresh replay = %x, %v; want %x", replay, err, want)
			}
		})
	}
}

// A canonical framing check cannot repair an unknown schema. Nonminimal
// lengths are not DER (X.690 (02/2021) §10.1), so fresh encoding refuses them.
func TestMAPWithoutBERReplayNoncanonicalOpaque(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		value      interface {
			UnmarshalBER([]byte, ...mapber.DecodeOption) error
			MarshalBER(...mapber.EncodeOption) ([]byte, error)
			MarshalDER() ([]byte, error)
		}
	}{
		{"unknown addition", "300b8001018202f1219e8101ff", new(gsm_map.PDPContextInfo)},
		{"private NULL", "300ba009300706022a03058100", new(gsm_map.ExtensionContainer)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.value.UnmarshalBER(wire); err != nil {
				t.Fatal(err)
			}
			if replay, err := tc.value.MarshalBER(); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay = %x, %v; want %x", replay, err, wire)
			}
			if _, err := tc.value.MarshalBER(mapber.WithoutBERReplay()); !errors.Is(err, mapber.ErrInvalidValue) {
				t.Fatalf("fresh opaque error = %v", err)
			}
			if _, err := tc.value.MarshalDER(); !errors.Is(err, mapber.ErrInvalidLength) {
				t.Fatalf("DER opaque error = %v", err)
			}
		})
	}
}
