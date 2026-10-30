package tcap_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func profileDecodeModes(t *testing.T, run func(*testing.T, []ber.DecodeOption)) {
	t.Helper()
	for i, mode := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}} {
		for _, tolerant := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode-%d/tolerant-%t", i, tolerant), func(t *testing.T) {
				options := append([]ber.DecodeOption(nil), mode...)
				if tolerant {
					options = append(options, ber.WithTolerance(new(ber.ViolationLog)))
				}
				run(t, options)
			})
		}
	}
}

// X.680 (02/2021) §31.2.7 and X.690 (02/2021) §§8.14–8.15:
// a schema-known tag has a base type only in its admitted grammar position.
func TestProfileUnknownPositions(t *testing.T) {
	for _, row := range []struct {
		name, root, wire string
		newValue         func() rosCodec
	}{
		{"abort-component", "TCMessage", "67054901014c00", func() rosCodec { return new(tcap.TCMessage) }},
		{"unidialogue-alternative", "UniDialoguePDU", "4100", func() rosCodec { return new(tcap.UniDialoguePDU) }},
		{"standalone-abort-component", "Abort", "30054901014c00", func() rosCodec { return new(tcap.Abort) }},
		{"premature-user-information", "AARQApdu", "60029e00", func() rosCodec { return new(tcap.AARQApdu) }},
		{"nested-unidialogue-alternative", "TCMessage", "611b6b0f280d060700118605010201a00241006c08a10602010102012d", func() rosCodec { return new(tcap.TCMessage) }},
		{"displaced-protocol-version", "AARQApdu", "601180020780a1090607040000010005038000", func() rosCodec { return new(tcap.AARQApdu) }},
		{"wrong-root-primitive", "AARQApdu", "4100", func() rosCodec { return new(tcap.AARQApdu) }},
		{"wrong-root-contents", "AARQApdu", "6103800108", func() rosCodec { return new(tcap.AARQApdu) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			profileDecodeModes(t, func(t *testing.T, options []ber.DecodeOption) {
				assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(options, row.root)...), nil)
				assertImplicitSentinels(t, row.newValue().UnmarshalBER(data, options...), ber.ErrUnexpectedElement)
			})
		})
	}
}

// X.690 (02/2021) §8.1.3: fallback validation keeps the first malformed
// element's error and location when an earlier unknown tag is well-formed.
func TestProfileUnknownPositionFallback(t *testing.T) {
	for _, row := range []struct{ name, wire, path string }{
		{"abort", "67074901014c000402", "child[2]"},
		{"unidialogue", "611d6b0f280d060700118605010201a00241006c0aa10602010102012d0402", "child[1].child[1]"},
	} {
		t.Run(row.name, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			profileDecodeModes(t, func(t *testing.T, options []ber.DecodeOption) {
				var value tcap.TCMessage
				err := value.UnmarshalBER(data, options...)
				assertImplicitSentinels(t, err, ber.ErrTruncated)
				var located *tcap.DecodeError
				if !errors.As(err, &located) || located.Path != row.path {
					t.Fatalf("location=%+v, want %q: %v", located, row.path, err)
				}
			})
		})
	}
}

// X.690 (02/2021) §8.14.3 requires constructed EXPLICIT identifiers;
// §8.18.6 defines EXTERNAL's single-ASN1-type as an EXPLICIT [0].
func TestExplicitProfileAndDecode(t *testing.T) {
	for _, row := range []struct{ name, wire, path string }{
		{"dialogue-portion", "620f4801014b006c08a10602010102012d", "begin.dialoguePortion"},
		{"application-context", "62274801016b182816060700118605010101a00b60098107040000010005036c08a10602010102012d", "begin.dialogueRequest.application-context-name"},
		{"associate-result", "62374801016b282826060700118605010101a01b611980020780a109060704000001000503820100a305a1030201006c08a10602010102012d", "begin.dialogueResponse.result"},
		{"external-single-asn1", "620e4801016b09280706010080020500", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			profileDecodeModes(t, func(t *testing.T, options []ber.DecodeOption) {
				assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(options)...), ber.ErrInvalidTag)
				var value tcap.TCMessage
				err := value.UnmarshalBER(data, options...)
				assertImplicitSentinels(t, err, ber.ErrInvalidTag)
				var located *tcap.DecodeError
				if !errors.As(err, &located) {
					t.Fatalf("missing location: %v", err)
				}
				if row.path != "" && located.Path != row.path {
					t.Fatalf("path=%q, want %q", located.Path, row.path)
				}
			})
		})
	}
}

// X.690 (02/2021) §8.15: each Bind and Unbind alternative encloses a
// TC-user open value; its own EXPLICIT tag retains the envelope checks.
func TestBindUnbindOpenTypeProfile(t *testing.T) {
	for _, root := range []struct {
		name     string
		first    byte
		newValue func() rosCodec
	}{
		{"Bind", 0xb0, func() rosCodec { return new(tcap.Bind) }},
		{"Unbind", 0xb3, func() rosCodec { return new(tcap.Unbind) }},
	} {
		for alternative := byte(0); alternative < 3; alternative++ {
			for _, row := range []struct{ name, contents string }{
				{"long-length", "048103616263"},
				{"constructed-octets", "24050403616263"},
				{"leading-zero-length", "04820003616263"},
				{"short-length-control", "0403616263"},
			} {
				t.Run(fmt.Sprintf("%s/alternative-%d/%s", root.name, alternative, row.name), func(t *testing.T) {
					contents, err := hex.DecodeString(row.contents)
					if err != nil {
						t.Fatal(err)
					}
					data := append([]byte{root.first + alternative, byte(len(contents))}, contents...)
					profileDecodeModes(t, func(t *testing.T, options []ber.DecodeOption) {
						var log ber.ViolationLog
						// Inspect tolerant reports as well as strict acceptance.
						strict := options
						options = []ber.DecodeOption{ber.WithTolerance(&log)}
						assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(strict, root.name)...), nil)
						value := root.newValue()
						assertImplicitSentinels(t, value.UnmarshalBER(data, strict...), nil)
						encoded, err := value.MarshalBER()
						if err != nil || !bytes.Equal(data, encoded) {
							t.Fatalf("replay: %v", err)
						}
						value = root.newValue()
						assertImplicitSentinels(t, value.UnmarshalBER(data, options...), nil)
						if len(log.Snapshot()) != 0 {
							t.Fatalf("open-value reports: %+v", log.Snapshot())
						}
						encoded, err = value.MarshalBER()
						if err != nil || !bytes.Equal(data, encoded) {
							t.Fatalf("tolerant replay: %v", err)
						}
					})
				})
			}
			t.Run(fmt.Sprintf("%s/alternative-%d/envelope", root.name, alternative), func(t *testing.T) {
				// The open-value exemption does not cover a nonminimal envelope length.
				data := []byte{root.first + alternative, 0x81, 5, 4, 3, 'a', 'b', 'c'}
				err := ber.ValidateBERElement(data, ber.TrackTCAPForm(nil, root.name)...)
				var violation *ber.ValidationError
				if !errors.As(err, &violation) || violation.Kind != ber.ProtocolRule {
					t.Fatalf("scan: %v", err)
				}
				for _, mode := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}} {
					if err = root.newValue().UnmarshalBER(data, mode...); !errors.As(err, &violation) || violation.Kind != ber.ProtocolRule {
						t.Fatalf("decode: %v", err)
					}
				}
			})
		}
	}
}

// X.690 (02/2021) §§8.15, 8.18: an identification alone does not
// turn an unknown or duplicate field into an EXTERNAL encoding choice.
func TestUnknownExternalEncodingPosition(t *testing.T) {
	control, err := hex.DecodeString("6b0e280c0607001186050101018101ff")
	if err != nil {
		t.Fatal(err)
	}
	assertImplicitSentinels(t, ber.ValidateBERElement(control, ber.TrackTCAPForm(nil, "DialoguePortion")...), ber.ErrTruncated)
	for _, row := range []struct{ name, wire string }{
		{"after-unknown-octets", "6b10280e06070011860501010183008101ff"},
		{"after-unknown-bits", "6b11280f0607001186050101018300820200ff"},
		{"duplicate-octets", "6b122810060700118605010101a00262008101ff"},
		{"duplicate-bits", "6b132811060700118605010101a0026200820200ff"},
		{"unknown-constructed-a0", "6b1528130607001186050101018300a006048103616263"},
		{"unknown-constructed-a1", "6b1428120607001186050101018300a1050403616263"},
		{"unknown-constructed-a3", "6b132811060700118605010101a306048103616263"},
	} {
		t.Run(row.name, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			profileDecodeModes(t, func(t *testing.T, options []ber.DecodeOption) {
				assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(options, "DialoguePortion")...), nil)
				var value tcap.DialoguePortion
				assertImplicitSentinels(t, value.UnmarshalBER(data, options...), ber.ErrUnexpectedElement)
			})
		})
	}
}
