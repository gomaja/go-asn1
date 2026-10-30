// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/implicit_universal_profile_test.go; SHA-256 e6de412bf1960004596ed0106110fb3f50fe0b201bc109e20dd72985b834684e.
package ber

import (
	"encoding/hex"
	"errors"
	"testing"
)

// X.680 (02/2021) §31.2.7 and X.690 (02/2021) §§8.8, 8.14.4:
// an IMPLICIT NULL retains both its primitive form and empty contents.
func TestProfileImplicitNullContents(t *testing.T) {
	for _, row := range []struct {
		root, wire string
		want       error
	}{
		{"TCMessage", "64104901016c0ba10902010181010002012d", ErrInvalidValue},
		{"TCMessage", "640f4901016c0aa108020101a10002012d", ErrInvalidTag},
		{"TCMessage", "64104901016c0ba10902010180010002012d", nil},
		{"TCMessage", "640f4901016c0aa108020101800002012d", ErrInvalidValue},
		{"TCMessage", "62134801016c0ca10a020200c881010002012d0500", ErrInvalidValue},
		{"Invoke", "300902010181010002012d", ErrInvalidValue},
		{"InvokeLinkedId", "810100", ErrInvalidValue},
		{"InvokeLinkedId", "a100", ErrInvalidTag},
		{"InvokeLinkedId", "8100", nil},
	} {
		t.Run(row.root+"/"+row.wire, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, row.root)...), row.want)
		})
	}
}

// X.690 (02/2021) §8.15 assigns the complete open-value encoding to
// its identified syntax. Every ROS instance shares that ownership boundary.
func TestGeneratedROSAliasProfileOwnership(t *testing.T) {
	for _, row := range []struct{ name, wire string }{
		{"argument/long-length", "a10c020100020100048103616263"},
		{"argument/constructed-octets", "a10d02010002010024050403616263"},
		{"argument/leading-zero-length", "a10d02010002010004820003616263"},
		{"argument/nested-long-length", "a10e0201000201003006048103616263"},
		{"linked-argument/long-length", "a10f020100800101020100048103616263"},
		{"linked-argument/constructed-octets", "a11002010080010102010024050403616263"},
		{"linked-argument/leading-zero-length", "a11002010080010102010004820003616263"},
		{"linked-argument/nested-long-length", "a1110201008001010201003006048103616263"},
		{"result/long-length", "a20e0201003009020100048103616263"},
		{"result/constructed-octets", "a20f020100300a02010024050403616263"},
		{"result/leading-zero-length", "a20f020100300a02010004820003616263"},
		{"result/nested-long-length", "a210020100300b0201003006048103616263"},
		{"parameter/long-length", "a30c020100020100048103616263"},
		{"parameter/constructed-octets", "a30d02010002010024050403616263"},
		{"parameter/leading-zero-length", "a30d02010002010004820003616263"},
		{"parameter/nested-long-length", "a30e0201000201003006048103616263"},
		{"short-length-control", "a10b0201000201000403616263"},
	} {
		data, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, root := range []string{"ROS", "ROSSingleAS", "ROSConsumerAS", "ROSSupplierAS"} {
			t.Run(root+"/"+row.name, func(t *testing.T) {
				if err := ValidateBERElement(data, TrackTCAPForm(nil, root)...); err != nil {
					t.Fatal(err)
				}
				options := TrackTCAPForm(nil, root)
				owned, err := OwnGeneratedBERInput(data, options)
				if err == nil {
					_, _, err = PrepareGeneratedBERInput(owned, options)
				}
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// The containing ROS envelope retains its profile checks; §8.15 starts
// only at the argument, result value or error parameter.
func TestROSAliasEnvelopeProfile(t *testing.T) {
	for _, row := range []struct{ name, wire string }{
		{"invoke-id", "a10702810100020100"},
		{"linked-id", "a10a02010080810101020100"},
		{"opcode", "a10702010002810100"},
		{"error-code", "a30702010002810100"},
		{"result-opcode", "a209020100300402810100"},
	} {
		data, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, root := range []string{"ROS", "ROSSingleAS", "ROSConsumerAS", "ROSSupplierAS"} {
			t.Run(root+"/"+row.name, func(t *testing.T) {
				for _, generated := range []bool{false, true} {
					options := TrackTCAPForm(nil, root)
					var err error
					if generated {
						var owned []byte
						owned, err = OwnGeneratedBERInput(data, options)
						if err == nil {
							_, _, err = PrepareGeneratedBERInput(owned, options)
						}
					} else {
						err = ValidateBERElement(data, options...)
					}
					var violation *ValidationError
					if !errors.As(err, &violation) || violation.Kind != ProtocolRule {
						t.Fatalf("generated=%v: %v", generated, err)
					}
				}
			})
		}
	}
}

// X.690 (02/2021) §8.1.3.2(a): preserve the primitive-indefinite
// length refusal before the additional IMPLICIT base-form check (§8.14.4).
func TestImplicitPrimitiveIndefiniteErrorPriority(t *testing.T) {
	for _, row := range []struct{ root, wire string }{
		{"TCMessage", "62074801014c800000"},
		{"ComponentPortion", "4c800000"},
		{"Begin", "42800000"},
	} {
		data, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(row.root, func(t *testing.T) {
			assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, row.root)...), ErrInvalidLength)
			options := TrackTCAPForm(nil, row.root)
			owned, err := OwnGeneratedBERInput(data, options)
			if err == nil {
				_, _, err = PrepareGeneratedBERInput(owned, options)
			}
			assertElementSentinels(t, err, ErrInvalidLength)
		})
	}
}

// X.680 (02/2021) §§25, 31: tags outside a grammar position have no
// inferred base type. X.690 (02/2021) §8.14 checks admitted positions only.
func TestProfileUnknownPositions(t *testing.T) {
	for _, row := range []struct{ root, wire string }{
		{"TCMessage", "67054901014c00"}, {"UniDialoguePDU", "4100"},
		{"Abort", "30054901014c00"}, {"AARQApdu", "60029e00"},
		{"TCMessage", "611b6b0f280d060700118605010201a00241006c08a10602010102012d"},
		{"AARQApdu", "601180020780a1090607040000010005038000"},
	} {
		t.Run(row.root+"/"+row.wire, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, row.root)...), nil)
		})
	}
}

// X.690 (02/2021) §8.15: Bind and Unbind retain the containing header's
// profile but their enclosed operation values use the TC-user's syntax.
func TestBindOpenValueProfile(t *testing.T) {
	for _, root := range []string{"Bind", "Unbind"} {
		first := byte(0xb0)
		if root == "Unbind" {
			first = 0xb3
		}
		for alternative := byte(0); alternative < 3; alternative++ {
			for _, tail := range []string{"06048103616263", "0724050403616263", "0704820003616263", "050403616263"} {
				data, err := hex.DecodeString(tail)
				if err != nil {
					t.Fatal(err)
				}
				data = append([]byte{first + alternative}, data...)
				assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, root)...), nil)
			}
			data := []byte{first + alternative, 0x81, 5, 4, 3, 'a', 'b', 'c'}
			var violation *ValidationError
			if err := ValidateBERElement(data, TrackTCAPForm(nil, root)...); !errors.As(err, &violation) {
				t.Fatalf("envelope profile lost: %v", err)
			}
		}
	}
}

// X.690 (02/2021) §8.14.3 requires every schema-known EXPLICIT wrapper
// to be constructed, including the single-ASN1-type alternative (§8.18.6).
func TestProfileExplicitForms(t *testing.T) {
	for _, row := range []struct{ root, wire string }{
		{"TCMessage", "620f4801014b006c08a10602010102012d"},
		{"TCMessage", "62274801016b182816060700118605010101a00b60098107040000010005036c08a10602010102012d"},
		{"TCMessage", "62374801016b282826060700118605010101a01b611980020780a109060704000001000503820100a305a1030201006c08a10602010102012d"},
		{"DialoguePortion", "6b0428028000"}, {"AssociateSourceDiagnostic", "8100"},
	} {
		t.Run(row.root+"/"+row.wire, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, row.root)...), ErrInvalidTag)
		})
	}
}

// X.690 (02/2021) §§8.15, 8.18: an unexpected universal EXTERNAL
// retains its open-value boundary; an invalid prefix cannot identify dialogue.
func TestUnexpectedExternalOpenBoundary(t *testing.T) {
	for _, row := range []struct{ root, wire string }{
		{"AARQApdu", "600a2808a006048103616263"},
		{"DialoguePortion", "6b1528130500060700118605010101a006048103616263"},
	} {
		data, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, row.root)...), nil)
	}
}

// X.690 (02/2021) §8.14: a root's base encoding is known only after
// its own tag matches, just as at a nested field or CHOICE alternative.
func TestProfileUnknownRootTags(t *testing.T) {
	for _, row := range []struct{ root, wire string }{
		{"AARQApdu", "4100"}, {"AARQApdu", "6103800108"},
		{"DialoguePortion", "4c00"}, {"Invoke", "4200"},
	} {
		data, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, row.root)...), nil)
	}
}

// X.690 (02/2021) §§8.15, 8.18.6–8.18.11: dialogue interpretation
// needs both an identification and an admitted EXTERNAL encoding choice.
func TestUnknownExternalEncodingPosition(t *testing.T) {
	// A matched encoding still contains the identified dialogue syntax.
	control, err := hex.DecodeString("6b0e280c0607001186050101018101ff")
	if err != nil {
		t.Fatal(err)
	}
	assertElementSentinels(t, ValidateBERElement(control, TrackTCAPForm(nil, "DialoguePortion")...), ErrTruncated)
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
			assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil, "DialoguePortion")...), nil)
		})
	}
}
