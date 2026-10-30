package tcap_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func assertImplicitSentinels(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, sentinel := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
		if errors.Is(got, sentinel) != (want == sentinel) {
			t.Errorf("%v: errors.Is(%v) differs; want %v", got, sentinel, want)
		}
	}
}

// X.680 (02/2021) §31.2.7; X.690 (02/2021) §§8.3, 8.8, 8.14.4:
// a standalone syntax scan sees IMPLICIT encoding faults even behind a
// preceding value constraint. Typed decoding keeps its first error and Path.
func TestImplicitNullProfileAndDecode(t *testing.T) {
	const prefix = "end.components.element[0].basicROS.invoke."
	for _, row := range []struct {
		wire, path, tolerantPath string
		want                     error
	}{
		{"64104901016c0ba10902010181010002012d", prefix + "linkedId.absent", prefix + "linkedId.absent", ber.ErrInvalidValue},
		{"640f4901016c0aa108020101a10002012d", prefix + "linkedId.InvokeLinkedId.absent", prefix + "linkedId.InvokeLinkedId.absent", ber.ErrInvalidTag},
		{"64104901016c0ba10902010180010002012d", "", "", nil},
		{"640f4901016c0aa108020101800002012d", prefix + "linkedId.present", prefix + "linkedId.present", ber.ErrInvalidValue},
		{"62134801016c0ca10a020200c881010002012d0500", "begin.components.element[0].basicROS.invoke.invokeId.present", "begin.components.element[0].basicROS.invoke.linkedId.absent", ber.ErrInvalidValue},
	} {
		t.Run(row.wire, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(nil)...), row.want)
			for _, tolerant := range []bool{false, true} {
				var value tcap.TCMessage
				var options []ber.DecodeOption
				wantPath := row.path
				if tolerant {
					options = []ber.DecodeOption{ber.WithTolerance(new(ber.ViolationLog))}
					wantPath = row.tolerantPath
				}
				err = value.UnmarshalBER(data, options...)
				assertImplicitSentinels(t, err, row.want)
				var located *tcap.DecodeError
				if wantPath != "" && (!errors.As(err, &located) || located.Path != wantPath) {
					t.Fatalf("path=%+v, want %q: %v", located, wantPath, err)
				}
			}
		})
	}
}

// X.690 (02/2021) §8.5 applies before a REAL can be rejected as an
// unexpected element (§8.15). TCAP does not declare REAL in its own syntax.
func TestUnexpectedRealContents(t *testing.T) {
	for _, row := range []struct {
		wire         string
		scan, decode error
	}{
		{"0903b00001", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"090183", ber.ErrTruncated, ber.ErrTruncated},
		{"090100", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"090144", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"090140", nil, ber.ErrUnexpectedElement},
		{"0903800001", nil, ber.ErrUnexpectedElement},
		{"050100", ber.ErrInvalidValue, ber.ErrInvalidValue},
	} {
		t.Run(row.wire, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(nil)...), row.scan)
			for _, options := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}} {
				var value tcap.TCMessage
				assertImplicitSentinels(t, value.UnmarshalBER(data, options...), row.decode)
			}
		})
	}
}

type rosCodec interface {
	UnmarshalBER([]byte, ...ber.DecodeOption) error
	MarshalBER(...ber.EncodeOption) ([]byte, error)
}

func rosRoots() []struct {
	name     string
	newValue func() rosCodec
} {
	return []struct {
		name     string
		newValue func() rosCodec
	}{
		{"ROS", func() rosCodec { return new(tcap.ROS) }},
		{"ROSSingleAS", func() rosCodec { return new(tcap.ROSSingleAS) }},
		{"ROSConsumerAS", func() rosCodec { return new(tcap.ROSConsumerAS) }},
		{"ROSSupplierAS", func() rosCodec { return new(tcap.ROSSupplierAS) }},
	}
}

// X.690 (02/2021) §8.15: the complete argument, result value and error
// parameter belong to the identified syntax, for ROS and all its instances.
func TestROSAliasOpenTypeProfile(t *testing.T) {
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
		for _, root := range rosRoots() {
			t.Run(root.name+"/"+row.name, func(t *testing.T) {
				assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(nil, root.name)...), nil)
				for _, mode := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}} {
					for _, tolerant := range []bool{false, true} {
						options := append([]ber.DecodeOption(nil), mode...)
						var log ber.ViolationLog
						if tolerant {
							options = append(options, ber.WithTolerance(&log))
						}
						value := root.newValue()
						if err := value.UnmarshalBER(data, options...); err != nil {
							t.Fatal(err)
						}
						if len(log.Snapshot()) != 0 {
							t.Fatalf("open value reported: %+v", log.Snapshot())
						}
						encoded, err := value.MarshalBER()
						if err != nil || !bytes.Equal(encoded, data) {
							t.Fatalf("replay: %v", err)
						}
					}
				}
			})
		}
	}
}

// X.690 (02/2021) §8.15 leaves the containing ROS envelope's rules intact.
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
		for _, root := range rosRoots() {
			t.Run(root.name+"/"+row.name, func(t *testing.T) {
				var violation *ber.ValidationError
				err := ber.ValidateBERElement(data, ber.TrackTCAPForm(nil, root.name)...)
				if !errors.As(err, &violation) || violation.Kind != ber.ProtocolRule {
					t.Fatalf("scan: %v", err)
				}
				for _, mode := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}} {
					err = root.newValue().UnmarshalBER(data, mode...)
					if !errors.As(err, &violation) || violation.Kind != ber.ProtocolRule {
						t.Fatalf("decode: %v", err)
					}
				}
			})
		}
	}
}
