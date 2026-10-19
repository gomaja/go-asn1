// Code generated from ASN.1. DO NOT EDIT.

package v21_map_sm_datatypes

import (
	"fmt"
	"math/big"
	"unicode/utf8"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// ValueCodec is an immutable binding to one source type's BER/DER implementation.
// Its zero value cannot encode or decode. Factories retain no mutable registry.
type ValueCodec[T any] struct {
	decode func([]byte, ...ber.DecodeOption) (T, error)
	encode func(T, ...ber.EncodeOption) ([]byte, error)
	der    func(T) ([]byte, error)
}

func (c ValueCodec[T]) valid() bool { return c.decode != nil && c.encode != nil && c.der != nil }
func (c ValueCodec[T]) DecodeBER(data []byte, opts ...ber.DecodeOption) (T, error) {
	if !c.valid() {
		var zero T
		return zero, ber.ErrInvalidCodec
	}
	return c.decode(data, opts...)
}
func (c ValueCodec[T]) EncodeBER(value T, opts ...ber.EncodeOption) ([]byte, error) {
	if !c.valid() {
		return nil, ber.ErrInvalidCodec
	}
	return c.encode(value, opts...)
}

// EncodeDER always validates strictly, independently of BER tolerance options.
func (c ValueCodec[T]) EncodeDER(value T) ([]byte, error) {
	if !c.valid() {
		return nil, ber.ErrInvalidCodec
	}
	return c.der(value)
}
func pointerValueCodec[T any](decode func([]byte, ...ber.DecodeOption) (*T, error), encode func(*T, ...ber.EncodeOption) ([]byte, error), der func(*T) ([]byte, error)) ValueCodec[T] {
	return ValueCodec[T]{
		decode: func(data []byte, opts ...ber.DecodeOption) (T, error) {
			v, err := decode(data, opts...)
			if err != nil {
				var zero T
				return zero, err
			}
			return *v, nil
		},
		encode: func(v T, opts ...ber.EncodeOption) ([]byte, error) { return encode(&v, opts...) },
		der:    func(v T) ([]byte, error) { return der(&v) },
	}
}

type compositeCodecPointer[T any] interface {
	*T
	UnmarshalBER([]byte, ...ber.DecodeOption) error
	MarshalBER(...ber.EncodeOption) ([]byte, error)
	MarshalDER() ([]byte, error)
}

func compositeValueCodec[T any, P compositeCodecPointer[T]]() ValueCodec[T] {
	return ValueCodec[T]{
		decode: func(data []byte, opts ...ber.DecodeOption) (T, error) {
			var v T
			if err := P(&v).UnmarshalBER(data, opts...); err != nil {
				var zero T
				return zero, err
			}
			return v, nil
		},
		encode: func(v T, opts ...ber.EncodeOption) ([]byte, error) { return P(&v).MarshalBER(opts...) },
		der:    func(v T) ([]byte, error) { return P(&v).MarshalDER() },
	}
}

type primitiveRule[T any] struct {
	invalid             func(T) bool
	length              func(T) int
	encodedLength       func(T) int
	observed            func(T) any
	description, clause string
}

func checkPrimitiveRules[T any](value T, rules []primitiveRule[T], source, name string, decode []ber.DecodeOption, encode []ber.EncodeOption, decoding bool) error {
	for _, rule := range rules {
		if !rule.invalid(value) {
			continue
		}
		ref := ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: rule.clause}
		if decoding {
			opts := ber.DecodeRule(decode, source, ref)
			if rule.length != nil {
				if err := ber.CheckDecodedLength(opts, name, rule.description, rule.length(value)); err != nil {
					return err
				}
			} else {
				if err := ber.CheckDecodedValue(opts, name, rule.description, fmt.Sprint(rule.observed(value))); err != nil {
					return err
				}
			}
		} else {
			opts := ber.EncodeRule(encode, source, ref)
			if rule.length != nil {
				observed := rule.length(value)
				if rule.encodedLength != nil {
					observed = rule.encodedLength(value)
				}
				if err := ber.CheckEncodedLength(opts, name, rule.description, observed); err != nil {
					return err
				}
			} else {
				if err := ber.CheckEncodedValue(opts, name, rule.description, fmt.Sprint(rule.observed(value))); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// primitiveValueCodec shares framing and replay mechanics; source-specific
// validation remains statically typed and bound by each factory.
func primitiveValueCodec[T any](source, name string, rules []primitiveRule[T], decode func([]byte, ...ber.DecodeOption) (T, int, error), encode func(T, bool) ([]byte, error), normalize func(T, bool, []ber.DecodeOption, []ber.EncodeOption) (T, error)) ValueCodec[BERValue[T]] {
	var c ValueCodec[BERValue[T]]
	fresh := func(value T, der bool, opts []ber.EncodeOption) ([]byte, error) {
		if err := ber.ValidateEncodeOptions(opts...); err != nil {
			return nil, err
		}
		if normalize != nil {
			var err error
			value, err = normalize(value, true, nil, opts)
			if err != nil {
				return nil, err
			}
		}
		if err := checkPrimitiveRules(value, rules, source, name, nil, opts, false); err != nil {
			return nil, err
		}
		return encode(value, der)
	}
	c.decode = func(data []byte, opts ...ber.DecodeOption) (result BERValue[T], returnErr error) {
		opts, commit := ber.StageDecodeReports(opts)
		defer func() { commit(returnErr == nil) }()
		opts = ber.TrackBERForm(opts)
		owned, err := ber.OwnGeneratedBERInput(data, opts)
		if err != nil {
			return result, err
		}
		data = owned
		prepared, preparedOpts, err := ber.PrepareGeneratedBERInput(data, opts)
		if err != nil {
			return result, ber.DiagnosePreflight(err, data, opts, "child", func(probe []ber.DecodeOption) error { _, err := c.DecodeBER(data, probe...); return err })
		}
		data, opts = prepared, preparedOpts
		opts = ber.LocateDecodedElement(data, source, opts)
		defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
		value, n, err := decode(data, opts...)
		if err != nil {
			return result, err
		}
		if n != len(data) {
			return result, ber.ErrExtraData
		}
		if normalize != nil {
			value, err = normalize(value, false, opts, nil)
			if err != nil {
				return result, err
			}
		}
		if err := checkPrimitiveRules(value, rules, source, name, opts, nil, true); err != nil {
			return result, err
		}
		result.Value = value
		if ber.BERNeedsPreservation(opts) {
			result.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
			if err := ber.CompleteGeneratedBERDecode(opts, &result, func(v *BERValue[T], options ...ber.EncodeOption) ([]byte, error) { return c.EncodeBER(*v, options...) }); err != nil {
				var zero BERValue[T]
				return zero, err
			}
		}
		return result, nil
	}
	c.encode = func(value BERValue[T], opts ...ber.EncodeOption) (encoded []byte, returnErr error) {
		opts, commit := ber.StageEncodeReports(opts)
		defer func() { commit(returnErr == nil) }()
		opts, err := ber.PrepareBERReplay(value.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return c.EncodeBER(value, mode) }, &value)
		if err != nil {
			return nil, err
		}
		if replay, ok := ber.PreparedBERReplay(value.berReplayNode_, opts); ok {
			return replay, nil
		}
		data, err := fresh(value.Value, false, opts)
		if err != nil {
			return nil, err
		}
		return ber.PreserveEncodedBERNode(data, value.berReplayNode_, opts), nil
	}
	c.der = func(value BERValue[T]) ([]byte, error) {
		data, err := fresh(value.Value, true, nil)
		if err != nil {
			return nil, err
		}
		if err := ber.ValidateDEREncodedElement(data); err != nil {
			return nil, err
		}
		return data, nil
	}
	return c
}
func octetValueCodec[T ~[]byte](source, name string, rules []primitiveRule[T]) ValueCodec[BERValue[T]] {
	return primitiveValueCodec(source, name, rules, func(data []byte, opts ...ber.DecodeOption) (T, int, error) {
		v, n, e := ber.DecodeOctetString(data, opts...)
		return T(v), n, e
	}, func(v T, _ bool) ([]byte, error) { return ber.EncodeOctetString([]byte(v)) }, nil)
}
func integerValueCodec[T ~int64](source, name string, rules []primitiveRule[T], enumerated bool) ValueCodec[BERValue[T]] {
	return primitiveValueCodec(source, name, rules, func(data []byte, opts ...ber.DecodeOption) (T, int, error) {
		if enumerated {
			v, n, e := ber.DecodeEnumerated(data, opts...)
			return T(v), n, e
		}
		v, n, e := ber.DecodeInteger(data, opts...)
		return T(v), n, e
	}, func(v T, _ bool) ([]byte, error) {
		if enumerated {
			return ber.EncodeEnumerated(int64(v)), nil
		}
		return ber.EncodeInteger(int64(v)), nil
	}, nil)
}
func bigIntegerValueCodec(source, name string) ValueCodec[BERValue[*big.Int]] {
	return primitiveValueCodec(source, name, nil, ber.DecodeBigInt, func(v *big.Int, _ bool) ([]byte, error) { return ber.EncodeBigInt(v) }, nil)
}
func bitValueCodec(source, name string, rules []primitiveRule[runtime.BitString], named bool, sets []ber.NamedBitSizeSet) ValueCodec[BERValue[runtime.BitString]] {
	// X.690 (02/2021) §§8.6.2.2–8.6.2.3: reject malformed storage before SIZE.
	normalize := func(v runtime.BitString, encoding bool, _ []ber.DecodeOption, _ []ber.EncodeOption) (runtime.BitString, error) {
		if encoding {
			return v, ber.ValidateBitStringLength(v.Bytes, v.BitLength)
		}
		return v, nil
	}
	if named {
		normalize = func(v runtime.BitString, encoding bool, opts []ber.DecodeOption, encodeOpts []ber.EncodeOption) (runtime.BitString, error) {
			if encoding {
				return ber.NormalizeNamedBitStringForBEREncoding(v, sets, encodeOpts...)
			}
			return ber.NormalizeNamedBitStringSize(v, sets, opts...), nil
		}
	}
	return primitiveValueCodec(source, name, rules, func(data []byte, opts ...ber.DecodeOption) (runtime.BitString, int, error) {
		bytes, unused, n, err := ber.DecodeBitString(data, opts...)
		if err != nil {
			return runtime.BitString{}, 0, err
		}
		length, err := ber.BitStringBitLength(len(bytes), unused)
		return runtime.BitString{Bytes: bytes, BitLength: length}, n, err
	}, func(v runtime.BitString, der bool) ([]byte, error) {
		if err := ber.ValidateBitStringLength(v.Bytes, v.BitLength); err != nil {
			return nil, err
		}
		if der && named {
			return ber.EncodeDERNamedBitString(v.Bytes, v.BitLength)
		}
		return ber.EncodeBitString(v.Bytes, (8-v.BitLength%8)%8)
	}, normalize)
}

// marshalFramedValue owns report staging and received-form replay for every
// generated schema value. Fresh callbacks retain the original typed checks.
func marshalFramedValue[T any](value *T, node *ber.ReplayNode, opts []ber.EncodeOption, recursive, fresh func(*T, ...ber.EncodeOption) ([]byte, error), fast bool) (encoded []byte, returnErr error) {
	opts, commit := ber.StageEncodeReports(opts)
	defer func() { commit(returnErr == nil) }()
	if fast && node == nil {
		return fresh(value, opts...)
	}
	var err error
	opts, err = ber.PrepareBERReplay(node, opts, func(mode ber.EncodeOption) ([]byte, error) { return recursive(value, mode) }, value)
	if err != nil {
		return nil, err
	}
	if data, ok := ber.PreparedBERReplay(node, opts); ok {
		return data, nil
	}
	data, err := fresh(value, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(data, node, opts), nil
}
func prepareValueBER(data []byte, opts []ber.DecodeOption, source, pathLabel string, probe func([]byte, []ber.DecodeOption) error) ([]byte, []ber.DecodeOption, error) {
	opts = ber.TrackBERForm(opts)
	owned, err := ber.OwnGeneratedBERInput(data, opts)
	if err != nil {
		return nil, opts, err
	}
	data = owned
	prepared, preparedOpts, err := ber.PrepareGeneratedBERInput(data, opts)
	if err != nil {
		return nil, opts, ber.DiagnosePreflight(err, data, opts, pathLabel, func(options []ber.DecodeOption) error { return probe(data, options) })
	}
	return prepared, ber.LocateDecodedElement(prepared, source, preparedOpts), nil
}
func sourceASN1Rule(clause string) ber.RuleRef {
	return ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: clause}
}
func checkDecodedLength(opts []ber.DecodeOption, source, clause, path, constraint string, observed int) error {
	return ber.CheckDecodedLength(ber.DecodeRule(opts, source, sourceASN1Rule(clause)), path, constraint, observed)
}
func checkEncodedLength(opts []ber.EncodeOption, source, clause, path, constraint string, observed int) error {
	return ber.CheckEncodedLength(ber.EncodeRule(opts, source, sourceASN1Rule(clause)), path, constraint, observed)
}
func checkDecodedValue(opts []ber.DecodeOption, source, clause, path, constraint, observed string) error {
	return ber.CheckDecodedValue(ber.DecodeRule(opts, source, sourceASN1Rule(clause)), path, constraint, observed)
}
func checkEncodedValue(opts []ber.EncodeOption, source, clause, path, constraint, observed string) error {
	return ber.CheckEncodedValue(ber.EncodeRule(opts, source, sourceASN1Rule(clause)), path, constraint, observed)
}
func checkDecodedCollectionLength(opts []ber.DecodeOption, source, clause, path, constraint string, observed int) error {
	return ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, source, sourceASN1Rule(clause)), path, constraint, observed)
}
func checkEncodedCollectionLength(opts []ber.EncodeOption, source, clause, path, constraint string, observed int) error {
	return ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, source, sourceASN1Rule(clause)), path, constraint, observed)
}
func completeValueBER[T any](data []byte, opts []ber.DecodeOption, value *T, node **ber.ReplayNode, encode func(*T, ...ber.EncodeOption) ([]byte, error)) error {
	if !ber.BERNeedsPreservation(opts) {
		return nil
	}
	*node = ber.CaptureGeneratedBERReplay(data, opts)
	return ber.CompleteGeneratedBERDecode(opts, value, encode)
}

func prepareCompositeBER[T any](data []byte, opts []ber.DecodeOption, source, pathLabel string, decode func(*T, []byte, ...ber.DecodeOption) error) ([]byte, []ber.DecodeOption, error) {
	return prepareValueBER(data, opts, source, pathLabel, func(input []byte, options []ber.DecodeOption) error {
		var probe T
		return decode(&probe, input, options...)
	})
}
func publishDecodedValue[T any](destination, value *T, err *error) {
	if *err == nil {
		*destination = *value
	}
}

// checkOpaqueElement defers diagnostic metadata until the opaque value fails.
// CheckBEROpaqueReplay selects the canonical override independently of the
// internal replay-comparison mode; BERReplayEnabled would conflate the two.
// No options selects default BER directly, avoiding a policy-selector frame.
func checkOpaqueElement(data []byte, opts []ber.EncodeOption, component string, index int, source string, children []byte) error {
	var err error
	if len(opts) == 0 {
		err = ber.CheckBEROpaqueElement(data)
	} else {
		err = opaqueElementShapeError(data, opts)
	}
	if err == nil {
		return nil
	}
	return checkInvalidOpaqueElement(data, opts, component, index, source, children)
}

// Keep ordinal scans and diagnostic options off the successful check's frame.
func checkInvalidOpaqueElement(data []byte, opts []ber.EncodeOption, component string, index int, source string, children []byte) error {
	if index >= 0 {
		component = fmt.Sprintf("%s[%d]", component, index)
	}
	if component != "" {
		opts = ber.ChildEncodeOptions(opts, component)
	}
	return ber.CheckBEROpaqueElement(data, ber.EncodeSource(opts, source)...)
}

// The extension loop owns one lazy base count. X.690 (02/2021) §8.9:
// preceding children are scanned once per encode, only on the first failure;
// each earlier addition is one complete TLV, so later ordinals are base + i.
func checkOpaqueAddition(data []byte, opts []ber.EncodeOption, source string, children []byte, i int, base *int) error {
	var err error
	if len(opts) == 0 {
		err = ber.CheckBEROpaqueElement(data)
	} else {
		err = opaqueElementShapeError(data, opts)
	}
	if err == nil {
		return nil
	}
	return checkInvalidOpaqueAddition(data, opts, source, children, i, base)
}
func checkInvalidOpaqueAddition(data []byte, opts []ber.EncodeOption, source string, children []byte, i int, base *int) error {
	if *base < 0 {
		count, err := encodedChildCount(children)
		if err != nil {
			return err
		}
		*base = count - i
	}
	return checkInvalidOpaqueElement(data, opts, "child", *base+i, source, nil)
}
func encodedChildCount(children []byte) (int, error) {
	count := 0
	for len(children) != 0 {
		_, n, _, err := ber.DecodeEncodedTLV(children)
		if err != nil {
			return 0, err
		}
		children = children[n:]
		count++
	}
	return count, nil
}

// DER keeps its direct successful check; only a refusal needs metadata.
func invalidDEROpaqueElement(data []byte, component, source string) error {
	err := checkInvalidOpaqueElement(data, []ber.EncodeOption{ber.WithoutBERReplay()}, component, -1, source, nil)
	if _, ok := err.(*ber.ValidationError); ok {
		return err
	}
	return qualifyBERError(ber.ValidateDEREncodedElement(data), component, "encoding", false)
}
func invalidDERAddition(data []byte, source string, children []byte, i int) error {
	count, err := encodedChildCount(children)
	if err != nil {
		return err
	}
	err = checkInvalidOpaqueElement(data, []ber.EncodeOption{ber.WithoutBERReplay()}, "child", count, source, nil)
	if _, ok := err.(*ber.ValidationError); ok {
		return err
	}
	return opaqueExtensionError(ber.ValidateDEREncodedElement(data), i)
}

// X.690 (02/2021) §8.23.10: the primitive contents encoder checks
// utf8.ValidString on the Go value before any TLV exists. Only malformed
// text needs diagnostic metadata; the encoded TLV is never parsed again.
func encodeUTF8String(value string, opts []ber.EncodeOption, component string, index int, source string) ([]byte, error) {
	if utf8.ValidString(value) {
		return ber.EncodeTLV(tag.Tag{Number: 12}, []byte(value))
	}
	return encodeInvalidUTF8String(value, opts, component, index, source)
}
func encodeInvalidUTF8String(value string, opts []ber.EncodeOption, component string, index int, source string) ([]byte, error) {
	if index >= 0 {
		component = fmt.Sprintf("%s[%d]", component, index)
	}
	rule := ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}
	if err := ber.CheckEncodedValue(ber.EncodeRule(opts, source, rule), component, "UTF8String shortest-form UTF-8 scalar text (X.690 (02/2021) §8.23.10)", value); err != nil {
		return nil, err
	}
	return ber.EncodeTLV(tag.Tag{Number: 12}, []byte(value))
}

// Encode diagnostics use the significant length compared by normalization,
// after trailing zero bits are removed (X.680 (02/2021) §22.7). Decode
// diagnostics retain the received length; tolerant output keeps its storage.
func namedBitObservedLength(value runtime.BitString) int {
	normalized, err := ber.NormalizeNamedBitStringForEncoding(value, nil)
	if err != nil {
		return value.BitLength
	}
	return normalized.BitLength
}

// Source and path are applied only when normalization refuses a SIZE.
func normalizeNamedBits(value runtime.BitString, sets []ber.NamedBitSizeSet, opts []ber.EncodeOption, component, source string) (runtime.BitString, error) {
	normalized, err := ber.NormalizeNamedBitStringForBEREncoding(value, sets, opts...)
	if err == nil {
		return normalized, nil
	}
	if ve, ok := err.(*ber.ValidationError); ok && ve.ObservedLength != nil {
		return runtime.BitString{}, ber.CheckEncodedLength(ber.EncodeRule(opts, source, ve.Rule), component, ve.Constraint, *ve.ObservedLength)
	}
	return runtime.BitString{}, qualifyBERError(err, component, "encoding", false)
}
func namedBitBuilderResult(value runtime.BitString, err error, source string) (runtime.BitString, error) {
	if ve, ok := err.(*ber.ValidationError); ok {
		located := *ve
		located.Source = source
		return value, &located
	}
	return value, err
}

// Linear encoders probe the same opaque policy before resolving a failed
// addition's ordinal. This probe never publishes tolerant reports.
func opaqueElementShapeError(data []byte, opts []ber.EncodeOption) error {
	if len(opts) == 0 || ber.CheckBEROpaqueReplay(opts...) == nil {
		return ber.CheckBEROpaqueElement(data)
	}
	return ber.ValidateDEREncodedElement(data)
}

// Value-rule refusals carry their own wire ordinal in the validation path.
// Structural failures retain the extension context used by the encoder.
func opaqueExtensionError(err error, index int) error {
	if _, ok := err.(*ber.ValidationError); ok {
		return err
	}
	return fmt.Errorf("encoding extension %d: %w", index, err)
}

// SMRoutingInfoForSMArgCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Arg.
func SMRoutingInfoForSMArgCodec() ValueCodec[SMRoutingInfoForSMArg] {
	return compositeValueCodec[SMRoutingInfoForSMArg, *SMRoutingInfoForSMArg]()
}

// SMSMDeliveryNotIntendedCodec binds MAP-SM-DataTypes.SM-DeliveryNotIntended.
func SMSMDeliveryNotIntendedCodec() ValueCodec[BERValue[SMSMDeliveryNotIntended]] {
	return integerValueCodec[SMSMDeliveryNotIntended]("MAP-SM-DataTypes.SM-DeliveryNotIntended", "SM-DeliveryNotIntended", nil, true)
}

// SMSMRPMTICodec binds MAP-SM-DataTypes.SM-RP-MTI.
func SMSMRPMTICodec() ValueCodec[BERValue[SMSMRPMTI]] {
	return integerValueCodec[SMSMRPMTI]("MAP-SM-DataTypes.SM-RP-MTI", "SM-RP-MTI", []primitiveRule[SMSMRPMTI]{{invalid: func(value SMSMRPMTI) bool { return !(int64(value) >= 0 && int64(value) <= 10) }, description: "(0..10)", clause: "51.4", observed: func(value SMSMRPMTI) any { return int64(value) }}}, false)
}

// SMSMRPSMEACodec binds MAP-SM-DataTypes.SM-RP-SMEA.
func SMSMRPSMEACodec() ValueCodec[BERValue[SMSMRPSMEA]] {
	return octetValueCodec[SMSMRPSMEA]("MAP-SM-DataTypes.SM-RP-SMEA", "SM-RP-SMEA", []primitiveRule[SMSMRPSMEA]{{invalid: func(value SMSMRPSMEA) bool { return !(len(value) >= 1 && len(value) <= 12) }, description: "SIZE (1..12)", clause: "51.5", length: func(value SMSMRPSMEA) int { return len(value) }}})
}

// SMRoutingInfoForSMResCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Res.
func SMRoutingInfoForSMResCodec() ValueCodec[SMRoutingInfoForSMRes] {
	return compositeValueCodec[SMRoutingInfoForSMRes, *SMRoutingInfoForSMRes]()
}

// SMIPSMGWGuidanceCodec binds MAP-SM-DataTypes.IP-SM-GW-Guidance.
func SMIPSMGWGuidanceCodec() ValueCodec[SMIPSMGWGuidance] {
	return compositeValueCodec[SMIPSMGWGuidance, *SMIPSMGWGuidance]()
}

// SMLocationInfoWithLMSICodec binds MAP-SM-DataTypes.LocationInfoWithLMSI.
func SMLocationInfoWithLMSICodec() ValueCodec[SMLocationInfoWithLMSI] {
	return compositeValueCodec[SMLocationInfoWithLMSI, *SMLocationInfoWithLMSI]()
}

// SMAdditionalNumberCodec binds MAP-SM-DataTypes.Additional-Number.
func SMAdditionalNumberCodec() ValueCodec[SMAdditionalNumber] {
	return compositeValueCodec[SMAdditionalNumber, *SMAdditionalNumber]()
}

// SMMOForwardSMArgCodec binds MAP-SM-DataTypes.MO-ForwardSM-Arg.
func SMMOForwardSMArgCodec() ValueCodec[SMMOForwardSMArg] {
	return compositeValueCodec[SMMOForwardSMArg, *SMMOForwardSMArg]()
}

// SMMOForwardSMResCodec binds MAP-SM-DataTypes.MO-ForwardSM-Res.
func SMMOForwardSMResCodec() ValueCodec[SMMOForwardSMRes] {
	return compositeValueCodec[SMMOForwardSMRes, *SMMOForwardSMRes]()
}

// SMMTForwardSMArgCodec binds MAP-SM-DataTypes.MT-ForwardSM-Arg.
func SMMTForwardSMArgCodec() ValueCodec[SMMTForwardSMArg] {
	return compositeValueCodec[SMMTForwardSMArg, *SMMTForwardSMArg]()
}

// SMCorrelationIDCodec binds MAP-SM-DataTypes.CorrelationID.
func SMCorrelationIDCodec() ValueCodec[SMCorrelationID] {
	return compositeValueCodec[SMCorrelationID, *SMCorrelationID]()
}

// SMSIPURICodec binds MAP-SM-DataTypes.SIP-URI.
func SMSIPURICodec() ValueCodec[BERValue[SMSIPURI]] {
	return octetValueCodec[SMSIPURI]("MAP-SM-DataTypes.SIP-URI", "SIP-URI", nil)
}

// SMMTForwardSMResCodec binds MAP-SM-DataTypes.MT-ForwardSM-Res.
func SMMTForwardSMResCodec() ValueCodec[SMMTForwardSMRes] {
	return compositeValueCodec[SMMTForwardSMRes, *SMMTForwardSMRes]()
}

// SMSMRPDACodec binds MAP-SM-DataTypes.SM-RP-DA.
func SMSMRPDACodec() ValueCodec[SMSMRPDA] {
	return compositeValueCodec[SMSMRPDA, *SMSMRPDA]()
}

// SMSMRPOACodec binds MAP-SM-DataTypes.SM-RP-OA.
func SMSMRPOACodec() ValueCodec[SMSMRPOA] {
	return compositeValueCodec[SMSMRPOA, *SMSMRPOA]()
}

// SMSMDeliveryTimerValueCodec binds MAP-SM-DataTypes.SM-DeliveryTimerValue.
func SMSMDeliveryTimerValueCodec() ValueCodec[BERValue[SMSMDeliveryTimerValue]] {
	return integerValueCodec[SMSMDeliveryTimerValue]("MAP-SM-DataTypes.SM-DeliveryTimerValue", "SM-DeliveryTimerValue", []primitiveRule[SMSMDeliveryTimerValue]{{invalid: func(value SMSMDeliveryTimerValue) bool { return !(int64(value) >= 30 && int64(value) <= 600) }, description: "(30..600)", clause: "51.4", observed: func(value SMSMDeliveryTimerValue) any { return int64(value) }}}, false)
}

// SMReportSMDeliveryStatusArgCodec binds MAP-SM-DataTypes.ReportSM-DeliveryStatusArg.
func SMReportSMDeliveryStatusArgCodec() ValueCodec[SMReportSMDeliveryStatusArg] {
	return compositeValueCodec[SMReportSMDeliveryStatusArg, *SMReportSMDeliveryStatusArg]()
}

// SMSMDeliveryOutcomeCodec binds MAP-SM-DataTypes.SM-DeliveryOutcome.
func SMSMDeliveryOutcomeCodec() ValueCodec[BERValue[SMSMDeliveryOutcome]] {
	return integerValueCodec[SMSMDeliveryOutcome]("MAP-SM-DataTypes.SM-DeliveryOutcome", "SM-DeliveryOutcome", []primitiveRule[SMSMDeliveryOutcome]{{invalid: func(value SMSMDeliveryOutcome) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value SMSMDeliveryOutcome) any { return int64(value) }}}, true)
}

// SMReportSMDeliveryStatusResCodec binds MAP-SM-DataTypes.ReportSM-DeliveryStatusRes.
func SMReportSMDeliveryStatusResCodec() ValueCodec[SMReportSMDeliveryStatusRes] {
	return compositeValueCodec[SMReportSMDeliveryStatusRes, *SMReportSMDeliveryStatusRes]()
}

// SMAlertServiceCentreArgCodec binds MAP-SM-DataTypes.AlertServiceCentreArg.
func SMAlertServiceCentreArgCodec() ValueCodec[SMAlertServiceCentreArg] {
	return compositeValueCodec[SMAlertServiceCentreArg, *SMAlertServiceCentreArg]()
}

// SMSmsGmscAlertEventCodec binds MAP-SM-DataTypes.SmsGmsc-Alert-Event.
func SMSmsGmscAlertEventCodec() ValueCodec[BERValue[SMSmsGmscAlertEvent]] {
	return integerValueCodec[SMSmsGmscAlertEvent]("MAP-SM-DataTypes.SmsGmsc-Alert-Event", "SmsGmsc-Alert-Event", []primitiveRule[SMSmsGmscAlertEvent]{{invalid: func(value SMSmsGmscAlertEvent) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SMSmsGmscAlertEvent) any { return int64(value) }}}, true)
}

// SMInformServiceCentreArgCodec binds MAP-SM-DataTypes.InformServiceCentreArg.
func SMInformServiceCentreArgCodec() ValueCodec[SMInformServiceCentreArg] {
	return compositeValueCodec[SMInformServiceCentreArg, *SMInformServiceCentreArg]()
}

// SMMWStatusCodec binds MAP-SM-DataTypes.MW-Status.
func SMMWStatusCodec() ValueCodec[BERValue[SMMWStatus]] {
	return bitValueCodec("MAP-SM-DataTypes.MW-Status", "MW-Status", []primitiveRule[SMMWStatus]{{invalid: func(value SMMWStatus) bool { return !(value.BitLength >= 6 && value.BitLength <= 16) }, description: "SIZE (6..16)", clause: "51.5", length: func(value SMMWStatus) int { return value.BitLength }, encodedLength: func(value SMMWStatus) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}})
}

// SMReadyForSMArgCodec binds MAP-SM-DataTypes.ReadyForSM-Arg.
func SMReadyForSMArgCodec() ValueCodec[SMReadyForSMArg] {
	return compositeValueCodec[SMReadyForSMArg, *SMReadyForSMArg]()
}

// SMReadyForSMResCodec binds MAP-SM-DataTypes.ReadyForSM-Res.
func SMReadyForSMResCodec() ValueCodec[SMReadyForSMRes] {
	return compositeValueCodec[SMReadyForSMRes, *SMReadyForSMRes]()
}

// SMAlertReasonCodec binds MAP-SM-DataTypes.AlertReason.
func SMAlertReasonCodec() ValueCodec[BERValue[SMAlertReason]] {
	return integerValueCodec[SMAlertReason]("MAP-SM-DataTypes.AlertReason", "AlertReason", []primitiveRule[SMAlertReason]{{invalid: func(value SMAlertReason) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SMAlertReason) any { return int64(value) }}}, true)
}

// SMMTForwardSMVGCSArgCodec binds MAP-SM-DataTypes.MT-ForwardSM-VGCS-Arg.
func SMMTForwardSMVGCSArgCodec() ValueCodec[SMMTForwardSMVGCSArg] {
	return compositeValueCodec[SMMTForwardSMVGCSArg, *SMMTForwardSMVGCSArg]()
}

// SMMTForwardSMVGCSResCodec binds MAP-SM-DataTypes.MT-ForwardSM-VGCS-Res.
func SMMTForwardSMVGCSResCodec() ValueCodec[SMMTForwardSMVGCSRes] {
	return compositeValueCodec[SMMTForwardSMVGCSRes, *SMMTForwardSMVGCSRes]()
}

// SMDispatcherListCodec binds MAP-SM-DataTypes.DispatcherList.
func SMDispatcherListCodec() ValueCodec[SMDispatcherList] {
	return pointerValueCodec(UnmarshalBERSMDispatcherList, MarshalBERSMDispatcherList, MarshalDERSMDispatcherList)
}

// SMAdditionalDispatcherListCodec binds MAP-SM-DataTypes.AdditionalDispatcherList.
func SMAdditionalDispatcherListCodec() ValueCodec[SMAdditionalDispatcherList] {
	return pointerValueCodec(UnmarshalBERSMAdditionalDispatcherList, MarshalBERSMAdditionalDispatcherList, MarshalDERSMAdditionalDispatcherList)
}
