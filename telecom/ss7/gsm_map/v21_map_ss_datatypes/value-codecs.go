// Code generated from ASN.1. DO NOT EDIT.

package v21_map_ss_datatypes

import (
	"fmt"
	"math/big"
	"strings"
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
				return nil, locatePrimitiveEncodeError(err, source, name, opts)
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
	if _, ok := err.(*ber.ElementError); ok {
		return qualifyBERError(err, component, "encoding", false)
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
	if _, ok := err.(*ber.ElementError); ok {
		return opaqueExtensionError(err, i)
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

// Reuse the ordinary SIZE check on refusal so parent path components agree
// with tolerant records. Successful normalization needs no location work.
func locatePrimitiveEncodeError(err error, source, path string, opts []ber.EncodeOption) error {
	if ve, ok := err.(*ber.ValidationError); ok && ve.ObservedLength != nil {
		return ber.CheckEncodedLength(ber.EncodeRule(opts, source, ve.Rule), path, ve.Constraint, *ve.ObservedLength)
	}
	return err
}
func namedBitBuilderResult(value runtime.BitString, err error, source string) (runtime.BitString, error) {
	if err != nil {
		err = namedBitBuilderError(err, source)
	}
	return value, err
}

// Keep builder location work on the refusal path.
func namedBitBuilderError(err error, source string) error {
	if ve, ok := err.(*ber.ValidationError); ok {
		located := *ve
		located.Source = source
		_, located.Path, _ = strings.Cut(source, ".")
		return &located
	}
	return err
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

// SSRegisterSSArgCodec binds MAP-SS-DataTypes.RegisterSS-Arg.
func SSRegisterSSArgCodec() ValueCodec[SSRegisterSSArg] {
	return compositeValueCodec[SSRegisterSSArg, *SSRegisterSSArg]()
}

// SSNoReplyConditionTimeCodec binds MAP-SS-DataTypes.NoReplyConditionTime.
func SSNoReplyConditionTimeCodec() ValueCodec[BERValue[SSNoReplyConditionTime]] {
	return integerValueCodec[SSNoReplyConditionTime]("MAP-SS-DataTypes.NoReplyConditionTime", "NoReplyConditionTime", []primitiveRule[SSNoReplyConditionTime]{{invalid: func(value SSNoReplyConditionTime) bool { return !(int64(value) >= 5 && int64(value) <= 30) }, description: "(5..30)", clause: "51.4", observed: func(value SSNoReplyConditionTime) any { return int64(value) }}}, false)
}

// SSSSInfoCodec binds MAP-SS-DataTypes.SS-Info.
func SSSSInfoCodec() ValueCodec[SSSSInfo] {
	return compositeValueCodec[SSSSInfo, *SSSSInfo]()
}

// SSForwardingInfoCodec binds MAP-SS-DataTypes.ForwardingInfo.
func SSForwardingInfoCodec() ValueCodec[SSForwardingInfo] {
	return compositeValueCodec[SSForwardingInfo, *SSForwardingInfo]()
}

// SSForwardingFeatureListCodec binds MAP-SS-DataTypes.ForwardingFeatureList.
func SSForwardingFeatureListCodec() ValueCodec[SSForwardingFeatureList] {
	return pointerValueCodec(UnmarshalBERSSForwardingFeatureList, MarshalBERSSForwardingFeatureList, MarshalDERSSForwardingFeatureList)
}

// SSForwardingFeatureCodec binds MAP-SS-DataTypes.ForwardingFeature.
func SSForwardingFeatureCodec() ValueCodec[SSForwardingFeature] {
	return compositeValueCodec[SSForwardingFeature, *SSForwardingFeature]()
}

// SSSSStatusCodec binds MAP-SS-DataTypes.SS-Status.
func SSSSStatusCodec() ValueCodec[BERValue[SSSSStatus]] {
	return pointerValueCodec(UnmarshalBERSSSSStatus, MarshalBERSSSSStatus, MarshalDERSSSSStatus)
}

// SSForwardingOptionsCodec binds MAP-SS-DataTypes.ForwardingOptions.
func SSForwardingOptionsCodec() ValueCodec[BERValue[SSForwardingOptions]] {
	return octetValueCodec[SSForwardingOptions]("MAP-SS-DataTypes.ForwardingOptions", "ForwardingOptions", []primitiveRule[SSForwardingOptions]{{invalid: func(value SSForwardingOptions) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value SSForwardingOptions) int { return len(value) }}})
}

// SSCallBarringInfoCodec binds MAP-SS-DataTypes.CallBarringInfo.
func SSCallBarringInfoCodec() ValueCodec[SSCallBarringInfo] {
	return compositeValueCodec[SSCallBarringInfo, *SSCallBarringInfo]()
}

// SSCallBarringFeatureListCodec binds MAP-SS-DataTypes.CallBarringFeatureList.
func SSCallBarringFeatureListCodec() ValueCodec[SSCallBarringFeatureList] {
	return pointerValueCodec(UnmarshalBERSSCallBarringFeatureList, MarshalBERSSCallBarringFeatureList, MarshalDERSSCallBarringFeatureList)
}

// SSCallBarringFeatureCodec binds MAP-SS-DataTypes.CallBarringFeature.
func SSCallBarringFeatureCodec() ValueCodec[SSCallBarringFeature] {
	return compositeValueCodec[SSCallBarringFeature, *SSCallBarringFeature]()
}

// SSSSDataCodec binds MAP-SS-DataTypes.SS-Data.
func SSSSDataCodec() ValueCodec[SSSSData] {
	return compositeValueCodec[SSSSData, *SSSSData]()
}

// SSSSSubscriptionOptionCodec binds MAP-SS-DataTypes.SS-SubscriptionOption.
func SSSSSubscriptionOptionCodec() ValueCodec[SSSSSubscriptionOption] {
	return compositeValueCodec[SSSSSubscriptionOption, *SSSSSubscriptionOption]()
}

// SSCliRestrictionOptionCodec binds MAP-SS-DataTypes.CliRestrictionOption.
func SSCliRestrictionOptionCodec() ValueCodec[BERValue[SSCliRestrictionOption]] {
	return integerValueCodec[SSCliRestrictionOption]("MAP-SS-DataTypes.CliRestrictionOption", "CliRestrictionOption", []primitiveRule[SSCliRestrictionOption]{{invalid: func(value SSCliRestrictionOption) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value SSCliRestrictionOption) any { return int64(value) }}}, true)
}

// SSOverrideCategoryCodec binds MAP-SS-DataTypes.OverrideCategory.
func SSOverrideCategoryCodec() ValueCodec[BERValue[SSOverrideCategory]] {
	return integerValueCodec[SSOverrideCategory]("MAP-SS-DataTypes.OverrideCategory", "OverrideCategory", []primitiveRule[SSOverrideCategory]{{invalid: func(value SSOverrideCategory) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SSOverrideCategory) any { return int64(value) }}}, true)
}

// SSSSForBSCodeCodec binds MAP-SS-DataTypes.SS-ForBS-Code.
func SSSSForBSCodeCodec() ValueCodec[SSSSForBSCode] {
	return compositeValueCodec[SSSSForBSCode, *SSSSForBSCode]()
}

// SSGenericServiceInfoCodec binds MAP-SS-DataTypes.GenericServiceInfo.
func SSGenericServiceInfoCodec() ValueCodec[SSGenericServiceInfo] {
	return compositeValueCodec[SSGenericServiceInfo, *SSGenericServiceInfo]()
}

// SSCCBSFeatureListCodec binds MAP-SS-DataTypes.CCBS-FeatureList.
func SSCCBSFeatureListCodec() ValueCodec[SSCCBSFeatureList] {
	return pointerValueCodec(UnmarshalBERSSCCBSFeatureList, MarshalBERSSCCBSFeatureList, MarshalDERSSCCBSFeatureList)
}

// SSCCBSFeatureCodec binds MAP-SS-DataTypes.CCBS-Feature.
func SSCCBSFeatureCodec() ValueCodec[SSCCBSFeature] {
	return compositeValueCodec[SSCCBSFeature, *SSCCBSFeature]()
}

// SSCCBSIndexCodec binds MAP-SS-DataTypes.CCBS-Index.
func SSCCBSIndexCodec() ValueCodec[BERValue[SSCCBSIndex]] {
	return integerValueCodec[SSCCBSIndex]("MAP-SS-DataTypes.CCBS-Index", "CCBS-Index", []primitiveRule[SSCCBSIndex]{{invalid: func(value SSCCBSIndex) bool { return !(int64(value) >= 1 && int64(value) <= 5) }, description: "(1..5)", clause: "51.4", observed: func(value SSCCBSIndex) any { return int64(value) }}}, false)
}

// SSInterrogateSSResCodec binds MAP-SS-DataTypes.InterrogateSS-Res.
func SSInterrogateSSResCodec() ValueCodec[SSInterrogateSSRes] {
	return compositeValueCodec[SSInterrogateSSRes, *SSInterrogateSSRes]()
}

// SSUSSDArgCodec binds MAP-SS-DataTypes.USSD-Arg.
func SSUSSDArgCodec() ValueCodec[SSUSSDArg] {
	return compositeValueCodec[SSUSSDArg, *SSUSSDArg]()
}

// SSUSSDResCodec binds MAP-SS-DataTypes.USSD-Res.
func SSUSSDResCodec() ValueCodec[SSUSSDRes] {
	return compositeValueCodec[SSUSSDRes, *SSUSSDRes]()
}

// SSUSSDDataCodingSchemeCodec binds MAP-SS-DataTypes.USSD-DataCodingScheme.
func SSUSSDDataCodingSchemeCodec() ValueCodec[BERValue[SSUSSDDataCodingScheme]] {
	return octetValueCodec[SSUSSDDataCodingScheme]("MAP-SS-DataTypes.USSD-DataCodingScheme", "USSD-DataCodingScheme", []primitiveRule[SSUSSDDataCodingScheme]{{invalid: func(value SSUSSDDataCodingScheme) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value SSUSSDDataCodingScheme) int { return len(value) }}})
}

// SSUSSDStringCodec binds MAP-SS-DataTypes.USSD-String.
func SSUSSDStringCodec() ValueCodec[BERValue[SSUSSDString]] {
	return octetValueCodec[SSUSSDString]("MAP-SS-DataTypes.USSD-String", "USSD-String", []primitiveRule[SSUSSDString]{{invalid: func(value SSUSSDString) bool { return !(len(value) >= 1 && len(value) <= 160) }, description: "SIZE (1..160)", clause: "51.5", length: func(value SSUSSDString) int { return len(value) }}})
}

// SSPasswordCodec binds MAP-SS-DataTypes.Password.
func SSPasswordCodec() ValueCodec[BERValue[SSPassword]] {
	return pointerValueCodec(UnmarshalBERSSPassword, MarshalBERSSPassword, MarshalDERSSPassword)
}

// SSGuidanceInfoCodec binds MAP-SS-DataTypes.GuidanceInfo.
func SSGuidanceInfoCodec() ValueCodec[BERValue[SSGuidanceInfo]] {
	return integerValueCodec[SSGuidanceInfo]("MAP-SS-DataTypes.GuidanceInfo", "GuidanceInfo", []primitiveRule[SSGuidanceInfo]{{invalid: func(value SSGuidanceInfo) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value SSGuidanceInfo) any { return int64(value) }}}, true)
}

// SSSSListCodec binds MAP-SS-DataTypes.SS-List.
func SSSSListCodec() ValueCodec[SSSSList] {
	return pointerValueCodec(UnmarshalBERSSSSList, MarshalBERSSSSList, MarshalDERSSSSList)
}

// SSSSInfoListCodec binds MAP-SS-DataTypes.SS-InfoList.
func SSSSInfoListCodec() ValueCodec[SSSSInfoList] {
	return pointerValueCodec(UnmarshalBERSSSSInfoList, MarshalBERSSSSInfoList, MarshalDERSSSSInfoList)
}

// SSBasicServiceGroupListCodec binds MAP-SS-DataTypes.BasicServiceGroupList.
func SSBasicServiceGroupListCodec() ValueCodec[SSBasicServiceGroupList] {
	return pointerValueCodec(UnmarshalBERSSBasicServiceGroupList, MarshalBERSSBasicServiceGroupList, MarshalDERSSBasicServiceGroupList)
}

// SSSSInvocationNotificationArgCodec binds MAP-SS-DataTypes.SS-InvocationNotificationArg.
func SSSSInvocationNotificationArgCodec() ValueCodec[SSSSInvocationNotificationArg] {
	return compositeValueCodec[SSSSInvocationNotificationArg, *SSSSInvocationNotificationArg]()
}

// SSCCBSRequestStateCodec binds MAP-SS-DataTypes.CCBS-RequestState.
func SSCCBSRequestStateCodec() ValueCodec[BERValue[SSCCBSRequestState]] {
	return integerValueCodec[SSCCBSRequestState]("MAP-SS-DataTypes.CCBS-RequestState", "CCBS-RequestState", []primitiveRule[SSCCBSRequestState]{{invalid: func(value SSCCBSRequestState) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value SSCCBSRequestState) any { return int64(value) }}}, true)
}

// SSSSInvocationNotificationResCodec binds MAP-SS-DataTypes.SS-InvocationNotificationRes.
func SSSSInvocationNotificationResCodec() ValueCodec[SSSSInvocationNotificationRes] {
	return compositeValueCodec[SSSSInvocationNotificationRes, *SSSSInvocationNotificationRes]()
}

// SSSSEventSpecificationCodec binds MAP-SS-DataTypes.SS-EventSpecification.
func SSSSEventSpecificationCodec() ValueCodec[SSSSEventSpecification] {
	return pointerValueCodec(UnmarshalBERSSSSEventSpecification, MarshalBERSSSSEventSpecification, MarshalDERSSSSEventSpecification)
}

// SSRegisterCCEntryArgCodec binds MAP-SS-DataTypes.RegisterCC-EntryArg.
func SSRegisterCCEntryArgCodec() ValueCodec[SSRegisterCCEntryArg] {
	return compositeValueCodec[SSRegisterCCEntryArg, *SSRegisterCCEntryArg]()
}

// SSCCBSDataCodec binds MAP-SS-DataTypes.CCBS-Data.
func SSCCBSDataCodec() ValueCodec[SSCCBSData] {
	return compositeValueCodec[SSCCBSData, *SSCCBSData]()
}

// SSServiceIndicatorCodec binds MAP-SS-DataTypes.ServiceIndicator.
func SSServiceIndicatorCodec() ValueCodec[BERValue[SSServiceIndicator]] {
	return bitValueCodec("MAP-SS-DataTypes.ServiceIndicator", "ServiceIndicator", []primitiveRule[SSServiceIndicator]{{invalid: func(value SSServiceIndicator) bool { return !(value.BitLength >= 2 && value.BitLength <= 32) }, description: "SIZE (2..32)", clause: "51.5", length: func(value SSServiceIndicator) int { return value.BitLength }, encodedLength: func(value SSServiceIndicator) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 32}}})
}

// SSRegisterCCEntryResCodec binds MAP-SS-DataTypes.RegisterCC-EntryRes.
func SSRegisterCCEntryResCodec() ValueCodec[SSRegisterCCEntryRes] {
	return compositeValueCodec[SSRegisterCCEntryRes, *SSRegisterCCEntryRes]()
}

// SSEraseCCEntryArgCodec binds MAP-SS-DataTypes.EraseCC-EntryArg.
func SSEraseCCEntryArgCodec() ValueCodec[SSEraseCCEntryArg] {
	return compositeValueCodec[SSEraseCCEntryArg, *SSEraseCCEntryArg]()
}

// SSEraseCCEntryResCodec binds MAP-SS-DataTypes.EraseCC-EntryRes.
func SSEraseCCEntryResCodec() ValueCodec[SSEraseCCEntryRes] {
	return compositeValueCodec[SSEraseCCEntryRes, *SSEraseCCEntryRes]()
}
