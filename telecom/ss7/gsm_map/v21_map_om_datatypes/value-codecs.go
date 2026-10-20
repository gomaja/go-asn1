// Code generated from ASN.1. DO NOT EDIT.

package v21_map_om_datatypes

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

const mapProfileEnabled = true

func mapSourceProfile(source string) bool {
	module, _, _ := strings.Cut(source, ".")
	switch module {
	}
	return true
}
func trackMAPSource(opts []ber.DecodeOption, source string) []ber.DecodeOption {
	if strings.HasPrefix(source, "MAP-") {
		return ber.TrackMAPForm(opts)
	}
	return ber.TrackMAPSyntax(opts, mapSourceProfile(source))
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
	profile := mapSourceProfile(source)
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
		opts = ber.TrackMAPSyntax(opts, profile)
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
		if mapProfileEnabled && !profile {
			opts = ber.GenericMAPEncodeOptions(opts)
		}
		opts, commit := ber.StageEncodeReports(opts)
		defer func() { commit(returnErr == nil) }()
		if value.berReplayNode_ == nil {
			return fresh(value.Value, false, opts)
		}
		boundary := mapProfileEnabled && ber.MAPEncodeBoundary(opts)
		opts, err := ber.PrepareBERReplay(value.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return c.EncodeBER(value, mode) }, &value)
		if err != nil {
			return nil, err
		}
		if replay, ok := ber.PreparedBERReplay(value.berReplayNode_, opts); ok {
			encoded = replay
		} else {
			data, err := fresh(value.Value, false, opts)
			if err != nil {
				return nil, err
			}
			encoded = ber.PreserveEncodedBERNode(data, value.berReplayNode_, opts)
		}
		if boundary {
			returnErr = ber.CheckMAPEncoded(encoded, value.berReplayNode_, opts, func(data []byte, options ...ber.DecodeOption) error {
				_, err := c.DecodeBER(data, options...)
				return err
			})
		}
		if mapProfileEnabled && !boundary {
			returnErr = ber.DeferMAPEncodeCheck(value.berReplayNode_, opts)
		}
		if returnErr != nil {
			encoded = nil
		}
		return encoded, returnErr
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
// This private slice is read-only after package initialization. A strict
// generated call carries no mutable report state, and child appends are
// capacity-limited. It is never returned through the public typed API.
var mapRootEncodeOptions, mapRootEncodeCommit = ber.StageGeneratedEncodeReports(nil)

func stageMAPEncodeReports(opts []ber.EncodeOption) ([]ber.EncodeOption, func(bool)) {
	if !mapProfileEnabled {
		return ber.StageEncodeReports(opts)
	}
	if len(opts) == 0 {
		return mapRootEncodeOptions, mapRootEncodeCommit
	}
	return ber.StageGeneratedEncodeReports(opts)
}
func marshalFramedValue[T any](value *T, node *ber.ReplayNode, opts []ber.EncodeOption, recursive, fresh func(*T, ...ber.EncodeOption) ([]byte, error), flags byte, decoders ...func([]byte, ...ber.DecodeOption) (*T, error)) (encoded []byte, returnErr error) {
	if mapProfileEnabled && flags&2 == 0 {
		opts = ber.GenericMAPEncodeOptions(opts)
	}
	boundary := mapProfileEnabled && ber.MAPEncodeBoundary(opts)
	opts, commit := stageMAPEncodeReports(opts)
	defer func() { commit(returnErr == nil) }()
	if flags&1 != 0 && node == nil {
		encoded, returnErr = fresh(value, opts...)
	} else {
		var err error
		opts, err = ber.PrepareBERReplay(node, opts, func(mode ber.EncodeOption) ([]byte, error) { return recursive(value, mode) }, value)
		if err != nil {
			return nil, err
		}
		if data, ok := ber.PreparedBERReplay(node, opts); ok {
			encoded = data
		} else {
			data, err := fresh(value, opts...)
			encoded, returnErr = data, err
			if err == nil {
				encoded = ber.PreserveEncodedBERNode(data, node, opts)
			}
		}
	}
	retry := false
	if returnErr != nil && boundary {
		var retryOpts []ber.EncodeOption
		retryOpts, retry = ber.RetryMAPEncode(returnErr, opts)
		if retry {
			encoded, returnErr = recursive(value, retryOpts...)
			node = nil
		}
	}
	if returnErr == nil && mapProfileEnabled {
		if boundary && (node != nil || retry) {
			returnErr = ber.CheckMAPEncoded(encoded, node, opts, func(data []byte, options ...ber.DecodeOption) error {
				if len(decoders) > 0 {
					_, err := decoders[0](data, options...)
					return err
				}
				decoder, ok := any(new(T)).(interface {
					UnmarshalBER([]byte, ...ber.DecodeOption) error
				})
				if !ok {
					return ber.ErrInvalidCodec
				}
				return decoder.UnmarshalBER(data, options...)
			})
		} else if !boundary && node != nil {
			returnErr = ber.DeferMAPEncodeCheck(node, opts)
		}
	}
	if returnErr != nil {
		encoded = nil
	}
	return encoded, returnErr
}

func prepareValueBER(data []byte, opts []ber.DecodeOption, source, pathLabel string, probe func([]byte, []ber.DecodeOption) error) ([]byte, []ber.DecodeOption, error) {
	opts = trackMAPSource(opts, source)
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

// checkPublicMAPEncode covers entries without shared ReplayNode framing.
func checkPublicMAPEncode[T any](value *T, node *ber.ReplayNode, opts []ber.EncodeOption, data *[]byte, err *error, boundary, external bool) {
	if !mapProfileEnabled {
		return
	}
	if !boundary {
		if *err == nil {
			if external {
				*err = ber.DeferMAPEncodeCheck(nil, opts, *data)
			} else {
				*err = ber.DeferMAPEncodeCheck(node, opts)
			}
		}
		return
	}
	retryOpts, retry := ber.RetryMAPEncode(*err, opts)
	if retry {
		encoder, ok := any(value).(interface {
			MarshalBER(...ber.EncodeOption) ([]byte, error)
		})
		if !ok {
			*err = ber.ErrInvalidCodec
			return
		}
		*data, *err = encoder.MarshalBER(retryOpts...)
		node = nil
	}
	if *err != nil || !external && node == nil && !retry {
		return
	}
	decode := func(data []byte, options ...ber.DecodeOption) error {
		decoder, ok := any(new(T)).(interface {
			UnmarshalBER([]byte, ...ber.DecodeOption) error
		})
		if !ok {
			return ber.ErrInvalidCodec
		}
		return decoder.UnmarshalBER(data, options...)
	}
	if external {
		*err = ber.CheckMAPEncodedElement(*data, opts, decode)
	} else {
		*err = ber.CheckMAPEncoded(*data, node, opts, decode)
	}
	if *err != nil {
		*data = nil
	}
}

// OMActivateTraceModeArgCodec binds MAP-OM-DataTypes.ActivateTraceModeArg.
func OMActivateTraceModeArgCodec() ValueCodec[OMActivateTraceModeArg] {
	return compositeValueCodec[OMActivateTraceModeArg, *OMActivateTraceModeArg]()
}

// OMMDTConfigurationCodec binds MAP-OM-DataTypes.MDT-Configuration.
func OMMDTConfigurationCodec() ValueCodec[OMMDTConfiguration] {
	return compositeValueCodec[OMMDTConfiguration, *OMMDTConfiguration]()
}

// OMMDTAllowedPLMNIdListCodec binds MAP-OM-DataTypes.MDT-Allowed-PLMNId-List.
func OMMDTAllowedPLMNIdListCodec() ValueCodec[OMMDTAllowedPLMNIdList] {
	return pointerValueCodec(UnmarshalBEROMMDTAllowedPLMNIdList, MarshalBEROMMDTAllowedPLMNIdList, MarshalDEROMMDTAllowedPLMNIdList)
}

// OMPeriodUMTSCodec binds MAP-OM-DataTypes.PeriodUMTS.
func OMPeriodUMTSCodec() ValueCodec[BERValue[OMPeriodUMTS]] {
	return integerValueCodec[OMPeriodUMTS]("MAP-OM-DataTypes.PeriodUMTS", "PeriodUMTS", []primitiveRule[OMPeriodUMTS]{{invalid: func(value OMPeriodUMTS) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7 && int64(value) != 8 && int64(value) != 9 && int64(value) != 10 && int64(value) != 11 && int64(value) != 12 && int64(value) != 13 && int64(value) != 14)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", clause: "20", observed: func(value OMPeriodUMTS) any { return int64(value) }}}, true)
}

// OMPeriodLTECodec binds MAP-OM-DataTypes.PeriodLTE.
func OMPeriodLTECodec() ValueCodec[BERValue[OMPeriodLTE]] {
	return integerValueCodec[OMPeriodLTE]("MAP-OM-DataTypes.PeriodLTE", "PeriodLTE", []primitiveRule[OMPeriodLTE]{{invalid: func(value OMPeriodLTE) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value OMPeriodLTE) any { return int64(value) }}}, true)
}

// OMPositioningMethodCodec binds MAP-OM-DataTypes.PositioningMethod.
func OMPositioningMethodCodec() ValueCodec[BERValue[OMPositioningMethod]] {
	return octetValueCodec[OMPositioningMethod]("MAP-OM-DataTypes.PositioningMethod", "PositioningMethod", []primitiveRule[OMPositioningMethod]{{invalid: func(value OMPositioningMethod) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value OMPositioningMethod) int { return len(value) }}})
}

// OMMeasurementQuantityCodec binds MAP-OM-DataTypes.MeasurementQuantity.
func OMMeasurementQuantityCodec() ValueCodec[BERValue[OMMeasurementQuantity]] {
	return octetValueCodec[OMMeasurementQuantity]("MAP-OM-DataTypes.MeasurementQuantity", "MeasurementQuantity", []primitiveRule[OMMeasurementQuantity]{{invalid: func(value OMMeasurementQuantity) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value OMMeasurementQuantity) int { return len(value) }}})
}

// OMEventThreshold1FCodec binds MAP-OM-DataTypes.EventThreshold1F.
func OMEventThreshold1FCodec() ValueCodec[BERValue[OMEventThreshold1F]] {
	return integerValueCodec[OMEventThreshold1F]("MAP-OM-DataTypes.EventThreshold1F", "EventThreshold1F", []primitiveRule[OMEventThreshold1F]{{invalid: func(value OMEventThreshold1F) bool { return !(int64(value) >= -120 && int64(value) <= 165) }, description: "(-120..165)", clause: "51.4", observed: func(value OMEventThreshold1F) any { return int64(value) }}}, false)
}

// OMEventThreshold1ICodec binds MAP-OM-DataTypes.EventThreshold1I.
func OMEventThreshold1ICodec() ValueCodec[BERValue[OMEventThreshold1I]] {
	return integerValueCodec[OMEventThreshold1I]("MAP-OM-DataTypes.EventThreshold1I", "EventThreshold1I", []primitiveRule[OMEventThreshold1I]{{invalid: func(value OMEventThreshold1I) bool { return !(int64(value) >= -120 && int64(value) <= -25) }, description: "(-120..-25)", clause: "51.4", observed: func(value OMEventThreshold1I) any { return int64(value) }}}, false)
}

// OMJobTypeCodec binds MAP-OM-DataTypes.JobType.
func OMJobTypeCodec() ValueCodec[BERValue[OMJobType]] {
	return integerValueCodec[OMJobType]("MAP-OM-DataTypes.JobType", "JobType", []primitiveRule[OMJobType]{{invalid: func(value OMJobType) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3)
	}, description: "ENUMERATED {0, 1, 2, 3}", clause: "20", observed: func(value OMJobType) any { return int64(value) }}}, true)
}

// OMAreaScopeCodec binds MAP-OM-DataTypes.AreaScope.
func OMAreaScopeCodec() ValueCodec[OMAreaScope] {
	return compositeValueCodec[OMAreaScope, *OMAreaScope]()
}

// OMCGIListCodec binds MAP-OM-DataTypes.CGI-List.
func OMCGIListCodec() ValueCodec[OMCGIList] {
	return pointerValueCodec(UnmarshalBEROMCGIList, MarshalBEROMCGIList, MarshalDEROMCGIList)
}

// OMEUTRANCGIListCodec binds MAP-OM-DataTypes.E-UTRAN-CGI-List.
func OMEUTRANCGIListCodec() ValueCodec[OMEUTRANCGIList] {
	return pointerValueCodec(UnmarshalBEROMEUTRANCGIList, MarshalBEROMEUTRANCGIList, MarshalDEROMEUTRANCGIList)
}

// OMRoutingAreaIdListCodec binds MAP-OM-DataTypes.RoutingAreaId-List.
func OMRoutingAreaIdListCodec() ValueCodec[OMRoutingAreaIdList] {
	return pointerValueCodec(UnmarshalBEROMRoutingAreaIdList, MarshalBEROMRoutingAreaIdList, MarshalDEROMRoutingAreaIdList)
}

// OMLocationAreaIdListCodec binds MAP-OM-DataTypes.LocationAreaId-List.
func OMLocationAreaIdListCodec() ValueCodec[OMLocationAreaIdList] {
	return pointerValueCodec(UnmarshalBEROMLocationAreaIdList, MarshalBEROMLocationAreaIdList, MarshalDEROMLocationAreaIdList)
}

// OMTrackingAreaIdListCodec binds MAP-OM-DataTypes.TrackingAreaId-List.
func OMTrackingAreaIdListCodec() ValueCodec[OMTrackingAreaIdList] {
	return pointerValueCodec(UnmarshalBEROMTrackingAreaIdList, MarshalBEROMTrackingAreaIdList, MarshalDEROMTrackingAreaIdList)
}

// OMListOfMeasurementsCodec binds MAP-OM-DataTypes.ListOfMeasurements.
func OMListOfMeasurementsCodec() ValueCodec[BERValue[OMListOfMeasurements]] {
	return octetValueCodec[OMListOfMeasurements]("MAP-OM-DataTypes.ListOfMeasurements", "ListOfMeasurements", []primitiveRule[OMListOfMeasurements]{{invalid: func(value OMListOfMeasurements) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value OMListOfMeasurements) int { return len(value) }}})
}

// OMReportingTriggerCodec binds MAP-OM-DataTypes.ReportingTrigger.
func OMReportingTriggerCodec() ValueCodec[BERValue[OMReportingTrigger]] {
	return octetValueCodec[OMReportingTrigger]("MAP-OM-DataTypes.ReportingTrigger", "ReportingTrigger", []primitiveRule[OMReportingTrigger]{{invalid: func(value OMReportingTrigger) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value OMReportingTrigger) int { return len(value) }}})
}

// OMReportIntervalCodec binds MAP-OM-DataTypes.ReportInterval.
func OMReportIntervalCodec() ValueCodec[BERValue[OMReportInterval]] {
	return integerValueCodec[OMReportInterval]("MAP-OM-DataTypes.ReportInterval", "ReportInterval", []primitiveRule[OMReportInterval]{{invalid: func(value OMReportInterval) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7 && int64(value) != 8 && int64(value) != 9 && int64(value) != 10 && int64(value) != 11 && int64(value) != 12 && int64(value) != 13 && int64(value) != 14 && int64(value) != 15 && int64(value) != 16 && int64(value) != 17 && int64(value) != 18 && int64(value) != 19 && int64(value) != 20 && int64(value) != 21 && int64(value) != 22 && int64(value) != 23 && int64(value) != 24 && int64(value) != 25 && int64(value) != 26 && int64(value) != 27)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}", clause: "20", observed: func(value OMReportInterval) any { return int64(value) }}}, true)
}

// OMReportAmountCodec binds MAP-OM-DataTypes.ReportAmount.
func OMReportAmountCodec() ValueCodec[BERValue[OMReportAmount]] {
	return integerValueCodec[OMReportAmount]("MAP-OM-DataTypes.ReportAmount", "ReportAmount", []primitiveRule[OMReportAmount]{{invalid: func(value OMReportAmount) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", clause: "20", observed: func(value OMReportAmount) any { return int64(value) }}}, true)
}

// OMEventThresholdRSRPCodec binds MAP-OM-DataTypes.EventThresholdRSRP.
func OMEventThresholdRSRPCodec() ValueCodec[BERValue[OMEventThresholdRSRP]] {
	return integerValueCodec[OMEventThresholdRSRP]("MAP-OM-DataTypes.EventThresholdRSRP", "EventThresholdRSRP", []primitiveRule[OMEventThresholdRSRP]{{invalid: func(value OMEventThresholdRSRP) bool { return !(int64(value) >= 0 && int64(value) <= 97) }, description: "(0..97)", clause: "51.4", observed: func(value OMEventThresholdRSRP) any { return int64(value) }}}, false)
}

// OMEventThresholdRSRQCodec binds MAP-OM-DataTypes.EventThresholdRSRQ.
func OMEventThresholdRSRQCodec() ValueCodec[BERValue[OMEventThresholdRSRQ]] {
	return integerValueCodec[OMEventThresholdRSRQ]("MAP-OM-DataTypes.EventThresholdRSRQ", "EventThresholdRSRQ", []primitiveRule[OMEventThresholdRSRQ]{{invalid: func(value OMEventThresholdRSRQ) bool { return !(int64(value) >= 0 && int64(value) <= 34) }, description: "(0..34)", clause: "51.4", observed: func(value OMEventThresholdRSRQ) any { return int64(value) }}}, false)
}

// OMLoggingIntervalCodec binds MAP-OM-DataTypes.LoggingInterval.
func OMLoggingIntervalCodec() ValueCodec[BERValue[OMLoggingInterval]] {
	return integerValueCodec[OMLoggingInterval]("MAP-OM-DataTypes.LoggingInterval", "LoggingInterval", []primitiveRule[OMLoggingInterval]{{invalid: func(value OMLoggingInterval) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", clause: "20", observed: func(value OMLoggingInterval) any { return int64(value) }}}, true)
}

// OMLoggingDurationCodec binds MAP-OM-DataTypes.LoggingDuration.
func OMLoggingDurationCodec() ValueCodec[BERValue[OMLoggingDuration]] {
	return integerValueCodec[OMLoggingDuration]("MAP-OM-DataTypes.LoggingDuration", "LoggingDuration", []primitiveRule[OMLoggingDuration]{{invalid: func(value OMLoggingDuration) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5}", clause: "20", observed: func(value OMLoggingDuration) any { return int64(value) }}}, true)
}

// OMTraceReferenceCodec binds MAP-OM-DataTypes.TraceReference.
func OMTraceReferenceCodec() ValueCodec[BERValue[OMTraceReference]] {
	return octetValueCodec[OMTraceReference]("MAP-OM-DataTypes.TraceReference", "TraceReference", []primitiveRule[OMTraceReference]{{invalid: func(value OMTraceReference) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value OMTraceReference) int { return len(value) }}})
}

// OMTraceReference2Codec binds MAP-OM-DataTypes.TraceReference2.
func OMTraceReference2Codec() ValueCodec[BERValue[OMTraceReference2]] {
	return octetValueCodec[OMTraceReference2]("MAP-OM-DataTypes.TraceReference2", "TraceReference2", []primitiveRule[OMTraceReference2]{{invalid: func(value OMTraceReference2) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value OMTraceReference2) int { return len(value) }}})
}

// OMTraceRecordingSessionReferenceCodec binds MAP-OM-DataTypes.TraceRecordingSessionReference.
func OMTraceRecordingSessionReferenceCodec() ValueCodec[BERValue[OMTraceRecordingSessionReference]] {
	return octetValueCodec[OMTraceRecordingSessionReference]("MAP-OM-DataTypes.TraceRecordingSessionReference", "TraceRecordingSessionReference", []primitiveRule[OMTraceRecordingSessionReference]{{invalid: func(value OMTraceRecordingSessionReference) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value OMTraceRecordingSessionReference) int { return len(value) }}})
}

// OMTraceTypeCodec binds MAP-OM-DataTypes.TraceType.
func OMTraceTypeCodec() ValueCodec[BERValue[OMTraceType]] {
	return integerValueCodec[OMTraceType]("MAP-OM-DataTypes.TraceType", "TraceType", []primitiveRule[OMTraceType]{{invalid: func(value OMTraceType) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "51.4", observed: func(value OMTraceType) any { return int64(value) }}}, false)
}

// OMTraceDepthListCodec binds MAP-OM-DataTypes.TraceDepthList.
func OMTraceDepthListCodec() ValueCodec[OMTraceDepthList] {
	return compositeValueCodec[OMTraceDepthList, *OMTraceDepthList]()
}

// OMTraceDepthCodec binds MAP-OM-DataTypes.TraceDepth.
func OMTraceDepthCodec() ValueCodec[BERValue[OMTraceDepth]] {
	return integerValueCodec[OMTraceDepth]("MAP-OM-DataTypes.TraceDepth", "TraceDepth", nil, true)
}

// OMTraceDepthExtensionCodec binds MAP-OM-DataTypes.TraceDepthExtension.
func OMTraceDepthExtensionCodec() ValueCodec[BERValue[OMTraceDepthExtension]] {
	return integerValueCodec[OMTraceDepthExtension]("MAP-OM-DataTypes.TraceDepthExtension", "TraceDepthExtension", nil, true)
}

// OMTraceNETypeListCodec binds MAP-OM-DataTypes.TraceNE-TypeList.
func OMTraceNETypeListCodec() ValueCodec[BERValue[OMTraceNETypeList]] {
	return bitValueCodec("MAP-OM-DataTypes.TraceNE-TypeList", "TraceNE-TypeList", []primitiveRule[OMTraceNETypeList]{{invalid: func(value OMTraceNETypeList) bool { return !(value.BitLength >= 6 && value.BitLength <= 16) }, description: "SIZE (6..16)", clause: "51.5", length: func(value OMTraceNETypeList) int { return value.BitLength }, encodedLength: func(value OMTraceNETypeList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}})
}

// OMTraceInterfaceListCodec binds MAP-OM-DataTypes.TraceInterfaceList.
func OMTraceInterfaceListCodec() ValueCodec[OMTraceInterfaceList] {
	return compositeValueCodec[OMTraceInterfaceList, *OMTraceInterfaceList]()
}

// OMMSCSInterfaceListCodec binds MAP-OM-DataTypes.MSC-S-InterfaceList.
func OMMSCSInterfaceListCodec() ValueCodec[BERValue[OMMSCSInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.MSC-S-InterfaceList", "MSC-S-InterfaceList", []primitiveRule[OMMSCSInterfaceList]{{invalid: func(value OMMSCSInterfaceList) bool { return !(value.BitLength >= 10 && value.BitLength <= 16) }, description: "SIZE (10..16)", clause: "51.5", length: func(value OMMSCSInterfaceList) int { return value.BitLength }, encodedLength: func(value OMMSCSInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 10, Max: 16}}})
}

// OMMGWInterfaceListCodec binds MAP-OM-DataTypes.MGW-InterfaceList.
func OMMGWInterfaceListCodec() ValueCodec[BERValue[OMMGWInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.MGW-InterfaceList", "MGW-InterfaceList", []primitiveRule[OMMGWInterfaceList]{{invalid: func(value OMMGWInterfaceList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value OMMGWInterfaceList) int { return value.BitLength }, encodedLength: func(value OMMGWInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// OMSGSNInterfaceListCodec binds MAP-OM-DataTypes.SGSN-InterfaceList.
func OMSGSNInterfaceListCodec() ValueCodec[BERValue[OMSGSNInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGSN-InterfaceList", "SGSN-InterfaceList", []primitiveRule[OMSGSNInterfaceList]{{invalid: func(value OMSGSNInterfaceList) bool { return !(value.BitLength >= 8 && value.BitLength <= 16) }, description: "SIZE (8..16)", clause: "51.5", length: func(value OMSGSNInterfaceList) int { return value.BitLength }, encodedLength: func(value OMSGSNInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 8, Max: 16}}})
}

// OMGGSNInterfaceListCodec binds MAP-OM-DataTypes.GGSN-InterfaceList.
func OMGGSNInterfaceListCodec() ValueCodec[BERValue[OMGGSNInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.GGSN-InterfaceList", "GGSN-InterfaceList", []primitiveRule[OMGGSNInterfaceList]{{invalid: func(value OMGGSNInterfaceList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value OMGGSNInterfaceList) int { return value.BitLength }, encodedLength: func(value OMGGSNInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// OMRNCInterfaceListCodec binds MAP-OM-DataTypes.RNC-InterfaceList.
func OMRNCInterfaceListCodec() ValueCodec[BERValue[OMRNCInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.RNC-InterfaceList", "RNC-InterfaceList", []primitiveRule[OMRNCInterfaceList]{{invalid: func(value OMRNCInterfaceList) bool { return !(value.BitLength >= 4 && value.BitLength <= 8) }, description: "SIZE (4..8)", clause: "51.5", length: func(value OMRNCInterfaceList) int { return value.BitLength }, encodedLength: func(value OMRNCInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 8}}})
}

// OMBMSCInterfaceListCodec binds MAP-OM-DataTypes.BMSC-InterfaceList.
func OMBMSCInterfaceListCodec() ValueCodec[BERValue[OMBMSCInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.BMSC-InterfaceList", "BMSC-InterfaceList", []primitiveRule[OMBMSCInterfaceList]{{invalid: func(value OMBMSCInterfaceList) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value OMBMSCInterfaceList) int { return value.BitLength }, encodedLength: func(value OMBMSCInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// OMMMEInterfaceListCodec binds MAP-OM-DataTypes.MME-InterfaceList.
func OMMMEInterfaceListCodec() ValueCodec[BERValue[OMMMEInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.MME-InterfaceList", "MME-InterfaceList", []primitiveRule[OMMMEInterfaceList]{{invalid: func(value OMMMEInterfaceList) bool { return !(value.BitLength >= 5 && value.BitLength <= 8) }, description: "SIZE (5..8)", clause: "51.5", length: func(value OMMMEInterfaceList) int { return value.BitLength }, encodedLength: func(value OMMMEInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 5, Max: 8}}})
}

// OMSGWInterfaceListCodec binds MAP-OM-DataTypes.SGW-InterfaceList.
func OMSGWInterfaceListCodec() ValueCodec[BERValue[OMSGWInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGW-InterfaceList", "SGW-InterfaceList", []primitiveRule[OMSGWInterfaceList]{{invalid: func(value OMSGWInterfaceList) bool { return !(value.BitLength >= 5 && value.BitLength <= 8) }, description: "SIZE (5..8)", clause: "51.5", length: func(value OMSGWInterfaceList) int { return value.BitLength }, encodedLength: func(value OMSGWInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 5, Max: 8}}})
}

// OMPGWInterfaceListCodec binds MAP-OM-DataTypes.PGW-InterfaceList.
func OMPGWInterfaceListCodec() ValueCodec[BERValue[OMPGWInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.PGW-InterfaceList", "PGW-InterfaceList", []primitiveRule[OMPGWInterfaceList]{{invalid: func(value OMPGWInterfaceList) bool { return !(value.BitLength >= 8 && value.BitLength <= 16) }, description: "SIZE (8..16)", clause: "51.5", length: func(value OMPGWInterfaceList) int { return value.BitLength }, encodedLength: func(value OMPGWInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 8, Max: 16}}})
}

// OMENBInterfaceListCodec binds MAP-OM-DataTypes.ENB-InterfaceList.
func OMENBInterfaceListCodec() ValueCodec[BERValue[OMENBInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.ENB-InterfaceList", "ENB-InterfaceList", []primitiveRule[OMENBInterfaceList]{{invalid: func(value OMENBInterfaceList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value OMENBInterfaceList) int { return value.BitLength }, encodedLength: func(value OMENBInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// OMTraceEventListCodec binds MAP-OM-DataTypes.TraceEventList.
func OMTraceEventListCodec() ValueCodec[OMTraceEventList] {
	return compositeValueCodec[OMTraceEventList, *OMTraceEventList]()
}

// OMMSCSEventListCodec binds MAP-OM-DataTypes.MSC-S-EventList.
func OMMSCSEventListCodec() ValueCodec[BERValue[OMMSCSEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.MSC-S-EventList", "MSC-S-EventList", []primitiveRule[OMMSCSEventList]{{invalid: func(value OMMSCSEventList) bool { return !(value.BitLength >= 5 && value.BitLength <= 16) }, description: "SIZE (5..16)", clause: "51.5", length: func(value OMMSCSEventList) int { return value.BitLength }, encodedLength: func(value OMMSCSEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 5, Max: 16}}})
}

// OMMGWEventListCodec binds MAP-OM-DataTypes.MGW-EventList.
func OMMGWEventListCodec() ValueCodec[BERValue[OMMGWEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.MGW-EventList", "MGW-EventList", []primitiveRule[OMMGWEventList]{{invalid: func(value OMMGWEventList) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value OMMGWEventList) int { return value.BitLength }, encodedLength: func(value OMMGWEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// OMSGSNEventListCodec binds MAP-OM-DataTypes.SGSN-EventList.
func OMSGSNEventListCodec() ValueCodec[BERValue[OMSGSNEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGSN-EventList", "SGSN-EventList", []primitiveRule[OMSGSNEventList]{{invalid: func(value OMSGSNEventList) bool { return !(value.BitLength >= 4 && value.BitLength <= 16) }, description: "SIZE (4..16)", clause: "51.5", length: func(value OMSGSNEventList) int { return value.BitLength }, encodedLength: func(value OMSGSNEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 16}}})
}

// OMGGSNEventListCodec binds MAP-OM-DataTypes.GGSN-EventList.
func OMGGSNEventListCodec() ValueCodec[BERValue[OMGGSNEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.GGSN-EventList", "GGSN-EventList", []primitiveRule[OMGGSNEventList]{{invalid: func(value OMGGSNEventList) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value OMGGSNEventList) int { return value.BitLength }, encodedLength: func(value OMGGSNEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// OMBMSCEventListCodec binds MAP-OM-DataTypes.BMSC-EventList.
func OMBMSCEventListCodec() ValueCodec[BERValue[OMBMSCEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.BMSC-EventList", "BMSC-EventList", []primitiveRule[OMBMSCEventList]{{invalid: func(value OMBMSCEventList) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value OMBMSCEventList) int { return value.BitLength }, encodedLength: func(value OMBMSCEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// OMMMEEventListCodec binds MAP-OM-DataTypes.MME-EventList.
func OMMMEEventListCodec() ValueCodec[BERValue[OMMMEEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.MME-EventList", "MME-EventList", []primitiveRule[OMMMEEventList]{{invalid: func(value OMMMEEventList) bool { return !(value.BitLength >= 6 && value.BitLength <= 8) }, description: "SIZE (6..8)", clause: "51.5", length: func(value OMMMEEventList) int { return value.BitLength }, encodedLength: func(value OMMMEEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 8}}})
}

// OMSGWEventListCodec binds MAP-OM-DataTypes.SGW-EventList.
func OMSGWEventListCodec() ValueCodec[BERValue[OMSGWEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGW-EventList", "SGW-EventList", []primitiveRule[OMSGWEventList]{{invalid: func(value OMSGWEventList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value OMSGWEventList) int { return value.BitLength }, encodedLength: func(value OMSGWEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// OMPGWEventListCodec binds MAP-OM-DataTypes.PGW-EventList.
func OMPGWEventListCodec() ValueCodec[BERValue[OMPGWEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.PGW-EventList", "PGW-EventList", []primitiveRule[OMPGWEventList]{{invalid: func(value OMPGWEventList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value OMPGWEventList) int { return value.BitLength }, encodedLength: func(value OMPGWEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// OMTracePropagationListCodec binds MAP-OM-DataTypes.TracePropagationList.
func OMTracePropagationListCodec() ValueCodec[OMTracePropagationList] {
	return compositeValueCodec[OMTracePropagationList, *OMTracePropagationList]()
}

// OMActivateTraceModeResCodec binds MAP-OM-DataTypes.ActivateTraceModeRes.
func OMActivateTraceModeResCodec() ValueCodec[OMActivateTraceModeRes] {
	return compositeValueCodec[OMActivateTraceModeRes, *OMActivateTraceModeRes]()
}

// OMDeactivateTraceModeArgCodec binds MAP-OM-DataTypes.DeactivateTraceModeArg.
func OMDeactivateTraceModeArgCodec() ValueCodec[OMDeactivateTraceModeArg] {
	return compositeValueCodec[OMDeactivateTraceModeArg, *OMDeactivateTraceModeArg]()
}

// OMDeactivateTraceModeResCodec binds MAP-OM-DataTypes.DeactivateTraceModeRes.
func OMDeactivateTraceModeResCodec() ValueCodec[OMDeactivateTraceModeRes] {
	return compositeValueCodec[OMDeactivateTraceModeRes, *OMDeactivateTraceModeRes]()
}
