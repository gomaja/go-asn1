// Code generated from ASN.1. DO NOT EDIT.

package gsm_map

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
	case "SS-DataTypes":
		return false
	case "SS-Errors":
		return false
	case "SS-Operations":
		return false
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

// BearerServiceCodeCodec binds MAP-BS-Code.BearerServiceCode.
func BearerServiceCodeCodec() ValueCodec[BERValue[BearerServiceCode]] {
	return octetValueCodec[BearerServiceCode]("MAP-BS-Code.BearerServiceCode", "BearerServiceCode", []primitiveRule[BearerServiceCode]{{invalid: func(value BearerServiceCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value BearerServiceCode) int { return len(value) }}})
}

// ExtBearerServiceCodeCodec binds MAP-BS-Code.Ext-BearerServiceCode.
func ExtBearerServiceCodeCodec() ValueCodec[BERValue[ExtBearerServiceCode]] {
	return octetValueCodec[ExtBearerServiceCode]("MAP-BS-Code.Ext-BearerServiceCode", "Ext-BearerServiceCode", []primitiveRule[ExtBearerServiceCode]{{invalid: func(value ExtBearerServiceCode) bool { return !(len(value) >= 1 && len(value) <= 5) }, description: "SIZE (1..5)", clause: "51.5", length: func(value ExtBearerServiceCode) int { return len(value) }}})
}

// ExtensionContainerCodec binds MAP-ExtensionDataTypes.ExtensionContainer.
func ExtensionContainerCodec() ValueCodec[ExtensionContainer] {
	return compositeValueCodec[ExtensionContainer, *ExtensionContainer]()
}

// SLRArgExtensionContainerCodec binds MAP-ExtensionDataTypes.SLR-ArgExtensionContainer.
func SLRArgExtensionContainerCodec() ValueCodec[SLRArgExtensionContainer] {
	return compositeValueCodec[SLRArgExtensionContainer, *SLRArgExtensionContainer]()
}

// PrivateExtensionListCodec binds MAP-ExtensionDataTypes.PrivateExtensionList.
func PrivateExtensionListCodec() ValueCodec[PrivateExtensionList] {
	return pointerValueCodec(UnmarshalBERPrivateExtensionList, MarshalBERPrivateExtensionList, MarshalDERPrivateExtensionList)
}

// PrivateExtensionCodec binds MAP-ExtensionDataTypes.PrivateExtension.
func PrivateExtensionCodec() ValueCodec[PrivateExtension] {
	return compositeValueCodec[PrivateExtension, *PrivateExtension]()
}

// PCSExtensionsCodec binds MAP-ExtensionDataTypes.PCS-Extensions.
func PCSExtensionsCodec() ValueCodec[PCSExtensions] {
	return compositeValueCodec[PCSExtensions, *PCSExtensions]()
}

// SLRArgPCSExtensionsCodec binds MAP-ExtensionDataTypes.SLR-Arg-PCS-Extensions.
func SLRArgPCSExtensionsCodec() ValueCodec[SLRArgPCSExtensions] {
	return compositeValueCodec[SLRArgPCSExtensions, *SLRArgPCSExtensions]()
}

// SSCodeCodec binds MAP-SS-Code.SS-Code.
func SSCodeCodec() ValueCodec[BERValue[SSCode]] {
	return pointerValueCodec(UnmarshalBERSSCode, MarshalBERSSCode, MarshalDERSSCode)
}

// TeleserviceCodeCodec binds MAP-TS-Code.TeleserviceCode.
func TeleserviceCodeCodec() ValueCodec[BERValue[TeleserviceCode]] {
	return octetValueCodec[TeleserviceCode]("MAP-TS-Code.TeleserviceCode", "TeleserviceCode", []primitiveRule[TeleserviceCode]{{invalid: func(value TeleserviceCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value TeleserviceCode) int { return len(value) }}})
}

// ExtTeleserviceCodeCodec binds MAP-TS-Code.Ext-TeleserviceCode.
func ExtTeleserviceCodeCodec() ValueCodec[BERValue[ExtTeleserviceCode]] {
	return octetValueCodec[ExtTeleserviceCode]("MAP-TS-Code.Ext-TeleserviceCode", "Ext-TeleserviceCode", []primitiveRule[ExtTeleserviceCode]{{invalid: func(value ExtTeleserviceCode) bool { return !(len(value) >= 1 && len(value) <= 5) }, description: "SIZE (1..5)", clause: "51.5", length: func(value ExtTeleserviceCode) int { return len(value) }}})
}

// TBCDSTRINGCodec binds MAP-CommonDataTypes.TBCD-STRING.
func TBCDSTRINGCodec() ValueCodec[BERValue[TBCDSTRING]] {
	return octetValueCodec[TBCDSTRING]("MAP-CommonDataTypes.TBCD-STRING", "TBCD-STRING", nil)
}

// DiameterIdentityCodec binds MAP-CommonDataTypes.DiameterIdentity.
func DiameterIdentityCodec() ValueCodec[BERValue[DiameterIdentity]] {
	return octetValueCodec[DiameterIdentity]("MAP-CommonDataTypes.DiameterIdentity", "DiameterIdentity", []primitiveRule[DiameterIdentity]{{invalid: func(value DiameterIdentity) bool { return !(len(value) >= 9 && len(value) <= 255) }, description: "SIZE (9..255)", clause: "51.5", length: func(value DiameterIdentity) int { return len(value) }}})
}

// AddressStringCodec binds MAP-CommonDataTypes.AddressString.
func AddressStringCodec() ValueCodec[BERValue[AddressString]] {
	return octetValueCodec[AddressString]("MAP-CommonDataTypes.AddressString", "AddressString", []primitiveRule[AddressString]{{invalid: func(value AddressString) bool { return !(len(value) >= 1 && len(value) <= 20) }, description: "SIZE (1..20)", clause: "51.5", length: func(value AddressString) int { return len(value) }}})
}

// ISDNAddressStringCodec binds MAP-CommonDataTypes.ISDN-AddressString.
func ISDNAddressStringCodec() ValueCodec[BERValue[ISDNAddressString]] {
	return pointerValueCodec(UnmarshalBERISDNAddressString, MarshalBERISDNAddressString, MarshalDERISDNAddressString)
}

// FTNAddressStringCodec binds MAP-CommonDataTypes.FTN-AddressString.
func FTNAddressStringCodec() ValueCodec[BERValue[FTNAddressString]] {
	return pointerValueCodec(UnmarshalBERFTNAddressString, MarshalBERFTNAddressString, MarshalDERFTNAddressString)
}

// ISDNSubaddressStringCodec binds MAP-CommonDataTypes.ISDN-SubaddressString.
func ISDNSubaddressStringCodec() ValueCodec[BERValue[ISDNSubaddressString]] {
	return octetValueCodec[ISDNSubaddressString]("MAP-CommonDataTypes.ISDN-SubaddressString", "ISDN-SubaddressString", []primitiveRule[ISDNSubaddressString]{{invalid: func(value ISDNSubaddressString) bool { return !(len(value) >= 1 && len(value) <= 21) }, description: "SIZE (1..21)", clause: "51.5", length: func(value ISDNSubaddressString) int { return len(value) }}})
}

// ExternalSignalInfoCodec binds MAP-CommonDataTypes.ExternalSignalInfo.
func ExternalSignalInfoCodec() ValueCodec[ExternalSignalInfo] {
	return compositeValueCodec[ExternalSignalInfo, *ExternalSignalInfo]()
}

// SignalInfoCodec binds MAP-CommonDataTypes.SignalInfo.
func SignalInfoCodec() ValueCodec[BERValue[SignalInfo]] {
	return octetValueCodec[SignalInfo]("MAP-CommonDataTypes.SignalInfo", "SignalInfo", []primitiveRule[SignalInfo]{{invalid: func(value SignalInfo) bool { return !(len(value) >= 1 && len(value) <= 200) }, description: "SIZE (1..200)", clause: "51.5", length: func(value SignalInfo) int { return len(value) }}})
}

// ProtocolIdCodec binds MAP-CommonDataTypes.ProtocolId.
func ProtocolIdCodec() ValueCodec[BERValue[ProtocolId]] {
	return integerValueCodec[ProtocolId]("MAP-CommonDataTypes.ProtocolId", "ProtocolId", []primitiveRule[ProtocolId]{{invalid: func(value ProtocolId) bool {
		return (int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4)
	}, description: "ENUMERATED {1, 2, 3, 4}", clause: "20", observed: func(value ProtocolId) any { return int64(value) }}}, true)
}

// ExtExternalSignalInfoCodec binds MAP-CommonDataTypes.Ext-ExternalSignalInfo.
func ExtExternalSignalInfoCodec() ValueCodec[ExtExternalSignalInfo] {
	return compositeValueCodec[ExtExternalSignalInfo, *ExtExternalSignalInfo]()
}

// ExtProtocolIdCodec binds MAP-CommonDataTypes.Ext-ProtocolId.
func ExtProtocolIdCodec() ValueCodec[BERValue[ExtProtocolId]] {
	return integerValueCodec[ExtProtocolId]("MAP-CommonDataTypes.Ext-ProtocolId", "Ext-ProtocolId", nil, true)
}

// AccessNetworkSignalInfoCodec binds MAP-CommonDataTypes.AccessNetworkSignalInfo.
func AccessNetworkSignalInfoCodec() ValueCodec[AccessNetworkSignalInfo] {
	return compositeValueCodec[AccessNetworkSignalInfo, *AccessNetworkSignalInfo]()
}

// LongSignalInfoCodec binds MAP-CommonDataTypes.LongSignalInfo.
func LongSignalInfoCodec() ValueCodec[BERValue[LongSignalInfo]] {
	return octetValueCodec[LongSignalInfo]("MAP-CommonDataTypes.LongSignalInfo", "LongSignalInfo", []primitiveRule[LongSignalInfo]{{invalid: func(value LongSignalInfo) bool { return !(len(value) >= 1 && len(value) <= 2560) }, description: "SIZE (1..2560)", clause: "51.5", length: func(value LongSignalInfo) int { return len(value) }}})
}

// AccessNetworkProtocolIdCodec binds MAP-CommonDataTypes.AccessNetworkProtocolId.
func AccessNetworkProtocolIdCodec() ValueCodec[BERValue[AccessNetworkProtocolId]] {
	return integerValueCodec[AccessNetworkProtocolId]("MAP-CommonDataTypes.AccessNetworkProtocolId", "AccessNetworkProtocolId", nil, true)
}

// AlertingPatternCodec binds MAP-CommonDataTypes.AlertingPattern.
func AlertingPatternCodec() ValueCodec[BERValue[AlertingPattern]] {
	return octetValueCodec[AlertingPattern]("MAP-CommonDataTypes.AlertingPattern", "AlertingPattern", []primitiveRule[AlertingPattern]{{invalid: func(value AlertingPattern) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value AlertingPattern) int { return len(value) }}})
}

// GSNAddressCodec binds MAP-CommonDataTypes.GSN-Address.
func GSNAddressCodec() ValueCodec[BERValue[GSNAddress]] {
	return octetValueCodec[GSNAddress]("MAP-CommonDataTypes.GSN-Address", "GSN-Address", []primitiveRule[GSNAddress]{{invalid: func(value GSNAddress) bool { return !(len(value) >= 5 && len(value) <= 17) }, description: "SIZE (5..17)", clause: "51.5", length: func(value GSNAddress) int { return len(value) }}})
}

// TimeCodec binds MAP-CommonDataTypes.Time.
func TimeCodec() ValueCodec[BERValue[Time]] {
	return octetValueCodec[Time]("MAP-CommonDataTypes.Time", "Time", []primitiveRule[Time]{{invalid: func(value Time) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value Time) int { return len(value) }}})
}

// IMSICodec binds MAP-CommonDataTypes.IMSI.
func IMSICodec() ValueCodec[BERValue[IMSI]] {
	return pointerValueCodec(UnmarshalBERIMSI, MarshalBERIMSI, MarshalDERIMSI)
}

// IdentityCodec binds MAP-CommonDataTypes.Identity.
func IdentityCodec() ValueCodec[Identity] {
	return compositeValueCodec[Identity, *Identity]()
}

// IMSIWithLMSICodec binds MAP-CommonDataTypes.IMSI-WithLMSI.
func IMSIWithLMSICodec() ValueCodec[IMSIWithLMSI] {
	return compositeValueCodec[IMSIWithLMSI, *IMSIWithLMSI]()
}

// ASCICallReferenceCodec binds MAP-CommonDataTypes.ASCI-CallReference.
func ASCICallReferenceCodec() ValueCodec[BERValue[ASCICallReference]] {
	return pointerValueCodec(UnmarshalBERASCICallReference, MarshalBERASCICallReference, MarshalDERASCICallReference)
}

// TMSICodec binds MAP-CommonDataTypes.TMSI.
func TMSICodec() ValueCodec[BERValue[TMSI]] {
	return octetValueCodec[TMSI]("MAP-CommonDataTypes.TMSI", "TMSI", []primitiveRule[TMSI]{{invalid: func(value TMSI) bool { return !(len(value) >= 1 && len(value) <= 4) }, description: "SIZE (1..4)", clause: "51.5", length: func(value TMSI) int { return len(value) }}})
}

// SubscriberIdCodec binds MAP-CommonDataTypes.SubscriberId.
func SubscriberIdCodec() ValueCodec[SubscriberId] {
	return compositeValueCodec[SubscriberId, *SubscriberId]()
}

// IMEICodec binds MAP-CommonDataTypes.IMEI.
func IMEICodec() ValueCodec[BERValue[IMEI]] {
	return pointerValueCodec(UnmarshalBERIMEI, MarshalBERIMEI, MarshalDERIMEI)
}

// HLRIdCodec binds MAP-CommonDataTypes.HLR-Id.
func HLRIdCodec() ValueCodec[BERValue[HLRId]] {
	return pointerValueCodec(UnmarshalBERHLRId, MarshalBERHLRId, MarshalDERHLRId)
}

// HLRListCodec binds MAP-CommonDataTypes.HLR-List.
func HLRListCodec() ValueCodec[HLRList] {
	return pointerValueCodec(UnmarshalBERHLRList, MarshalBERHLRList, MarshalDERHLRList)
}

// LMSICodec binds MAP-CommonDataTypes.LMSI.
func LMSICodec() ValueCodec[BERValue[LMSI]] {
	return octetValueCodec[LMSI]("MAP-CommonDataTypes.LMSI", "LMSI", []primitiveRule[LMSI]{{invalid: func(value LMSI) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value LMSI) int { return len(value) }}})
}

// GlobalCellIdCodec binds MAP-CommonDataTypes.GlobalCellId.
func GlobalCellIdCodec() ValueCodec[BERValue[GlobalCellId]] {
	return octetValueCodec[GlobalCellId]("MAP-CommonDataTypes.GlobalCellId", "GlobalCellId", []primitiveRule[GlobalCellId]{{invalid: func(value GlobalCellId) bool { return !(len(value) >= 5 && len(value) <= 7) }, description: "SIZE (5..7)", clause: "51.5", length: func(value GlobalCellId) int { return len(value) }}})
}

// NetworkResourceCodec binds MAP-CommonDataTypes.NetworkResource.
func NetworkResourceCodec() ValueCodec[BERValue[NetworkResource]] {
	return integerValueCodec[NetworkResource]("MAP-CommonDataTypes.NetworkResource", "NetworkResource", []primitiveRule[NetworkResource]{{invalid: func(value NetworkResource) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", clause: "20", observed: func(value NetworkResource) any { return int64(value) }}}, true)
}

// AdditionalNetworkResourceCodec binds MAP-CommonDataTypes.AdditionalNetworkResource.
func AdditionalNetworkResourceCodec() ValueCodec[BERValue[AdditionalNetworkResource]] {
	return integerValueCodec[AdditionalNetworkResource]("MAP-CommonDataTypes.AdditionalNetworkResource", "AdditionalNetworkResource", nil, true)
}

// NAEAPreferredCICodec binds MAP-CommonDataTypes.NAEA-PreferredCI.
func NAEAPreferredCICodec() ValueCodec[NAEAPreferredCI] {
	return compositeValueCodec[NAEAPreferredCI, *NAEAPreferredCI]()
}

// NAEACICCodec binds MAP-CommonDataTypes.NAEA-CIC.
func NAEACICCodec() ValueCodec[BERValue[NAEACIC]] {
	return octetValueCodec[NAEACIC]("MAP-CommonDataTypes.NAEA-CIC", "NAEA-CIC", []primitiveRule[NAEACIC]{{invalid: func(value NAEACIC) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value NAEACIC) int { return len(value) }}})
}

// SubscriberIdentityCodec binds MAP-CommonDataTypes.SubscriberIdentity.
func SubscriberIdentityCodec() ValueCodec[SubscriberIdentity] {
	return compositeValueCodec[SubscriberIdentity, *SubscriberIdentity]()
}

// LCSClientExternalIDCodec binds MAP-CommonDataTypes.LCSClientExternalID.
func LCSClientExternalIDCodec() ValueCodec[LCSClientExternalID] {
	return compositeValueCodec[LCSClientExternalID, *LCSClientExternalID]()
}

// LCSClientInternalIDCodec binds MAP-CommonDataTypes.LCSClientInternalID.
func LCSClientInternalIDCodec() ValueCodec[BERValue[LCSClientInternalID]] {
	return integerValueCodec[LCSClientInternalID]("MAP-CommonDataTypes.LCSClientInternalID", "LCSClientInternalID", nil, true)
}

// LCSServiceTypeIDCodec binds MAP-CommonDataTypes.LCSServiceTypeID.
func LCSServiceTypeIDCodec() ValueCodec[BERValue[LCSServiceTypeID]] {
	return integerValueCodec[LCSServiceTypeID]("MAP-CommonDataTypes.LCSServiceTypeID", "LCSServiceTypeID", []primitiveRule[LCSServiceTypeID]{{invalid: func(value LCSServiceTypeID) bool { return !(int64(value) >= 0 && int64(value) <= 127) }, description: "(0..127)", clause: "51.4", observed: func(value LCSServiceTypeID) any { return int64(value) }}}, false)
}

// PLMNIdCodec binds MAP-CommonDataTypes.PLMN-Id.
func PLMNIdCodec() ValueCodec[BERValue[PLMNId]] {
	return octetValueCodec[PLMNId]("MAP-CommonDataTypes.PLMN-Id", "PLMN-Id", []primitiveRule[PLMNId]{{invalid: func(value PLMNId) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value PLMNId) int { return len(value) }}})
}

// EUTRANCGICodec binds MAP-CommonDataTypes.E-UTRAN-CGI.
func EUTRANCGICodec() ValueCodec[BERValue[EUTRANCGI]] {
	return octetValueCodec[EUTRANCGI]("MAP-CommonDataTypes.E-UTRAN-CGI", "E-UTRAN-CGI", []primitiveRule[EUTRANCGI]{{invalid: func(value EUTRANCGI) bool { return !(len(value) == 7) }, description: "SIZE (7)", clause: "51.5", length: func(value EUTRANCGI) int { return len(value) }}})
}

// NRCGICodec binds MAP-CommonDataTypes.NR-CGI.
func NRCGICodec() ValueCodec[BERValue[NRCGI]] {
	return octetValueCodec[NRCGI]("MAP-CommonDataTypes.NR-CGI", "NR-CGI", []primitiveRule[NRCGI]{{invalid: func(value NRCGI) bool { return !(len(value) == 8) }, description: "SIZE (8)", clause: "51.5", length: func(value NRCGI) int { return len(value) }}})
}

// TAIdCodec binds MAP-CommonDataTypes.TA-Id.
func TAIdCodec() ValueCodec[BERValue[TAId]] {
	return octetValueCodec[TAId]("MAP-CommonDataTypes.TA-Id", "TA-Id", []primitiveRule[TAId]{{invalid: func(value TAId) bool { return !(len(value) == 5) }, description: "SIZE (5)", clause: "51.5", length: func(value TAId) int { return len(value) }}})
}

// NRTAIdCodec binds MAP-CommonDataTypes.NR-TA-Id.
func NRTAIdCodec() ValueCodec[BERValue[NRTAId]] {
	return octetValueCodec[NRTAId]("MAP-CommonDataTypes.NR-TA-Id", "NR-TA-Id", []primitiveRule[NRTAId]{{invalid: func(value NRTAId) bool { return !(len(value) == 6) }, description: "SIZE (6)", clause: "51.5", length: func(value NRTAId) int { return len(value) }}})
}

// RAIdentityCodec binds MAP-CommonDataTypes.RAIdentity.
func RAIdentityCodec() ValueCodec[BERValue[RAIdentity]] {
	return octetValueCodec[RAIdentity]("MAP-CommonDataTypes.RAIdentity", "RAIdentity", []primitiveRule[RAIdentity]{{invalid: func(value RAIdentity) bool { return !(len(value) == 6) }, description: "SIZE (6)", clause: "51.5", length: func(value RAIdentity) int { return len(value) }}})
}

// NetworkNodeDiameterAddressCodec binds MAP-CommonDataTypes.NetworkNodeDiameterAddress.
func NetworkNodeDiameterAddressCodec() ValueCodec[NetworkNodeDiameterAddress] {
	return compositeValueCodec[NetworkNodeDiameterAddress, *NetworkNodeDiameterAddress]()
}

// CellGlobalIdOrServiceAreaIdOrLAICodec binds MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdOrLAI.
func CellGlobalIdOrServiceAreaIdOrLAICodec() ValueCodec[CellGlobalIdOrServiceAreaIdOrLAI] {
	return compositeValueCodec[CellGlobalIdOrServiceAreaIdOrLAI, *CellGlobalIdOrServiceAreaIdOrLAI]()
}

// CellGlobalIdOrServiceAreaIdFixedLengthCodec binds MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdFixedLength.
func CellGlobalIdOrServiceAreaIdFixedLengthCodec() ValueCodec[BERValue[CellGlobalIdOrServiceAreaIdFixedLength]] {
	return octetValueCodec[CellGlobalIdOrServiceAreaIdFixedLength]("MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdFixedLength", "CellGlobalIdOrServiceAreaIdFixedLength", []primitiveRule[CellGlobalIdOrServiceAreaIdFixedLength]{{invalid: func(value CellGlobalIdOrServiceAreaIdFixedLength) bool { return !(len(value) == 7) }, description: "SIZE (7)", clause: "51.5", length: func(value CellGlobalIdOrServiceAreaIdFixedLength) int { return len(value) }}})
}

// LAIFixedLengthCodec binds MAP-CommonDataTypes.LAIFixedLength.
func LAIFixedLengthCodec() ValueCodec[BERValue[LAIFixedLength]] {
	return octetValueCodec[LAIFixedLength]("MAP-CommonDataTypes.LAIFixedLength", "LAIFixedLength", []primitiveRule[LAIFixedLength]{{invalid: func(value LAIFixedLength) bool { return !(len(value) == 5) }, description: "SIZE (5)", clause: "51.5", length: func(value LAIFixedLength) int { return len(value) }}})
}

// BasicServiceCodeCodec binds MAP-CommonDataTypes.BasicServiceCode.
func BasicServiceCodeCodec() ValueCodec[BasicServiceCode] {
	return compositeValueCodec[BasicServiceCode, *BasicServiceCode]()
}

// ExtBasicServiceCodeCodec binds MAP-CommonDataTypes.Ext-BasicServiceCode.
func ExtBasicServiceCodeCodec() ValueCodec[ExtBasicServiceCode] {
	return compositeValueCodec[ExtBasicServiceCode, *ExtBasicServiceCode]()
}

// EMLPPInfoCodec binds MAP-CommonDataTypes.EMLPP-Info.
func EMLPPInfoCodec() ValueCodec[EMLPPInfo] {
	return compositeValueCodec[EMLPPInfo, *EMLPPInfo]()
}

// EMLPPPriorityCodec binds MAP-CommonDataTypes.EMLPP-Priority.
func EMLPPPriorityCodec() ValueCodec[BERValue[EMLPPPriority]] {
	return integerValueCodec[EMLPPPriority]("MAP-CommonDataTypes.EMLPP-Priority", "EMLPP-Priority", []primitiveRule[EMLPPPriority]{{invalid: func(value EMLPPPriority) bool { return !(int64(value) >= 0 && int64(value) <= 15) }, description: "(0..15)", clause: "51.4", observed: func(value EMLPPPriority) any { return int64(value) }}}, false)
}

// MCSSInfoCodec binds MAP-CommonDataTypes.MC-SS-Info.
func MCSSInfoCodec() ValueCodec[MCSSInfo] {
	return compositeValueCodec[MCSSInfo, *MCSSInfo]()
}

// MaxMCBearersCodec binds MAP-CommonDataTypes.MaxMC-Bearers.
func MaxMCBearersCodec() ValueCodec[BERValue[MaxMCBearers]] {
	return integerValueCodec[MaxMCBearers]("MAP-CommonDataTypes.MaxMC-Bearers", "MaxMC-Bearers", []primitiveRule[MaxMCBearers]{{invalid: func(value MaxMCBearers) bool { return !(int64(value) >= 2 && int64(value) <= 7) }, description: "(2..7)", clause: "51.4", observed: func(value MaxMCBearers) any { return int64(value) }}}, false)
}

// MCBearersCodec binds MAP-CommonDataTypes.MC-Bearers.
func MCBearersCodec() ValueCodec[BERValue[MCBearers]] {
	return integerValueCodec[MCBearers]("MAP-CommonDataTypes.MC-Bearers", "MC-Bearers", []primitiveRule[MCBearers]{{invalid: func(value MCBearers) bool { return !(int64(value) >= 1 && int64(value) <= 7) }, description: "(1..7)", clause: "51.4", observed: func(value MCBearers) any { return int64(value) }}}, false)
}

// ExtSSStatusCodec binds MAP-CommonDataTypes.Ext-SS-Status.
func ExtSSStatusCodec() ValueCodec[BERValue[ExtSSStatus]] {
	return octetValueCodec[ExtSSStatus]("MAP-CommonDataTypes.Ext-SS-Status", "Ext-SS-Status", []primitiveRule[ExtSSStatus]{{invalid: func(value ExtSSStatus) bool { return !(len(value) >= 1 && len(value) <= 5) }, description: "SIZE (1..5)", clause: "51.5", length: func(value ExtSSStatus) int { return len(value) }}})
}

// AgeOfLocationInformationCodec binds MAP-CommonDataTypes.AgeOfLocationInformation.
func AgeOfLocationInformationCodec() ValueCodec[BERValue[AgeOfLocationInformation]] {
	return integerValueCodec[AgeOfLocationInformation]("MAP-CommonDataTypes.AgeOfLocationInformation", "AgeOfLocationInformation", []primitiveRule[AgeOfLocationInformation]{{invalid: func(value AgeOfLocationInformation) bool { return !(int64(value) >= 0 && int64(value) <= 32767) }, description: "(0..32767)", clause: "51.4", observed: func(value AgeOfLocationInformation) any { return int64(value) }}}, false)
}

// RegisterSSArgCodec binds MAP-SS-DataTypes.RegisterSS-Arg.
func RegisterSSArgCodec() ValueCodec[RegisterSSArg] {
	return compositeValueCodec[RegisterSSArg, *RegisterSSArg]()
}

// NoReplyConditionTimeCodec binds MAP-SS-DataTypes.NoReplyConditionTime.
func NoReplyConditionTimeCodec() ValueCodec[BERValue[NoReplyConditionTime]] {
	return integerValueCodec[NoReplyConditionTime]("MAP-SS-DataTypes.NoReplyConditionTime", "NoReplyConditionTime", []primitiveRule[NoReplyConditionTime]{{invalid: func(value NoReplyConditionTime) bool { return !(int64(value) >= 5 && int64(value) <= 30) }, description: "(5..30)", clause: "51.4", observed: func(value NoReplyConditionTime) any { return int64(value) }}}, false)
}

// SSInfoCodec binds MAP-SS-DataTypes.SS-Info.
func SSInfoCodec() ValueCodec[SSInfo] {
	return compositeValueCodec[SSInfo, *SSInfo]()
}

// ForwardingInfoCodec binds MAP-SS-DataTypes.ForwardingInfo.
func ForwardingInfoCodec() ValueCodec[ForwardingInfo] {
	return compositeValueCodec[ForwardingInfo, *ForwardingInfo]()
}

// ForwardingFeatureListCodec binds MAP-SS-DataTypes.ForwardingFeatureList.
func ForwardingFeatureListCodec() ValueCodec[ForwardingFeatureList] {
	return pointerValueCodec(UnmarshalBERForwardingFeatureList, MarshalBERForwardingFeatureList, MarshalDERForwardingFeatureList)
}

// ForwardingFeatureCodec binds MAP-SS-DataTypes.ForwardingFeature.
func ForwardingFeatureCodec() ValueCodec[ForwardingFeature] {
	return compositeValueCodec[ForwardingFeature, *ForwardingFeature]()
}

// SSStatusCodec binds MAP-SS-DataTypes.SS-Status.
func SSStatusCodec() ValueCodec[BERValue[SSStatus]] {
	return pointerValueCodec(UnmarshalBERSSStatus, MarshalBERSSStatus, MarshalDERSSStatus)
}

// ForwardingOptionsCodec binds MAP-SS-DataTypes.ForwardingOptions.
func ForwardingOptionsCodec() ValueCodec[BERValue[ForwardingOptions]] {
	return octetValueCodec[ForwardingOptions]("MAP-SS-DataTypes.ForwardingOptions", "ForwardingOptions", []primitiveRule[ForwardingOptions]{{invalid: func(value ForwardingOptions) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value ForwardingOptions) int { return len(value) }}})
}

// CallBarringInfoCodec binds MAP-SS-DataTypes.CallBarringInfo.
func CallBarringInfoCodec() ValueCodec[CallBarringInfo] {
	return compositeValueCodec[CallBarringInfo, *CallBarringInfo]()
}

// CallBarringFeatureListCodec binds MAP-SS-DataTypes.CallBarringFeatureList.
func CallBarringFeatureListCodec() ValueCodec[CallBarringFeatureList] {
	return pointerValueCodec(UnmarshalBERCallBarringFeatureList, MarshalBERCallBarringFeatureList, MarshalDERCallBarringFeatureList)
}

// CallBarringFeatureCodec binds MAP-SS-DataTypes.CallBarringFeature.
func CallBarringFeatureCodec() ValueCodec[CallBarringFeature] {
	return compositeValueCodec[CallBarringFeature, *CallBarringFeature]()
}

// SSDataCodec binds MAP-SS-DataTypes.SS-Data.
func SSDataCodec() ValueCodec[SSData] {
	return compositeValueCodec[SSData, *SSData]()
}

// SSSubscriptionOptionCodec binds MAP-SS-DataTypes.SS-SubscriptionOption.
func SSSubscriptionOptionCodec() ValueCodec[SSSubscriptionOption] {
	return compositeValueCodec[SSSubscriptionOption, *SSSubscriptionOption]()
}

// CliRestrictionOptionCodec binds MAP-SS-DataTypes.CliRestrictionOption.
func CliRestrictionOptionCodec() ValueCodec[BERValue[CliRestrictionOption]] {
	return integerValueCodec[CliRestrictionOption]("MAP-SS-DataTypes.CliRestrictionOption", "CliRestrictionOption", []primitiveRule[CliRestrictionOption]{{invalid: func(value CliRestrictionOption) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value CliRestrictionOption) any { return int64(value) }}}, true)
}

// OverrideCategoryCodec binds MAP-SS-DataTypes.OverrideCategory.
func OverrideCategoryCodec() ValueCodec[BERValue[OverrideCategory]] {
	return integerValueCodec[OverrideCategory]("MAP-SS-DataTypes.OverrideCategory", "OverrideCategory", []primitiveRule[OverrideCategory]{{invalid: func(value OverrideCategory) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value OverrideCategory) any { return int64(value) }}}, true)
}

// SSForBSCodeCodec binds MAP-SS-DataTypes.SS-ForBS-Code.
func SSForBSCodeCodec() ValueCodec[SSForBSCode] {
	return compositeValueCodec[SSForBSCode, *SSForBSCode]()
}

// GenericServiceInfoCodec binds MAP-SS-DataTypes.GenericServiceInfo.
func GenericServiceInfoCodec() ValueCodec[GenericServiceInfo] {
	return compositeValueCodec[GenericServiceInfo, *GenericServiceInfo]()
}

// CCBSFeatureListCodec binds MAP-SS-DataTypes.CCBS-FeatureList.
func CCBSFeatureListCodec() ValueCodec[CCBSFeatureList] {
	return pointerValueCodec(UnmarshalBERCCBSFeatureList, MarshalBERCCBSFeatureList, MarshalDERCCBSFeatureList)
}

// CCBSFeatureCodec binds MAP-SS-DataTypes.CCBS-Feature.
func CCBSFeatureCodec() ValueCodec[CCBSFeature] {
	return compositeValueCodec[CCBSFeature, *CCBSFeature]()
}

// CCBSIndexCodec binds MAP-SS-DataTypes.CCBS-Index.
func CCBSIndexCodec() ValueCodec[BERValue[CCBSIndex]] {
	return integerValueCodec[CCBSIndex]("MAP-SS-DataTypes.CCBS-Index", "CCBS-Index", []primitiveRule[CCBSIndex]{{invalid: func(value CCBSIndex) bool { return !(int64(value) >= 1 && int64(value) <= 5) }, description: "(1..5)", clause: "51.4", observed: func(value CCBSIndex) any { return int64(value) }}}, false)
}

// InterrogateSSResCodec binds MAP-SS-DataTypes.InterrogateSS-Res.
func InterrogateSSResCodec() ValueCodec[InterrogateSSRes] {
	return compositeValueCodec[InterrogateSSRes, *InterrogateSSRes]()
}

// USSDArgCodec binds MAP-SS-DataTypes.USSD-Arg.
func USSDArgCodec() ValueCodec[USSDArg] {
	return compositeValueCodec[USSDArg, *USSDArg]()
}

// USSDResCodec binds MAP-SS-DataTypes.USSD-Res.
func USSDResCodec() ValueCodec[USSDRes] {
	return compositeValueCodec[USSDRes, *USSDRes]()
}

// USSDDataCodingSchemeCodec binds MAP-SS-DataTypes.USSD-DataCodingScheme.
func USSDDataCodingSchemeCodec() ValueCodec[BERValue[USSDDataCodingScheme]] {
	return octetValueCodec[USSDDataCodingScheme]("MAP-SS-DataTypes.USSD-DataCodingScheme", "USSD-DataCodingScheme", []primitiveRule[USSDDataCodingScheme]{{invalid: func(value USSDDataCodingScheme) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value USSDDataCodingScheme) int { return len(value) }}})
}

// USSDStringCodec binds MAP-SS-DataTypes.USSD-String.
func USSDStringCodec() ValueCodec[BERValue[USSDString]] {
	return octetValueCodec[USSDString]("MAP-SS-DataTypes.USSD-String", "USSD-String", []primitiveRule[USSDString]{{invalid: func(value USSDString) bool { return !(len(value) >= 1 && len(value) <= 160) }, description: "SIZE (1..160)", clause: "51.5", length: func(value USSDString) int { return len(value) }}})
}

// PasswordCodec binds MAP-SS-DataTypes.Password.
func PasswordCodec() ValueCodec[BERValue[Password]] {
	return pointerValueCodec(UnmarshalBERPassword, MarshalBERPassword, MarshalDERPassword)
}

// GuidanceInfoCodec binds MAP-SS-DataTypes.GuidanceInfo.
func GuidanceInfoCodec() ValueCodec[BERValue[GuidanceInfo]] {
	return pointerValueCodec(UnmarshalBERGuidanceInfo, MarshalBERGuidanceInfo, MarshalDERGuidanceInfo)
}

// SSListCodec binds MAP-SS-DataTypes.SS-List.
func SSListCodec() ValueCodec[SSList] {
	return pointerValueCodec(UnmarshalBERSSList, MarshalBERSSList, MarshalDERSSList)
}

// SSInfoListCodec binds MAP-SS-DataTypes.SS-InfoList.
func SSInfoListCodec() ValueCodec[SSInfoList] {
	return pointerValueCodec(UnmarshalBERSSInfoList, MarshalBERSSInfoList, MarshalDERSSInfoList)
}

// BasicServiceGroupListCodec binds MAP-SS-DataTypes.BasicServiceGroupList.
func BasicServiceGroupListCodec() ValueCodec[BasicServiceGroupList] {
	return pointerValueCodec(UnmarshalBERBasicServiceGroupList, MarshalBERBasicServiceGroupList, MarshalDERBasicServiceGroupList)
}

// SSInvocationNotificationArgCodec binds MAP-SS-DataTypes.SS-InvocationNotificationArg.
func SSInvocationNotificationArgCodec() ValueCodec[SSInvocationNotificationArg] {
	return compositeValueCodec[SSInvocationNotificationArg, *SSInvocationNotificationArg]()
}

// CCBSRequestStateCodec binds MAP-SS-DataTypes.CCBS-RequestState.
func CCBSRequestStateCodec() ValueCodec[BERValue[CCBSRequestState]] {
	return integerValueCodec[CCBSRequestState]("MAP-SS-DataTypes.CCBS-RequestState", "CCBS-RequestState", []primitiveRule[CCBSRequestState]{{invalid: func(value CCBSRequestState) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value CCBSRequestState) any { return int64(value) }}}, true)
}

// SSInvocationNotificationResCodec binds MAP-SS-DataTypes.SS-InvocationNotificationRes.
func SSInvocationNotificationResCodec() ValueCodec[SSInvocationNotificationRes] {
	return compositeValueCodec[SSInvocationNotificationRes, *SSInvocationNotificationRes]()
}

// SSEventSpecificationCodec binds MAP-SS-DataTypes.SS-EventSpecification.
func SSEventSpecificationCodec() ValueCodec[SSEventSpecification] {
	return pointerValueCodec(UnmarshalBERSSEventSpecification, MarshalBERSSEventSpecification, MarshalDERSSEventSpecification)
}

// RegisterCCEntryArgCodec binds MAP-SS-DataTypes.RegisterCC-EntryArg.
func RegisterCCEntryArgCodec() ValueCodec[RegisterCCEntryArg] {
	return compositeValueCodec[RegisterCCEntryArg, *RegisterCCEntryArg]()
}

// CCBSDataCodec binds MAP-SS-DataTypes.CCBS-Data.
func CCBSDataCodec() ValueCodec[CCBSData] {
	return compositeValueCodec[CCBSData, *CCBSData]()
}

// ServiceIndicatorCodec binds MAP-SS-DataTypes.ServiceIndicator.
func ServiceIndicatorCodec() ValueCodec[BERValue[ServiceIndicator]] {
	return bitValueCodec("MAP-SS-DataTypes.ServiceIndicator", "ServiceIndicator", []primitiveRule[ServiceIndicator]{{invalid: func(value ServiceIndicator) bool { return !(value.BitLength >= 2 && value.BitLength <= 32) }, description: "SIZE (2..32)", clause: "51.5", length: func(value ServiceIndicator) int { return value.BitLength }, encodedLength: func(value ServiceIndicator) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 32}}})
}

// RegisterCCEntryResCodec binds MAP-SS-DataTypes.RegisterCC-EntryRes.
func RegisterCCEntryResCodec() ValueCodec[RegisterCCEntryRes] {
	return compositeValueCodec[RegisterCCEntryRes, *RegisterCCEntryRes]()
}

// EraseCCEntryArgCodec binds MAP-SS-DataTypes.EraseCC-EntryArg.
func EraseCCEntryArgCodec() ValueCodec[EraseCCEntryArg] {
	return compositeValueCodec[EraseCCEntryArg, *EraseCCEntryArg]()
}

// EraseCCEntryResCodec binds MAP-SS-DataTypes.EraseCC-EntryRes.
func EraseCCEntryResCodec() ValueCodec[EraseCCEntryRes] {
	return compositeValueCodec[EraseCCEntryRes, *EraseCCEntryRes]()
}

// RoamingNotAllowedParamCodec binds MAP-ER-DataTypes.RoamingNotAllowedParam.
func RoamingNotAllowedParamCodec() ValueCodec[RoamingNotAllowedParam] {
	return compositeValueCodec[RoamingNotAllowedParam, *RoamingNotAllowedParam]()
}

// AdditionalRoamingNotAllowedCauseCodec binds MAP-ER-DataTypes.AdditionalRoamingNotAllowedCause.
func AdditionalRoamingNotAllowedCauseCodec() ValueCodec[BERValue[AdditionalRoamingNotAllowedCause]] {
	return integerValueCodec[AdditionalRoamingNotAllowedCause]("MAP-ER-DataTypes.AdditionalRoamingNotAllowedCause", "AdditionalRoamingNotAllowedCause", nil, true)
}

// RoamingNotAllowedCauseCodec binds MAP-ER-DataTypes.RoamingNotAllowedCause.
func RoamingNotAllowedCauseCodec() ValueCodec[BERValue[RoamingNotAllowedCause]] {
	return integerValueCodec[RoamingNotAllowedCause]("MAP-ER-DataTypes.RoamingNotAllowedCause", "RoamingNotAllowedCause", []primitiveRule[RoamingNotAllowedCause]{{invalid: func(value RoamingNotAllowedCause) bool { return (int64(value) != 0 && int64(value) != 3) }, description: "ENUMERATED {0, 3}", clause: "20", observed: func(value RoamingNotAllowedCause) any { return int64(value) }}}, true)
}

// CallBarredParamCodec binds MAP-ER-DataTypes.CallBarredParam.
func CallBarredParamCodec() ValueCodec[CallBarredParam] {
	return compositeValueCodec[CallBarredParam, *CallBarredParam]()
}

// CallBarringCauseCodec binds MAP-ER-DataTypes.CallBarringCause.
func CallBarringCauseCodec() ValueCodec[BERValue[CallBarringCause]] {
	return integerValueCodec[CallBarringCause]("MAP-ER-DataTypes.CallBarringCause", "CallBarringCause", []primitiveRule[CallBarringCause]{{invalid: func(value CallBarringCause) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value CallBarringCause) any { return int64(value) }}}, true)
}

// ExtensibleCallBarredParamCodec binds MAP-ER-DataTypes.ExtensibleCallBarredParam.
func ExtensibleCallBarredParamCodec() ValueCodec[ExtensibleCallBarredParam] {
	return compositeValueCodec[ExtensibleCallBarredParam, *ExtensibleCallBarredParam]()
}

// CUGRejectParamCodec binds MAP-ER-DataTypes.CUG-RejectParam.
func CUGRejectParamCodec() ValueCodec[CUGRejectParam] {
	return compositeValueCodec[CUGRejectParam, *CUGRejectParam]()
}

// CUGRejectCauseCodec binds MAP-ER-DataTypes.CUG-RejectCause.
func CUGRejectCauseCodec() ValueCodec[BERValue[CUGRejectCause]] {
	return integerValueCodec[CUGRejectCause]("MAP-ER-DataTypes.CUG-RejectCause", "CUG-RejectCause", []primitiveRule[CUGRejectCause]{{invalid: func(value CUGRejectCause) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 5 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 5, 7}", clause: "20", observed: func(value CUGRejectCause) any { return int64(value) }}}, true)
}

// SSIncompatibilityCauseCodec binds MAP-ER-DataTypes.SS-IncompatibilityCause.
func SSIncompatibilityCauseCodec() ValueCodec[SSIncompatibilityCause] {
	return compositeValueCodec[SSIncompatibilityCause, *SSIncompatibilityCause]()
}

// PWRegistrationFailureCauseCodec binds MAP-ER-DataTypes.PW-RegistrationFailureCause.
func PWRegistrationFailureCauseCodec() ValueCodec[BERValue[PWRegistrationFailureCause]] {
	return pointerValueCodec(UnmarshalBERPWRegistrationFailureCause, MarshalBERPWRegistrationFailureCause, MarshalDERPWRegistrationFailureCause)
}

// SMEnumeratedDeliveryFailureCauseCodec binds MAP-ER-DataTypes.SM-EnumeratedDeliveryFailureCause.
func SMEnumeratedDeliveryFailureCauseCodec() ValueCodec[BERValue[SMEnumeratedDeliveryFailureCause]] {
	return integerValueCodec[SMEnumeratedDeliveryFailureCause]("MAP-ER-DataTypes.SM-EnumeratedDeliveryFailureCause", "SM-EnumeratedDeliveryFailureCause", []primitiveRule[SMEnumeratedDeliveryFailureCause]{{invalid: func(value SMEnumeratedDeliveryFailureCause) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value SMEnumeratedDeliveryFailureCause) any { return int64(value) }}}, true)
}

// SMDeliveryFailureCauseCodec binds MAP-ER-DataTypes.SM-DeliveryFailureCause.
func SMDeliveryFailureCauseCodec() ValueCodec[SMDeliveryFailureCause] {
	return compositeValueCodec[SMDeliveryFailureCause, *SMDeliveryFailureCause]()
}

// AbsentSubscriberSMParamCodec binds MAP-ER-DataTypes.AbsentSubscriberSM-Param.
func AbsentSubscriberSMParamCodec() ValueCodec[AbsentSubscriberSMParam] {
	return compositeValueCodec[AbsentSubscriberSMParam, *AbsentSubscriberSMParam]()
}

// AbsentSubscriberDiagnosticSMCodec binds MAP-ER-DataTypes.AbsentSubscriberDiagnosticSM.
func AbsentSubscriberDiagnosticSMCodec() ValueCodec[BERValue[AbsentSubscriberDiagnosticSM]] {
	return integerValueCodec[AbsentSubscriberDiagnosticSM]("MAP-ER-DataTypes.AbsentSubscriberDiagnosticSM", "AbsentSubscriberDiagnosticSM", []primitiveRule[AbsentSubscriberDiagnosticSM]{{invalid: func(value AbsentSubscriberDiagnosticSM) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "51.4", observed: func(value AbsentSubscriberDiagnosticSM) any { return int64(value) }}}, false)
}

// SystemFailureParamCodec binds MAP-ER-DataTypes.SystemFailureParam.
func SystemFailureParamCodec() ValueCodec[SystemFailureParam] {
	return compositeValueCodec[SystemFailureParam, *SystemFailureParam]()
}

// ExtensibleSystemFailureParamCodec binds MAP-ER-DataTypes.ExtensibleSystemFailureParam.
func ExtensibleSystemFailureParamCodec() ValueCodec[ExtensibleSystemFailureParam] {
	return compositeValueCodec[ExtensibleSystemFailureParam, *ExtensibleSystemFailureParam]()
}

// FailureCauseParamCodec binds MAP-ER-DataTypes.FailureCauseParam.
func FailureCauseParamCodec() ValueCodec[BERValue[FailureCauseParam]] {
	return integerValueCodec[FailureCauseParam]("MAP-ER-DataTypes.FailureCauseParam", "FailureCauseParam", nil, true)
}

// DataMissingParamCodec binds MAP-ER-DataTypes.DataMissingParam.
func DataMissingParamCodec() ValueCodec[DataMissingParam] {
	return compositeValueCodec[DataMissingParam, *DataMissingParam]()
}

// UnexpectedDataParamCodec binds MAP-ER-DataTypes.UnexpectedDataParam.
func UnexpectedDataParamCodec() ValueCodec[UnexpectedDataParam] {
	return compositeValueCodec[UnexpectedDataParam, *UnexpectedDataParam]()
}

// FacilityNotSupParamCodec binds MAP-ER-DataTypes.FacilityNotSupParam.
func FacilityNotSupParamCodec() ValueCodec[FacilityNotSupParam] {
	return compositeValueCodec[FacilityNotSupParam, *FacilityNotSupParam]()
}

// ORNotAllowedParamCodec binds MAP-ER-DataTypes.OR-NotAllowedParam.
func ORNotAllowedParamCodec() ValueCodec[ORNotAllowedParam] {
	return compositeValueCodec[ORNotAllowedParam, *ORNotAllowedParam]()
}

// UnknownSubscriberParamCodec binds MAP-ER-DataTypes.UnknownSubscriberParam.
func UnknownSubscriberParamCodec() ValueCodec[UnknownSubscriberParam] {
	return compositeValueCodec[UnknownSubscriberParam, *UnknownSubscriberParam]()
}

// UnknownSubscriberDiagnosticCodec binds MAP-ER-DataTypes.UnknownSubscriberDiagnostic.
func UnknownSubscriberDiagnosticCodec() ValueCodec[BERValue[UnknownSubscriberDiagnostic]] {
	return integerValueCodec[UnknownSubscriberDiagnostic]("MAP-ER-DataTypes.UnknownSubscriberDiagnostic", "UnknownSubscriberDiagnostic", nil, true)
}

// NumberChangedParamCodec binds MAP-ER-DataTypes.NumberChangedParam.
func NumberChangedParamCodec() ValueCodec[NumberChangedParam] {
	return compositeValueCodec[NumberChangedParam, *NumberChangedParam]()
}

// UnidentifiedSubParamCodec binds MAP-ER-DataTypes.UnidentifiedSubParam.
func UnidentifiedSubParamCodec() ValueCodec[UnidentifiedSubParam] {
	return compositeValueCodec[UnidentifiedSubParam, *UnidentifiedSubParam]()
}

// IllegalSubscriberParamCodec binds MAP-ER-DataTypes.IllegalSubscriberParam.
func IllegalSubscriberParamCodec() ValueCodec[IllegalSubscriberParam] {
	return compositeValueCodec[IllegalSubscriberParam, *IllegalSubscriberParam]()
}

// IllegalEquipmentParamCodec binds MAP-ER-DataTypes.IllegalEquipmentParam.
func IllegalEquipmentParamCodec() ValueCodec[IllegalEquipmentParam] {
	return compositeValueCodec[IllegalEquipmentParam, *IllegalEquipmentParam]()
}

// BearerServNotProvParamCodec binds MAP-ER-DataTypes.BearerServNotProvParam.
func BearerServNotProvParamCodec() ValueCodec[BearerServNotProvParam] {
	return compositeValueCodec[BearerServNotProvParam, *BearerServNotProvParam]()
}

// TeleservNotProvParamCodec binds MAP-ER-DataTypes.TeleservNotProvParam.
func TeleservNotProvParamCodec() ValueCodec[TeleservNotProvParam] {
	return compositeValueCodec[TeleservNotProvParam, *TeleservNotProvParam]()
}

// TracingBufferFullParamCodec binds MAP-ER-DataTypes.TracingBufferFullParam.
func TracingBufferFullParamCodec() ValueCodec[TracingBufferFullParam] {
	return compositeValueCodec[TracingBufferFullParam, *TracingBufferFullParam]()
}

// NoRoamingNbParamCodec binds MAP-ER-DataTypes.NoRoamingNbParam.
func NoRoamingNbParamCodec() ValueCodec[NoRoamingNbParam] {
	return compositeValueCodec[NoRoamingNbParam, *NoRoamingNbParam]()
}

// AbsentSubscriberParamCodec binds MAP-ER-DataTypes.AbsentSubscriberParam.
func AbsentSubscriberParamCodec() ValueCodec[AbsentSubscriberParam] {
	return compositeValueCodec[AbsentSubscriberParam, *AbsentSubscriberParam]()
}

// AbsentSubscriberReasonCodec binds MAP-ER-DataTypes.AbsentSubscriberReason.
func AbsentSubscriberReasonCodec() ValueCodec[BERValue[AbsentSubscriberReason]] {
	return integerValueCodec[AbsentSubscriberReason]("MAP-ER-DataTypes.AbsentSubscriberReason", "AbsentSubscriberReason", nil, true)
}

// BusySubscriberParamCodec binds MAP-ER-DataTypes.BusySubscriberParam.
func BusySubscriberParamCodec() ValueCodec[BusySubscriberParam] {
	return compositeValueCodec[BusySubscriberParam, *BusySubscriberParam]()
}

// NoSubscriberReplyParamCodec binds MAP-ER-DataTypes.NoSubscriberReplyParam.
func NoSubscriberReplyParamCodec() ValueCodec[NoSubscriberReplyParam] {
	return compositeValueCodec[NoSubscriberReplyParam, *NoSubscriberReplyParam]()
}

// ForwardingViolationParamCodec binds MAP-ER-DataTypes.ForwardingViolationParam.
func ForwardingViolationParamCodec() ValueCodec[ForwardingViolationParam] {
	return compositeValueCodec[ForwardingViolationParam, *ForwardingViolationParam]()
}

// ForwardingFailedParamCodec binds MAP-ER-DataTypes.ForwardingFailedParam.
func ForwardingFailedParamCodec() ValueCodec[ForwardingFailedParam] {
	return compositeValueCodec[ForwardingFailedParam, *ForwardingFailedParam]()
}

// ATINotAllowedParamCodec binds MAP-ER-DataTypes.ATI-NotAllowedParam.
func ATINotAllowedParamCodec() ValueCodec[ATINotAllowedParam] {
	return compositeValueCodec[ATINotAllowedParam, *ATINotAllowedParam]()
}

// ATSINotAllowedParamCodec binds MAP-ER-DataTypes.ATSI-NotAllowedParam.
func ATSINotAllowedParamCodec() ValueCodec[ATSINotAllowedParam] {
	return compositeValueCodec[ATSINotAllowedParam, *ATSINotAllowedParam]()
}

// ATMNotAllowedParamCodec binds MAP-ER-DataTypes.ATM-NotAllowedParam.
func ATMNotAllowedParamCodec() ValueCodec[ATMNotAllowedParam] {
	return compositeValueCodec[ATMNotAllowedParam, *ATMNotAllowedParam]()
}

// IllegalSSOperationParamCodec binds MAP-ER-DataTypes.IllegalSS-OperationParam.
func IllegalSSOperationParamCodec() ValueCodec[IllegalSSOperationParam] {
	return compositeValueCodec[IllegalSSOperationParam, *IllegalSSOperationParam]()
}

// SSNotAvailableParamCodec binds MAP-ER-DataTypes.SS-NotAvailableParam.
func SSNotAvailableParamCodec() ValueCodec[SSNotAvailableParam] {
	return compositeValueCodec[SSNotAvailableParam, *SSNotAvailableParam]()
}

// SSSubscriptionViolationParamCodec binds MAP-ER-DataTypes.SS-SubscriptionViolationParam.
func SSSubscriptionViolationParamCodec() ValueCodec[SSSubscriptionViolationParam] {
	return compositeValueCodec[SSSubscriptionViolationParam, *SSSubscriptionViolationParam]()
}

// InformationNotAvailableParamCodec binds MAP-ER-DataTypes.InformationNotAvailableParam.
func InformationNotAvailableParamCodec() ValueCodec[InformationNotAvailableParam] {
	return compositeValueCodec[InformationNotAvailableParam, *InformationNotAvailableParam]()
}

// SubBusyForMTSMSParamCodec binds MAP-ER-DataTypes.SubBusyForMT-SMS-Param.
func SubBusyForMTSMSParamCodec() ValueCodec[SubBusyForMTSMSParam] {
	return compositeValueCodec[SubBusyForMTSMSParam, *SubBusyForMTSMSParam]()
}

// MessageWaitListFullParamCodec binds MAP-ER-DataTypes.MessageWaitListFullParam.
func MessageWaitListFullParamCodec() ValueCodec[MessageWaitListFullParam] {
	return compositeValueCodec[MessageWaitListFullParam, *MessageWaitListFullParam]()
}

// ResourceLimitationParamCodec binds MAP-ER-DataTypes.ResourceLimitationParam.
func ResourceLimitationParamCodec() ValueCodec[ResourceLimitationParam] {
	return compositeValueCodec[ResourceLimitationParam, *ResourceLimitationParam]()
}

// NoGroupCallNbParamCodec binds MAP-ER-DataTypes.NoGroupCallNbParam.
func NoGroupCallNbParamCodec() ValueCodec[NoGroupCallNbParam] {
	return compositeValueCodec[NoGroupCallNbParam, *NoGroupCallNbParam]()
}

// IncompatibleTerminalParamCodec binds MAP-ER-DataTypes.IncompatibleTerminalParam.
func IncompatibleTerminalParamCodec() ValueCodec[IncompatibleTerminalParam] {
	return compositeValueCodec[IncompatibleTerminalParam, *IncompatibleTerminalParam]()
}

// ShortTermDenialParamCodec binds MAP-ER-DataTypes.ShortTermDenialParam.
func ShortTermDenialParamCodec() ValueCodec[ShortTermDenialParam] {
	return compositeValueCodec[ShortTermDenialParam, *ShortTermDenialParam]()
}

// LongTermDenialParamCodec binds MAP-ER-DataTypes.LongTermDenialParam.
func LongTermDenialParamCodec() ValueCodec[LongTermDenialParam] {
	return compositeValueCodec[LongTermDenialParam, *LongTermDenialParam]()
}

// UnauthorizedRequestingNetworkParamCodec binds MAP-ER-DataTypes.UnauthorizedRequestingNetwork-Param.
func UnauthorizedRequestingNetworkParamCodec() ValueCodec[UnauthorizedRequestingNetworkParam] {
	return compositeValueCodec[UnauthorizedRequestingNetworkParam, *UnauthorizedRequestingNetworkParam]()
}

// UnauthorizedLCSClientParamCodec binds MAP-ER-DataTypes.UnauthorizedLCSClient-Param.
func UnauthorizedLCSClientParamCodec() ValueCodec[UnauthorizedLCSClientParam] {
	return compositeValueCodec[UnauthorizedLCSClientParam, *UnauthorizedLCSClientParam]()
}

// UnauthorizedLCSClientDiagnosticCodec binds MAP-ER-DataTypes.UnauthorizedLCSClient-Diagnostic.
func UnauthorizedLCSClientDiagnosticCodec() ValueCodec[BERValue[UnauthorizedLCSClientDiagnostic]] {
	return integerValueCodec[UnauthorizedLCSClientDiagnostic]("MAP-ER-DataTypes.UnauthorizedLCSClient-Diagnostic", "UnauthorizedLCSClient-Diagnostic", nil, true)
}

// PositionMethodFailureParamCodec binds MAP-ER-DataTypes.PositionMethodFailure-Param.
func PositionMethodFailureParamCodec() ValueCodec[PositionMethodFailureParam] {
	return compositeValueCodec[PositionMethodFailureParam, *PositionMethodFailureParam]()
}

// PositionMethodFailureDiagnosticCodec binds MAP-ER-DataTypes.PositionMethodFailure-Diagnostic.
func PositionMethodFailureDiagnosticCodec() ValueCodec[BERValue[PositionMethodFailureDiagnostic]] {
	return integerValueCodec[PositionMethodFailureDiagnostic]("MAP-ER-DataTypes.PositionMethodFailure-Diagnostic", "PositionMethodFailure-Diagnostic", nil, true)
}

// UnknownOrUnreachableLCSClientParamCodec binds MAP-ER-DataTypes.UnknownOrUnreachableLCSClient-Param.
func UnknownOrUnreachableLCSClientParamCodec() ValueCodec[UnknownOrUnreachableLCSClientParam] {
	return compositeValueCodec[UnknownOrUnreachableLCSClientParam, *UnknownOrUnreachableLCSClientParam]()
}

// MMEventNotSupportedParamCodec binds MAP-ER-DataTypes.MM-EventNotSupported-Param.
func MMEventNotSupportedParamCodec() ValueCodec[MMEventNotSupportedParam] {
	return compositeValueCodec[MMEventNotSupportedParam, *MMEventNotSupportedParam]()
}

// TargetCellOutsideGCAParamCodec binds MAP-ER-DataTypes.TargetCellOutsideGCA-Param.
func TargetCellOutsideGCAParamCodec() ValueCodec[TargetCellOutsideGCAParam] {
	return compositeValueCodec[TargetCellOutsideGCAParam, *TargetCellOutsideGCAParam]()
}

// OngoingGroupCallParamCodec binds MAP-ER-DataTypes.OngoingGroupCallParam.
func OngoingGroupCallParamCodec() ValueCodec[OngoingGroupCallParam] {
	return compositeValueCodec[OngoingGroupCallParam, *OngoingGroupCallParam]()
}

// ActivateTraceModeArgCodec binds MAP-OM-DataTypes.ActivateTraceModeArg.
func ActivateTraceModeArgCodec() ValueCodec[ActivateTraceModeArg] {
	return compositeValueCodec[ActivateTraceModeArg, *ActivateTraceModeArg]()
}

// MDTConfigurationCodec binds MAP-OM-DataTypes.MDT-Configuration.
func MDTConfigurationCodec() ValueCodec[MDTConfiguration] {
	return compositeValueCodec[MDTConfiguration, *MDTConfiguration]()
}

// MDTAllowedPLMNIdListCodec binds MAP-OM-DataTypes.MDT-Allowed-PLMNId-List.
func MDTAllowedPLMNIdListCodec() ValueCodec[MDTAllowedPLMNIdList] {
	return pointerValueCodec(UnmarshalBERMDTAllowedPLMNIdList, MarshalBERMDTAllowedPLMNIdList, MarshalDERMDTAllowedPLMNIdList)
}

// PeriodUMTSCodec binds MAP-OM-DataTypes.PeriodUMTS.
func PeriodUMTSCodec() ValueCodec[BERValue[PeriodUMTS]] {
	return integerValueCodec[PeriodUMTS]("MAP-OM-DataTypes.PeriodUMTS", "PeriodUMTS", []primitiveRule[PeriodUMTS]{{invalid: func(value PeriodUMTS) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7 && int64(value) != 8 && int64(value) != 9 && int64(value) != 10 && int64(value) != 11 && int64(value) != 12 && int64(value) != 13 && int64(value) != 14)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", clause: "20", observed: func(value PeriodUMTS) any { return int64(value) }}}, true)
}

// PeriodLTECodec binds MAP-OM-DataTypes.PeriodLTE.
func PeriodLTECodec() ValueCodec[BERValue[PeriodLTE]] {
	return integerValueCodec[PeriodLTE]("MAP-OM-DataTypes.PeriodLTE", "PeriodLTE", []primitiveRule[PeriodLTE]{{invalid: func(value PeriodLTE) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value PeriodLTE) any { return int64(value) }}}, true)
}

// PositioningMethodCodec binds MAP-OM-DataTypes.PositioningMethod.
func PositioningMethodCodec() ValueCodec[BERValue[PositioningMethod]] {
	return octetValueCodec[PositioningMethod]("MAP-OM-DataTypes.PositioningMethod", "PositioningMethod", []primitiveRule[PositioningMethod]{{invalid: func(value PositioningMethod) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value PositioningMethod) int { return len(value) }}})
}

// MeasurementQuantityCodec binds MAP-OM-DataTypes.MeasurementQuantity.
func MeasurementQuantityCodec() ValueCodec[BERValue[MeasurementQuantity]] {
	return octetValueCodec[MeasurementQuantity]("MAP-OM-DataTypes.MeasurementQuantity", "MeasurementQuantity", []primitiveRule[MeasurementQuantity]{{invalid: func(value MeasurementQuantity) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MeasurementQuantity) int { return len(value) }}})
}

// EventThreshold1FCodec binds MAP-OM-DataTypes.EventThreshold1F.
func EventThreshold1FCodec() ValueCodec[BERValue[EventThreshold1F]] {
	return integerValueCodec[EventThreshold1F]("MAP-OM-DataTypes.EventThreshold1F", "EventThreshold1F", []primitiveRule[EventThreshold1F]{{invalid: func(value EventThreshold1F) bool { return !(int64(value) >= -120 && int64(value) <= 165) }, description: "(-120..165)", clause: "51.4", observed: func(value EventThreshold1F) any { return int64(value) }}}, false)
}

// EventThreshold1ICodec binds MAP-OM-DataTypes.EventThreshold1I.
func EventThreshold1ICodec() ValueCodec[BERValue[EventThreshold1I]] {
	return integerValueCodec[EventThreshold1I]("MAP-OM-DataTypes.EventThreshold1I", "EventThreshold1I", []primitiveRule[EventThreshold1I]{{invalid: func(value EventThreshold1I) bool { return !(int64(value) >= -120 && int64(value) <= -25) }, description: "(-120..-25)", clause: "51.4", observed: func(value EventThreshold1I) any { return int64(value) }}}, false)
}

// JobTypeCodec binds MAP-OM-DataTypes.JobType.
func JobTypeCodec() ValueCodec[BERValue[JobType]] {
	return integerValueCodec[JobType]("MAP-OM-DataTypes.JobType", "JobType", []primitiveRule[JobType]{{invalid: func(value JobType) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3)
	}, description: "ENUMERATED {0, 1, 2, 3}", clause: "20", observed: func(value JobType) any { return int64(value) }}}, true)
}

// AreaScopeCodec binds MAP-OM-DataTypes.AreaScope.
func AreaScopeCodec() ValueCodec[AreaScope] {
	return compositeValueCodec[AreaScope, *AreaScope]()
}

// CGIListCodec binds MAP-OM-DataTypes.CGI-List.
func CGIListCodec() ValueCodec[CGIList] {
	return pointerValueCodec(UnmarshalBERCGIList, MarshalBERCGIList, MarshalDERCGIList)
}

// EUTRANCGIListCodec binds MAP-OM-DataTypes.E-UTRAN-CGI-List.
func EUTRANCGIListCodec() ValueCodec[EUTRANCGIList] {
	return pointerValueCodec(UnmarshalBEREUTRANCGIList, MarshalBEREUTRANCGIList, MarshalDEREUTRANCGIList)
}

// RoutingAreaIdListCodec binds MAP-OM-DataTypes.RoutingAreaId-List.
func RoutingAreaIdListCodec() ValueCodec[RoutingAreaIdList] {
	return pointerValueCodec(UnmarshalBERRoutingAreaIdList, MarshalBERRoutingAreaIdList, MarshalDERRoutingAreaIdList)
}

// LocationAreaIdListCodec binds MAP-OM-DataTypes.LocationAreaId-List.
func LocationAreaIdListCodec() ValueCodec[LocationAreaIdList] {
	return pointerValueCodec(UnmarshalBERLocationAreaIdList, MarshalBERLocationAreaIdList, MarshalDERLocationAreaIdList)
}

// TrackingAreaIdListCodec binds MAP-OM-DataTypes.TrackingAreaId-List.
func TrackingAreaIdListCodec() ValueCodec[TrackingAreaIdList] {
	return pointerValueCodec(UnmarshalBERTrackingAreaIdList, MarshalBERTrackingAreaIdList, MarshalDERTrackingAreaIdList)
}

// ListOfMeasurementsCodec binds MAP-OM-DataTypes.ListOfMeasurements.
func ListOfMeasurementsCodec() ValueCodec[BERValue[ListOfMeasurements]] {
	return octetValueCodec[ListOfMeasurements]("MAP-OM-DataTypes.ListOfMeasurements", "ListOfMeasurements", []primitiveRule[ListOfMeasurements]{{invalid: func(value ListOfMeasurements) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value ListOfMeasurements) int { return len(value) }}})
}

// ReportingTriggerCodec binds MAP-OM-DataTypes.ReportingTrigger.
func ReportingTriggerCodec() ValueCodec[BERValue[ReportingTrigger]] {
	return octetValueCodec[ReportingTrigger]("MAP-OM-DataTypes.ReportingTrigger", "ReportingTrigger", []primitiveRule[ReportingTrigger]{{invalid: func(value ReportingTrigger) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value ReportingTrigger) int { return len(value) }}})
}

// ReportIntervalCodec binds MAP-OM-DataTypes.ReportInterval.
func ReportIntervalCodec() ValueCodec[BERValue[ReportInterval]] {
	return integerValueCodec[ReportInterval]("MAP-OM-DataTypes.ReportInterval", "ReportInterval", []primitiveRule[ReportInterval]{{invalid: func(value ReportInterval) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7 && int64(value) != 8 && int64(value) != 9 && int64(value) != 10 && int64(value) != 11 && int64(value) != 12 && int64(value) != 13 && int64(value) != 14 && int64(value) != 15 && int64(value) != 16 && int64(value) != 17 && int64(value) != 18 && int64(value) != 19 && int64(value) != 20 && int64(value) != 21 && int64(value) != 22 && int64(value) != 23 && int64(value) != 24 && int64(value) != 25 && int64(value) != 26 && int64(value) != 27)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}", clause: "20", observed: func(value ReportInterval) any { return int64(value) }}}, true)
}

// ReportAmountCodec binds MAP-OM-DataTypes.ReportAmount.
func ReportAmountCodec() ValueCodec[BERValue[ReportAmount]] {
	return integerValueCodec[ReportAmount]("MAP-OM-DataTypes.ReportAmount", "ReportAmount", []primitiveRule[ReportAmount]{{invalid: func(value ReportAmount) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", clause: "20", observed: func(value ReportAmount) any { return int64(value) }}}, true)
}

// EventThresholdRSRPCodec binds MAP-OM-DataTypes.EventThresholdRSRP.
func EventThresholdRSRPCodec() ValueCodec[BERValue[EventThresholdRSRP]] {
	return integerValueCodec[EventThresholdRSRP]("MAP-OM-DataTypes.EventThresholdRSRP", "EventThresholdRSRP", []primitiveRule[EventThresholdRSRP]{{invalid: func(value EventThresholdRSRP) bool { return !(int64(value) >= 0 && int64(value) <= 97) }, description: "(0..97)", clause: "51.4", observed: func(value EventThresholdRSRP) any { return int64(value) }}}, false)
}

// EventThresholdRSRQCodec binds MAP-OM-DataTypes.EventThresholdRSRQ.
func EventThresholdRSRQCodec() ValueCodec[BERValue[EventThresholdRSRQ]] {
	return integerValueCodec[EventThresholdRSRQ]("MAP-OM-DataTypes.EventThresholdRSRQ", "EventThresholdRSRQ", []primitiveRule[EventThresholdRSRQ]{{invalid: func(value EventThresholdRSRQ) bool { return !(int64(value) >= 0 && int64(value) <= 34) }, description: "(0..34)", clause: "51.4", observed: func(value EventThresholdRSRQ) any { return int64(value) }}}, false)
}

// LoggingIntervalCodec binds MAP-OM-DataTypes.LoggingInterval.
func LoggingIntervalCodec() ValueCodec[BERValue[LoggingInterval]] {
	return integerValueCodec[LoggingInterval]("MAP-OM-DataTypes.LoggingInterval", "LoggingInterval", []primitiveRule[LoggingInterval]{{invalid: func(value LoggingInterval) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", clause: "20", observed: func(value LoggingInterval) any { return int64(value) }}}, true)
}

// LoggingDurationCodec binds MAP-OM-DataTypes.LoggingDuration.
func LoggingDurationCodec() ValueCodec[BERValue[LoggingDuration]] {
	return integerValueCodec[LoggingDuration]("MAP-OM-DataTypes.LoggingDuration", "LoggingDuration", []primitiveRule[LoggingDuration]{{invalid: func(value LoggingDuration) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5}", clause: "20", observed: func(value LoggingDuration) any { return int64(value) }}}, true)
}

// TraceReferenceCodec binds MAP-OM-DataTypes.TraceReference.
func TraceReferenceCodec() ValueCodec[BERValue[TraceReference]] {
	return octetValueCodec[TraceReference]("MAP-OM-DataTypes.TraceReference", "TraceReference", []primitiveRule[TraceReference]{{invalid: func(value TraceReference) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value TraceReference) int { return len(value) }}})
}

// TraceReference2Codec binds MAP-OM-DataTypes.TraceReference2.
func TraceReference2Codec() ValueCodec[BERValue[TraceReference2]] {
	return octetValueCodec[TraceReference2]("MAP-OM-DataTypes.TraceReference2", "TraceReference2", []primitiveRule[TraceReference2]{{invalid: func(value TraceReference2) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value TraceReference2) int { return len(value) }}})
}

// TraceRecordingSessionReferenceCodec binds MAP-OM-DataTypes.TraceRecordingSessionReference.
func TraceRecordingSessionReferenceCodec() ValueCodec[BERValue[TraceRecordingSessionReference]] {
	return octetValueCodec[TraceRecordingSessionReference]("MAP-OM-DataTypes.TraceRecordingSessionReference", "TraceRecordingSessionReference", []primitiveRule[TraceRecordingSessionReference]{{invalid: func(value TraceRecordingSessionReference) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value TraceRecordingSessionReference) int { return len(value) }}})
}

// TraceTypeCodec binds MAP-OM-DataTypes.TraceType.
func TraceTypeCodec() ValueCodec[BERValue[TraceType]] {
	return integerValueCodec[TraceType]("MAP-OM-DataTypes.TraceType", "TraceType", []primitiveRule[TraceType]{{invalid: func(value TraceType) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "51.4", observed: func(value TraceType) any { return int64(value) }}}, false)
}

// TraceDepthListCodec binds MAP-OM-DataTypes.TraceDepthList.
func TraceDepthListCodec() ValueCodec[TraceDepthList] {
	return compositeValueCodec[TraceDepthList, *TraceDepthList]()
}

// TraceDepthCodec binds MAP-OM-DataTypes.TraceDepth.
func TraceDepthCodec() ValueCodec[BERValue[TraceDepth]] {
	return integerValueCodec[TraceDepth]("MAP-OM-DataTypes.TraceDepth", "TraceDepth", nil, true)
}

// TraceDepthExtensionCodec binds MAP-OM-DataTypes.TraceDepthExtension.
func TraceDepthExtensionCodec() ValueCodec[BERValue[TraceDepthExtension]] {
	return integerValueCodec[TraceDepthExtension]("MAP-OM-DataTypes.TraceDepthExtension", "TraceDepthExtension", nil, true)
}

// TraceNETypeListCodec binds MAP-OM-DataTypes.TraceNE-TypeList.
func TraceNETypeListCodec() ValueCodec[BERValue[TraceNETypeList]] {
	return bitValueCodec("MAP-OM-DataTypes.TraceNE-TypeList", "TraceNE-TypeList", []primitiveRule[TraceNETypeList]{{invalid: func(value TraceNETypeList) bool { return !(value.BitLength >= 6 && value.BitLength <= 16) }, description: "SIZE (6..16)", clause: "51.5", length: func(value TraceNETypeList) int { return value.BitLength }, encodedLength: func(value TraceNETypeList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}})
}

// TraceInterfaceListCodec binds MAP-OM-DataTypes.TraceInterfaceList.
func TraceInterfaceListCodec() ValueCodec[TraceInterfaceList] {
	return compositeValueCodec[TraceInterfaceList, *TraceInterfaceList]()
}

// MSCSInterfaceListCodec binds MAP-OM-DataTypes.MSC-S-InterfaceList.
func MSCSInterfaceListCodec() ValueCodec[BERValue[MSCSInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.MSC-S-InterfaceList", "MSC-S-InterfaceList", []primitiveRule[MSCSInterfaceList]{{invalid: func(value MSCSInterfaceList) bool { return !(value.BitLength >= 10 && value.BitLength <= 16) }, description: "SIZE (10..16)", clause: "51.5", length: func(value MSCSInterfaceList) int { return value.BitLength }, encodedLength: func(value MSCSInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 10, Max: 16}}})
}

// MGWInterfaceListCodec binds MAP-OM-DataTypes.MGW-InterfaceList.
func MGWInterfaceListCodec() ValueCodec[BERValue[MGWInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.MGW-InterfaceList", "MGW-InterfaceList", []primitiveRule[MGWInterfaceList]{{invalid: func(value MGWInterfaceList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value MGWInterfaceList) int { return value.BitLength }, encodedLength: func(value MGWInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// SGSNInterfaceListCodec binds MAP-OM-DataTypes.SGSN-InterfaceList.
func SGSNInterfaceListCodec() ValueCodec[BERValue[SGSNInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGSN-InterfaceList", "SGSN-InterfaceList", []primitiveRule[SGSNInterfaceList]{{invalid: func(value SGSNInterfaceList) bool { return !(value.BitLength >= 8 && value.BitLength <= 16) }, description: "SIZE (8..16)", clause: "51.5", length: func(value SGSNInterfaceList) int { return value.BitLength }, encodedLength: func(value SGSNInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 8, Max: 16}}})
}

// GGSNInterfaceListCodec binds MAP-OM-DataTypes.GGSN-InterfaceList.
func GGSNInterfaceListCodec() ValueCodec[BERValue[GGSNInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.GGSN-InterfaceList", "GGSN-InterfaceList", []primitiveRule[GGSNInterfaceList]{{invalid: func(value GGSNInterfaceList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value GGSNInterfaceList) int { return value.BitLength }, encodedLength: func(value GGSNInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// RNCInterfaceListCodec binds MAP-OM-DataTypes.RNC-InterfaceList.
func RNCInterfaceListCodec() ValueCodec[BERValue[RNCInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.RNC-InterfaceList", "RNC-InterfaceList", []primitiveRule[RNCInterfaceList]{{invalid: func(value RNCInterfaceList) bool { return !(value.BitLength >= 4 && value.BitLength <= 8) }, description: "SIZE (4..8)", clause: "51.5", length: func(value RNCInterfaceList) int { return value.BitLength }, encodedLength: func(value RNCInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 8}}})
}

// BMSCInterfaceListCodec binds MAP-OM-DataTypes.BMSC-InterfaceList.
func BMSCInterfaceListCodec() ValueCodec[BERValue[BMSCInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.BMSC-InterfaceList", "BMSC-InterfaceList", []primitiveRule[BMSCInterfaceList]{{invalid: func(value BMSCInterfaceList) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value BMSCInterfaceList) int { return value.BitLength }, encodedLength: func(value BMSCInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// MMEInterfaceListCodec binds MAP-OM-DataTypes.MME-InterfaceList.
func MMEInterfaceListCodec() ValueCodec[BERValue[MMEInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.MME-InterfaceList", "MME-InterfaceList", []primitiveRule[MMEInterfaceList]{{invalid: func(value MMEInterfaceList) bool { return !(value.BitLength >= 5 && value.BitLength <= 8) }, description: "SIZE (5..8)", clause: "51.5", length: func(value MMEInterfaceList) int { return value.BitLength }, encodedLength: func(value MMEInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 5, Max: 8}}})
}

// SGWInterfaceListCodec binds MAP-OM-DataTypes.SGW-InterfaceList.
func SGWInterfaceListCodec() ValueCodec[BERValue[SGWInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGW-InterfaceList", "SGW-InterfaceList", []primitiveRule[SGWInterfaceList]{{invalid: func(value SGWInterfaceList) bool { return !(value.BitLength >= 5 && value.BitLength <= 8) }, description: "SIZE (5..8)", clause: "51.5", length: func(value SGWInterfaceList) int { return value.BitLength }, encodedLength: func(value SGWInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 5, Max: 8}}})
}

// PGWInterfaceListCodec binds MAP-OM-DataTypes.PGW-InterfaceList.
func PGWInterfaceListCodec() ValueCodec[BERValue[PGWInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.PGW-InterfaceList", "PGW-InterfaceList", []primitiveRule[PGWInterfaceList]{{invalid: func(value PGWInterfaceList) bool { return !(value.BitLength >= 8 && value.BitLength <= 16) }, description: "SIZE (8..16)", clause: "51.5", length: func(value PGWInterfaceList) int { return value.BitLength }, encodedLength: func(value PGWInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 8, Max: 16}}})
}

// ENBInterfaceListCodec binds MAP-OM-DataTypes.ENB-InterfaceList.
func ENBInterfaceListCodec() ValueCodec[BERValue[ENBInterfaceList]] {
	return bitValueCodec("MAP-OM-DataTypes.ENB-InterfaceList", "ENB-InterfaceList", []primitiveRule[ENBInterfaceList]{{invalid: func(value ENBInterfaceList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value ENBInterfaceList) int { return value.BitLength }, encodedLength: func(value ENBInterfaceList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// TraceEventListCodec binds MAP-OM-DataTypes.TraceEventList.
func TraceEventListCodec() ValueCodec[TraceEventList] {
	return compositeValueCodec[TraceEventList, *TraceEventList]()
}

// MSCSEventListCodec binds MAP-OM-DataTypes.MSC-S-EventList.
func MSCSEventListCodec() ValueCodec[BERValue[MSCSEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.MSC-S-EventList", "MSC-S-EventList", []primitiveRule[MSCSEventList]{{invalid: func(value MSCSEventList) bool { return !(value.BitLength >= 5 && value.BitLength <= 16) }, description: "SIZE (5..16)", clause: "51.5", length: func(value MSCSEventList) int { return value.BitLength }, encodedLength: func(value MSCSEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 5, Max: 16}}})
}

// MGWEventListCodec binds MAP-OM-DataTypes.MGW-EventList.
func MGWEventListCodec() ValueCodec[BERValue[MGWEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.MGW-EventList", "MGW-EventList", []primitiveRule[MGWEventList]{{invalid: func(value MGWEventList) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value MGWEventList) int { return value.BitLength }, encodedLength: func(value MGWEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// SGSNEventListCodec binds MAP-OM-DataTypes.SGSN-EventList.
func SGSNEventListCodec() ValueCodec[BERValue[SGSNEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGSN-EventList", "SGSN-EventList", []primitiveRule[SGSNEventList]{{invalid: func(value SGSNEventList) bool { return !(value.BitLength >= 4 && value.BitLength <= 16) }, description: "SIZE (4..16)", clause: "51.5", length: func(value SGSNEventList) int { return value.BitLength }, encodedLength: func(value SGSNEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 16}}})
}

// GGSNEventListCodec binds MAP-OM-DataTypes.GGSN-EventList.
func GGSNEventListCodec() ValueCodec[BERValue[GGSNEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.GGSN-EventList", "GGSN-EventList", []primitiveRule[GGSNEventList]{{invalid: func(value GGSNEventList) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value GGSNEventList) int { return value.BitLength }, encodedLength: func(value GGSNEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// BMSCEventListCodec binds MAP-OM-DataTypes.BMSC-EventList.
func BMSCEventListCodec() ValueCodec[BERValue[BMSCEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.BMSC-EventList", "BMSC-EventList", []primitiveRule[BMSCEventList]{{invalid: func(value BMSCEventList) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value BMSCEventList) int { return value.BitLength }, encodedLength: func(value BMSCEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// MMEEventListCodec binds MAP-OM-DataTypes.MME-EventList.
func MMEEventListCodec() ValueCodec[BERValue[MMEEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.MME-EventList", "MME-EventList", []primitiveRule[MMEEventList]{{invalid: func(value MMEEventList) bool { return !(value.BitLength >= 6 && value.BitLength <= 8) }, description: "SIZE (6..8)", clause: "51.5", length: func(value MMEEventList) int { return value.BitLength }, encodedLength: func(value MMEEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 8}}})
}

// SGWEventListCodec binds MAP-OM-DataTypes.SGW-EventList.
func SGWEventListCodec() ValueCodec[BERValue[SGWEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.SGW-EventList", "SGW-EventList", []primitiveRule[SGWEventList]{{invalid: func(value SGWEventList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value SGWEventList) int { return value.BitLength }, encodedLength: func(value SGWEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// PGWEventListCodec binds MAP-OM-DataTypes.PGW-EventList.
func PGWEventListCodec() ValueCodec[BERValue[PGWEventList]] {
	return bitValueCodec("MAP-OM-DataTypes.PGW-EventList", "PGW-EventList", []primitiveRule[PGWEventList]{{invalid: func(value PGWEventList) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value PGWEventList) int { return value.BitLength }, encodedLength: func(value PGWEventList) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// TracePropagationListCodec binds MAP-OM-DataTypes.TracePropagationList.
func TracePropagationListCodec() ValueCodec[TracePropagationList] {
	return compositeValueCodec[TracePropagationList, *TracePropagationList]()
}

// ActivateTraceModeResCodec binds MAP-OM-DataTypes.ActivateTraceModeRes.
func ActivateTraceModeResCodec() ValueCodec[ActivateTraceModeRes] {
	return compositeValueCodec[ActivateTraceModeRes, *ActivateTraceModeRes]()
}

// DeactivateTraceModeArgCodec binds MAP-OM-DataTypes.DeactivateTraceModeArg.
func DeactivateTraceModeArgCodec() ValueCodec[DeactivateTraceModeArg] {
	return compositeValueCodec[DeactivateTraceModeArg, *DeactivateTraceModeArg]()
}

// DeactivateTraceModeResCodec binds MAP-OM-DataTypes.DeactivateTraceModeRes.
func DeactivateTraceModeResCodec() ValueCodec[DeactivateTraceModeRes] {
	return compositeValueCodec[DeactivateTraceModeRes, *DeactivateTraceModeRes]()
}

// UpdateLocationArgCodec binds MAP-MS-DataTypes.UpdateLocationArg.
func UpdateLocationArgCodec() ValueCodec[UpdateLocationArg] {
	return compositeValueCodec[UpdateLocationArg, *UpdateLocationArg]()
}

// VLRCapabilityCodec binds MAP-MS-DataTypes.VLR-Capability.
func VLRCapabilityCodec() ValueCodec[VLRCapability] {
	return compositeValueCodec[VLRCapability, *VLRCapability]()
}

// SupportedRATTypesCodec binds MAP-MS-DataTypes.SupportedRAT-Types.
func SupportedRATTypesCodec() ValueCodec[BERValue[SupportedRATTypes]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedRAT-Types", "SupportedRAT-Types", []primitiveRule[SupportedRATTypes]{{invalid: func(value SupportedRATTypes) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value SupportedRATTypes) int { return value.BitLength }, encodedLength: func(value SupportedRATTypes) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// SuperChargerInfoCodec binds MAP-MS-DataTypes.SuperChargerInfo.
func SuperChargerInfoCodec() ValueCodec[SuperChargerInfo] {
	return compositeValueCodec[SuperChargerInfo, *SuperChargerInfo]()
}

// AgeIndicatorCodec binds MAP-MS-DataTypes.AgeIndicator.
func AgeIndicatorCodec() ValueCodec[BERValue[AgeIndicator]] {
	return octetValueCodec[AgeIndicator]("MAP-MS-DataTypes.AgeIndicator", "AgeIndicator", []primitiveRule[AgeIndicator]{{invalid: func(value AgeIndicator) bool { return !(len(value) >= 1 && len(value) <= 6) }, description: "SIZE (1..6)", clause: "51.5", length: func(value AgeIndicator) int { return len(value) }}})
}

// ISTSupportIndicatorCodec binds MAP-MS-DataTypes.IST-SupportIndicator.
func ISTSupportIndicatorCodec() ValueCodec[BERValue[ISTSupportIndicator]] {
	return integerValueCodec[ISTSupportIndicator]("MAP-MS-DataTypes.IST-SupportIndicator", "IST-SupportIndicator", nil, true)
}

// SupportedLCSCapabilitySetsCodec binds MAP-MS-DataTypes.SupportedLCS-CapabilitySets.
func SupportedLCSCapabilitySetsCodec() ValueCodec[BERValue[SupportedLCSCapabilitySets]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedLCS-CapabilitySets", "SupportedLCS-CapabilitySets", []primitiveRule[SupportedLCSCapabilitySets]{{invalid: func(value SupportedLCSCapabilitySets) bool { return !(value.BitLength >= 2 && value.BitLength <= 16) }, description: "SIZE (2..16)", clause: "51.5", length: func(value SupportedLCSCapabilitySets) int { return value.BitLength }, encodedLength: func(value SupportedLCSCapabilitySets) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}})
}

// UpdateLocationResCodec binds MAP-MS-DataTypes.UpdateLocationRes.
func UpdateLocationResCodec() ValueCodec[UpdateLocationRes] {
	return compositeValueCodec[UpdateLocationRes, *UpdateLocationRes]()
}

// ADDInfoCodec binds MAP-MS-DataTypes.ADD-Info.
func ADDInfoCodec() ValueCodec[ADDInfo] {
	return compositeValueCodec[ADDInfo, *ADDInfo]()
}

// PagingAreaCodec binds MAP-MS-DataTypes.PagingArea.
func PagingAreaCodec() ValueCodec[PagingArea] {
	return pointerValueCodec(UnmarshalBERPagingArea, MarshalBERPagingArea, MarshalDERPagingArea)
}

// LocationAreaCodec binds MAP-MS-DataTypes.LocationArea.
func LocationAreaCodec() ValueCodec[LocationArea] {
	return compositeValueCodec[LocationArea, *LocationArea]()
}

// LACCodec binds MAP-MS-DataTypes.LAC.
func LACCodec() ValueCodec[BERValue[LAC]] {
	return octetValueCodec[LAC]("MAP-MS-DataTypes.LAC", "LAC", []primitiveRule[LAC]{{invalid: func(value LAC) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value LAC) int { return len(value) }}})
}

// CancelLocationArgCodec binds MAP-MS-DataTypes.CancelLocationArg.
func CancelLocationArgCodec() ValueCodec[CancelLocationArg] {
	return compositeValueCodec[CancelLocationArg, *CancelLocationArg]()
}

// TypeOfUpdateCodec binds MAP-MS-DataTypes.TypeOfUpdate.
func TypeOfUpdateCodec() ValueCodec[BERValue[TypeOfUpdate]] {
	return integerValueCodec[TypeOfUpdate]("MAP-MS-DataTypes.TypeOfUpdate", "TypeOfUpdate", nil, true)
}

// CancellationTypeCodec binds MAP-MS-DataTypes.CancellationType.
func CancellationTypeCodec() ValueCodec[BERValue[CancellationType]] {
	return integerValueCodec[CancellationType]("MAP-MS-DataTypes.CancellationType", "CancellationType", nil, true)
}

// CancelLocationResCodec binds MAP-MS-DataTypes.CancelLocationRes.
func CancelLocationResCodec() ValueCodec[CancelLocationRes] {
	return compositeValueCodec[CancelLocationRes, *CancelLocationRes]()
}

// PurgeMSArgCodec binds MAP-MS-DataTypes.PurgeMS-Arg.
func PurgeMSArgCodec() ValueCodec[PurgeMSArg] {
	return compositeValueCodec[PurgeMSArg, *PurgeMSArg]()
}

// PurgeMSResCodec binds MAP-MS-DataTypes.PurgeMS-Res.
func PurgeMSResCodec() ValueCodec[PurgeMSRes] {
	return compositeValueCodec[PurgeMSRes, *PurgeMSRes]()
}

// SendIdentificationArgCodec binds MAP-MS-DataTypes.SendIdentificationArg.
func SendIdentificationArgCodec() ValueCodec[SendIdentificationArg] {
	return compositeValueCodec[SendIdentificationArg, *SendIdentificationArg]()
}

// HopCounterCodec binds MAP-MS-DataTypes.HopCounter.
func HopCounterCodec() ValueCodec[BERValue[HopCounter]] {
	return integerValueCodec[HopCounter]("MAP-MS-DataTypes.HopCounter", "HopCounter", []primitiveRule[HopCounter]{{invalid: func(value HopCounter) bool { return !(int64(value) >= 0 && int64(value) <= 3) }, description: "(0..3)", clause: "51.4", observed: func(value HopCounter) any { return int64(value) }}}, false)
}

// SendIdentificationResCodec binds MAP-MS-DataTypes.SendIdentificationRes.
func SendIdentificationResCodec() ValueCodec[SendIdentificationRes] {
	return compositeValueCodec[SendIdentificationRes, *SendIdentificationRes]()
}

// AuthenticationSetListCodec binds MAP-MS-DataTypes.AuthenticationSetList.
func AuthenticationSetListCodec() ValueCodec[AuthenticationSetList] {
	return compositeValueCodec[AuthenticationSetList, *AuthenticationSetList]()
}

// TripletListCodec binds MAP-MS-DataTypes.TripletList.
func TripletListCodec() ValueCodec[TripletList] {
	return pointerValueCodec(UnmarshalBERTripletList, MarshalBERTripletList, MarshalDERTripletList)
}

// QuintupletListCodec binds MAP-MS-DataTypes.QuintupletList.
func QuintupletListCodec() ValueCodec[QuintupletList] {
	return pointerValueCodec(UnmarshalBERQuintupletList, MarshalBERQuintupletList, MarshalDERQuintupletList)
}

// AuthenticationTripletCodec binds MAP-MS-DataTypes.AuthenticationTriplet.
func AuthenticationTripletCodec() ValueCodec[AuthenticationTriplet] {
	return compositeValueCodec[AuthenticationTriplet, *AuthenticationTriplet]()
}

// AuthenticationQuintupletCodec binds MAP-MS-DataTypes.AuthenticationQuintuplet.
func AuthenticationQuintupletCodec() ValueCodec[AuthenticationQuintuplet] {
	return compositeValueCodec[AuthenticationQuintuplet, *AuthenticationQuintuplet]()
}

// CurrentSecurityContextCodec binds MAP-MS-DataTypes.CurrentSecurityContext.
func CurrentSecurityContextCodec() ValueCodec[CurrentSecurityContext] {
	return compositeValueCodec[CurrentSecurityContext, *CurrentSecurityContext]()
}

// GSMSecurityContextDataCodec binds MAP-MS-DataTypes.GSM-SecurityContextData.
func GSMSecurityContextDataCodec() ValueCodec[GSMSecurityContextData] {
	return compositeValueCodec[GSMSecurityContextData, *GSMSecurityContextData]()
}

// UMTSSecurityContextDataCodec binds MAP-MS-DataTypes.UMTS-SecurityContextData.
func UMTSSecurityContextDataCodec() ValueCodec[UMTSSecurityContextData] {
	return compositeValueCodec[UMTSSecurityContextData, *UMTSSecurityContextData]()
}

// RANDCodec binds MAP-MS-DataTypes.RAND.
func RANDCodec() ValueCodec[BERValue[RAND]] {
	return octetValueCodec[RAND]("MAP-MS-DataTypes.RAND", "RAND", []primitiveRule[RAND]{{invalid: func(value RAND) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value RAND) int { return len(value) }}})
}

// SRESCodec binds MAP-MS-DataTypes.SRES.
func SRESCodec() ValueCodec[BERValue[SRES]] {
	return octetValueCodec[SRES]("MAP-MS-DataTypes.SRES", "SRES", []primitiveRule[SRES]{{invalid: func(value SRES) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value SRES) int { return len(value) }}})
}

// KcCodec binds MAP-MS-DataTypes.Kc.
func KcCodec() ValueCodec[BERValue[Kc]] {
	return octetValueCodec[Kc]("MAP-MS-DataTypes.Kc", "Kc", []primitiveRule[Kc]{{invalid: func(value Kc) bool { return !(len(value) == 8) }, description: "SIZE (8)", clause: "51.5", length: func(value Kc) int { return len(value) }}})
}

// XRESCodec binds MAP-MS-DataTypes.XRES.
func XRESCodec() ValueCodec[BERValue[XRES]] {
	return octetValueCodec[XRES]("MAP-MS-DataTypes.XRES", "XRES", []primitiveRule[XRES]{{invalid: func(value XRES) bool { return !(len(value) >= 4 && len(value) <= 16) }, description: "SIZE (4..16)", clause: "51.5", length: func(value XRES) int { return len(value) }}})
}

// CKCodec binds MAP-MS-DataTypes.CK.
func CKCodec() ValueCodec[BERValue[CK]] {
	return octetValueCodec[CK]("MAP-MS-DataTypes.CK", "CK", []primitiveRule[CK]{{invalid: func(value CK) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value CK) int { return len(value) }}})
}

// IKCodec binds MAP-MS-DataTypes.IK.
func IKCodec() ValueCodec[BERValue[IK]] {
	return octetValueCodec[IK]("MAP-MS-DataTypes.IK", "IK", []primitiveRule[IK]{{invalid: func(value IK) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value IK) int { return len(value) }}})
}

// AUTNCodec binds MAP-MS-DataTypes.AUTN.
func AUTNCodec() ValueCodec[BERValue[AUTN]] {
	return octetValueCodec[AUTN]("MAP-MS-DataTypes.AUTN", "AUTN", []primitiveRule[AUTN]{{invalid: func(value AUTN) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value AUTN) int { return len(value) }}})
}

// AUTSCodec binds MAP-MS-DataTypes.AUTS.
func AUTSCodec() ValueCodec[BERValue[AUTS]] {
	return octetValueCodec[AUTS]("MAP-MS-DataTypes.AUTS", "AUTS", []primitiveRule[AUTS]{{invalid: func(value AUTS) bool { return !(len(value) == 14) }, description: "SIZE (14)", clause: "51.5", length: func(value AUTS) int { return len(value) }}})
}

// CksnCodec binds MAP-MS-DataTypes.Cksn.
func CksnCodec() ValueCodec[BERValue[Cksn]] {
	return octetValueCodec[Cksn]("MAP-MS-DataTypes.Cksn", "Cksn", []primitiveRule[Cksn]{{invalid: func(value Cksn) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value Cksn) int { return len(value) }}})
}

// KSICodec binds MAP-MS-DataTypes.KSI.
func KSICodec() ValueCodec[BERValue[KSI]] {
	return octetValueCodec[KSI]("MAP-MS-DataTypes.KSI", "KSI", []primitiveRule[KSI]{{invalid: func(value KSI) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value KSI) int { return len(value) }}})
}

// AuthenticationFailureReportArgCodec binds MAP-MS-DataTypes.AuthenticationFailureReportArg.
func AuthenticationFailureReportArgCodec() ValueCodec[AuthenticationFailureReportArg] {
	return compositeValueCodec[AuthenticationFailureReportArg, *AuthenticationFailureReportArg]()
}

// AccessTypeCodec binds MAP-MS-DataTypes.AccessType.
func AccessTypeCodec() ValueCodec[BERValue[AccessType]] {
	return integerValueCodec[AccessType]("MAP-MS-DataTypes.AccessType", "AccessType", nil, true)
}

// AuthenticationFailureReportResCodec binds MAP-MS-DataTypes.AuthenticationFailureReportRes.
func AuthenticationFailureReportResCodec() ValueCodec[AuthenticationFailureReportRes] {
	return compositeValueCodec[AuthenticationFailureReportRes, *AuthenticationFailureReportRes]()
}

// FailureCauseCodec binds MAP-MS-DataTypes.FailureCause.
func FailureCauseCodec() ValueCodec[BERValue[FailureCause]] {
	return integerValueCodec[FailureCause]("MAP-MS-DataTypes.FailureCause", "FailureCause", []primitiveRule[FailureCause]{{invalid: func(value FailureCause) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value FailureCause) any { return int64(value) }}}, true)
}

// UpdateGprsLocationArgCodec binds MAP-MS-DataTypes.UpdateGprsLocationArg.
func UpdateGprsLocationArgCodec() ValueCodec[UpdateGprsLocationArg] {
	return compositeValueCodec[UpdateGprsLocationArg, *UpdateGprsLocationArg]()
}

// SMSRegisterRequestCodec binds MAP-MS-DataTypes.SMSRegisterRequest.
func SMSRegisterRequestCodec() ValueCodec[BERValue[SMSRegisterRequest]] {
	return integerValueCodec[SMSRegisterRequest]("MAP-MS-DataTypes.SMSRegisterRequest", "SMSRegisterRequest", nil, true)
}

// UsedRATTypeCodec binds MAP-MS-DataTypes.Used-RAT-Type.
func UsedRATTypeCodec() ValueCodec[BERValue[UsedRATType]] {
	return integerValueCodec[UsedRATType]("MAP-MS-DataTypes.Used-RAT-Type", "Used-RAT-Type", nil, true)
}

// EPSInfoCodec binds MAP-MS-DataTypes.EPS-Info.
func EPSInfoCodec() ValueCodec[EPSInfo] {
	return compositeValueCodec[EPSInfo, *EPSInfo]()
}

// PDNGWUpdateCodec binds MAP-MS-DataTypes.PDN-GW-Update.
func PDNGWUpdateCodec() ValueCodec[PDNGWUpdate] {
	return compositeValueCodec[PDNGWUpdate, *PDNGWUpdate]()
}

// ISRInformationCodec binds MAP-MS-DataTypes.ISR-Information.
func ISRInformationCodec() ValueCodec[BERValue[ISRInformation]] {
	return bitValueCodec("MAP-MS-DataTypes.ISR-Information", "ISR-Information", []primitiveRule[ISRInformation]{{invalid: func(value ISRInformation) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value ISRInformation) int { return value.BitLength }, encodedLength: func(value ISRInformation) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// SGSNCapabilityCodec binds MAP-MS-DataTypes.SGSN-Capability.
func SGSNCapabilityCodec() ValueCodec[SGSNCapability] {
	return compositeValueCodec[SGSNCapability, *SGSNCapability]()
}

// SupportedFeaturesCodec binds MAP-MS-DataTypes.SupportedFeatures.
func SupportedFeaturesCodec() ValueCodec[BERValue[SupportedFeatures]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedFeatures", "SupportedFeatures", []primitiveRule[SupportedFeatures]{{invalid: func(value SupportedFeatures) bool { return !(value.BitLength >= 26 && value.BitLength <= 40) }, description: "SIZE (26..40)", clause: "51.5", length: func(value SupportedFeatures) int { return value.BitLength }, encodedLength: func(value SupportedFeatures) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 26, Max: 40}}})
}

// ExtSupportedFeaturesCodec binds MAP-MS-DataTypes.Ext-SupportedFeatures.
func ExtSupportedFeaturesCodec() ValueCodec[BERValue[ExtSupportedFeatures]] {
	return bitValueCodec("MAP-MS-DataTypes.Ext-SupportedFeatures", "Ext-SupportedFeatures", []primitiveRule[ExtSupportedFeatures]{{invalid: func(value ExtSupportedFeatures) bool { return !(value.BitLength >= 1 && value.BitLength <= 40) }, description: "SIZE (1..40)", clause: "51.5", length: func(value ExtSupportedFeatures) int { return value.BitLength }, encodedLength: func(value ExtSupportedFeatures) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 40}}})
}

// UESRVCCCapabilityCodec binds MAP-MS-DataTypes.UE-SRVCC-Capability.
func UESRVCCCapabilityCodec() ValueCodec[BERValue[UESRVCCCapability]] {
	return integerValueCodec[UESRVCCCapability]("MAP-MS-DataTypes.UE-SRVCC-Capability", "UE-SRVCC-Capability", nil, true)
}

// UpdateGprsLocationResCodec binds MAP-MS-DataTypes.UpdateGprsLocationRes.
func UpdateGprsLocationResCodec() ValueCodec[UpdateGprsLocationRes] {
	return compositeValueCodec[UpdateGprsLocationRes, *UpdateGprsLocationRes]()
}

// EPLMNListCodec binds MAP-MS-DataTypes.EPLMN-List.
func EPLMNListCodec() ValueCodec[EPLMNList] {
	return pointerValueCodec(UnmarshalBEREPLMNList, MarshalBEREPLMNList, MarshalDEREPLMNList)
}

// AdjacentPLMNListCodec binds MAP-MS-DataTypes.AdjacentPLMN-List.
func AdjacentPLMNListCodec() ValueCodec[AdjacentPLMNList] {
	return pointerValueCodec(UnmarshalBERAdjacentPLMNList, MarshalBERAdjacentPLMNList, MarshalDERAdjacentPLMNList)
}

// ForwardAccessSignallingArgCodec binds MAP-MS-DataTypes.ForwardAccessSignalling-Arg.
func ForwardAccessSignallingArgCodec() ValueCodec[ForwardAccessSignallingArg] {
	return compositeValueCodec[ForwardAccessSignallingArg, *ForwardAccessSignallingArg]()
}

// AllowedGSMAlgorithmsCodec binds MAP-MS-DataTypes.AllowedGSM-Algorithms.
func AllowedGSMAlgorithmsCodec() ValueCodec[BERValue[AllowedGSMAlgorithms]] {
	return octetValueCodec[AllowedGSMAlgorithms]("MAP-MS-DataTypes.AllowedGSM-Algorithms", "AllowedGSM-Algorithms", []primitiveRule[AllowedGSMAlgorithms]{{invalid: func(value AllowedGSMAlgorithms) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value AllowedGSMAlgorithms) int { return len(value) }}})
}

// AllowedUMTSAlgorithmsCodec binds MAP-MS-DataTypes.AllowedUMTS-Algorithms.
func AllowedUMTSAlgorithmsCodec() ValueCodec[AllowedUMTSAlgorithms] {
	return compositeValueCodec[AllowedUMTSAlgorithms, *AllowedUMTSAlgorithms]()
}

// PermittedIntegrityProtectionAlgorithmsCodec binds MAP-MS-DataTypes.PermittedIntegrityProtectionAlgorithms.
func PermittedIntegrityProtectionAlgorithmsCodec() ValueCodec[BERValue[PermittedIntegrityProtectionAlgorithms]] {
	return octetValueCodec[PermittedIntegrityProtectionAlgorithms]("MAP-MS-DataTypes.PermittedIntegrityProtectionAlgorithms", "PermittedIntegrityProtectionAlgorithms", []primitiveRule[PermittedIntegrityProtectionAlgorithms]{{invalid: func(value PermittedIntegrityProtectionAlgorithms) bool { return !(len(value) >= 1 && len(value) <= 9) }, description: "SIZE (1..9)", clause: "51.5", length: func(value PermittedIntegrityProtectionAlgorithms) int { return len(value) }}})
}

// PermittedEncryptionAlgorithmsCodec binds MAP-MS-DataTypes.PermittedEncryptionAlgorithms.
func PermittedEncryptionAlgorithmsCodec() ValueCodec[BERValue[PermittedEncryptionAlgorithms]] {
	return octetValueCodec[PermittedEncryptionAlgorithms]("MAP-MS-DataTypes.PermittedEncryptionAlgorithms", "PermittedEncryptionAlgorithms", []primitiveRule[PermittedEncryptionAlgorithms]{{invalid: func(value PermittedEncryptionAlgorithms) bool { return !(len(value) >= 1 && len(value) <= 9) }, description: "SIZE (1..9)", clause: "51.5", length: func(value PermittedEncryptionAlgorithms) int { return len(value) }}})
}

// KeyStatusCodec binds MAP-MS-DataTypes.KeyStatus.
func KeyStatusCodec() ValueCodec[BERValue[KeyStatus]] {
	return integerValueCodec[KeyStatus]("MAP-MS-DataTypes.KeyStatus", "KeyStatus", nil, true)
}

// PrepareHOArgCodec binds MAP-MS-DataTypes.PrepareHO-Arg.
func PrepareHOArgCodec() ValueCodec[PrepareHOArg] {
	return compositeValueCodec[PrepareHOArg, *PrepareHOArg]()
}

// LCLSGlobalCallReferenceCodec binds MAP-MS-DataTypes.LCLS-GlobalCallReference.
func LCLSGlobalCallReferenceCodec() ValueCodec[BERValue[LCLSGlobalCallReference]] {
	return octetValueCodec[LCLSGlobalCallReference]("MAP-MS-DataTypes.LCLS-GlobalCallReference", "LCLS-GlobalCallReference", []primitiveRule[LCLSGlobalCallReference]{{invalid: func(value LCLSGlobalCallReference) bool { return !(len(value) >= 13 && len(value) <= 15) }, description: "SIZE (13..15)", clause: "51.5", length: func(value LCLSGlobalCallReference) int { return len(value) }}})
}

// LCLSNegotiationCodec binds MAP-MS-DataTypes.LCLS-Negotiation.
func LCLSNegotiationCodec() ValueCodec[BERValue[LCLSNegotiation]] {
	return bitValueCodec("MAP-MS-DataTypes.LCLS-Negotiation", "LCLS-Negotiation", []primitiveRule[LCLSNegotiation]{{invalid: func(value LCLSNegotiation) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value LCLSNegotiation) int { return value.BitLength }, encodedLength: func(value LCLSNegotiation) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// LCLSConfigurationPreferenceCodec binds MAP-MS-DataTypes.LCLS-ConfigurationPreference.
func LCLSConfigurationPreferenceCodec() ValueCodec[BERValue[LCLSConfigurationPreference]] {
	return bitValueCodec("MAP-MS-DataTypes.LCLS-ConfigurationPreference", "LCLS-ConfigurationPreference", []primitiveRule[LCLSConfigurationPreference]{{invalid: func(value LCLSConfigurationPreference) bool { return !(value.BitLength >= 4 && value.BitLength <= 8) }, description: "SIZE (4..8)", clause: "51.5", length: func(value LCLSConfigurationPreference) int { return value.BitLength }, encodedLength: func(value LCLSConfigurationPreference) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 8}}})
}

// BSSMAPServiceHandoverListCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandoverList.
func BSSMAPServiceHandoverListCodec() ValueCodec[BSSMAPServiceHandoverList] {
	return pointerValueCodec(UnmarshalBERBSSMAPServiceHandoverList, MarshalBERBSSMAPServiceHandoverList, MarshalDERBSSMAPServiceHandoverList)
}

// BSSMAPServiceHandoverInfoCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandoverInfo.
func BSSMAPServiceHandoverInfoCodec() ValueCodec[BSSMAPServiceHandoverInfo] {
	return compositeValueCodec[BSSMAPServiceHandoverInfo, *BSSMAPServiceHandoverInfo]()
}

// BSSMAPServiceHandoverCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandover.
func BSSMAPServiceHandoverCodec() ValueCodec[BERValue[BSSMAPServiceHandover]] {
	return octetValueCodec[BSSMAPServiceHandover]("MAP-MS-DataTypes.BSSMAP-ServiceHandover", "BSSMAP-ServiceHandover", []primitiveRule[BSSMAPServiceHandover]{{invalid: func(value BSSMAPServiceHandover) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value BSSMAPServiceHandover) int { return len(value) }}})
}

// RANAPServiceHandoverCodec binds MAP-MS-DataTypes.RANAP-ServiceHandover.
func RANAPServiceHandoverCodec() ValueCodec[BERValue[RANAPServiceHandover]] {
	return octetValueCodec[RANAPServiceHandover]("MAP-MS-DataTypes.RANAP-ServiceHandover", "RANAP-ServiceHandover", []primitiveRule[RANAPServiceHandover]{{invalid: func(value RANAPServiceHandover) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value RANAPServiceHandover) int { return len(value) }}})
}

// RadioResourceListCodec binds MAP-MS-DataTypes.RadioResourceList.
func RadioResourceListCodec() ValueCodec[RadioResourceList] {
	return pointerValueCodec(UnmarshalBERRadioResourceList, MarshalBERRadioResourceList, MarshalDERRadioResourceList)
}

// RadioResourceCodec binds MAP-MS-DataTypes.RadioResource.
func RadioResourceCodec() ValueCodec[RadioResource] {
	return compositeValueCodec[RadioResource, *RadioResource]()
}

// PrepareHOResCodec binds MAP-MS-DataTypes.PrepareHO-Res.
func PrepareHOResCodec() ValueCodec[PrepareHORes] {
	return compositeValueCodec[PrepareHORes, *PrepareHORes]()
}

// SelectedUMTSAlgorithmsCodec binds MAP-MS-DataTypes.SelectedUMTS-Algorithms.
func SelectedUMTSAlgorithmsCodec() ValueCodec[SelectedUMTSAlgorithms] {
	return compositeValueCodec[SelectedUMTSAlgorithms, *SelectedUMTSAlgorithms]()
}

// ChosenIntegrityProtectionAlgorithmCodec binds MAP-MS-DataTypes.ChosenIntegrityProtectionAlgorithm.
func ChosenIntegrityProtectionAlgorithmCodec() ValueCodec[BERValue[ChosenIntegrityProtectionAlgorithm]] {
	return octetValueCodec[ChosenIntegrityProtectionAlgorithm]("MAP-MS-DataTypes.ChosenIntegrityProtectionAlgorithm", "ChosenIntegrityProtectionAlgorithm", []primitiveRule[ChosenIntegrityProtectionAlgorithm]{{invalid: func(value ChosenIntegrityProtectionAlgorithm) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value ChosenIntegrityProtectionAlgorithm) int { return len(value) }}})
}

// ChosenEncryptionAlgorithmCodec binds MAP-MS-DataTypes.ChosenEncryptionAlgorithm.
func ChosenEncryptionAlgorithmCodec() ValueCodec[BERValue[ChosenEncryptionAlgorithm]] {
	return octetValueCodec[ChosenEncryptionAlgorithm]("MAP-MS-DataTypes.ChosenEncryptionAlgorithm", "ChosenEncryptionAlgorithm", []primitiveRule[ChosenEncryptionAlgorithm]{{invalid: func(value ChosenEncryptionAlgorithm) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value ChosenEncryptionAlgorithm) int { return len(value) }}})
}

// ChosenRadioResourceInformationCodec binds MAP-MS-DataTypes.ChosenRadioResourceInformation.
func ChosenRadioResourceInformationCodec() ValueCodec[ChosenRadioResourceInformation] {
	return compositeValueCodec[ChosenRadioResourceInformation, *ChosenRadioResourceInformation]()
}

// ChosenChannelInfoCodec binds MAP-MS-DataTypes.ChosenChannelInfo.
func ChosenChannelInfoCodec() ValueCodec[BERValue[ChosenChannelInfo]] {
	return octetValueCodec[ChosenChannelInfo]("MAP-MS-DataTypes.ChosenChannelInfo", "ChosenChannelInfo", []primitiveRule[ChosenChannelInfo]{{invalid: func(value ChosenChannelInfo) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value ChosenChannelInfo) int { return len(value) }}})
}

// ChosenSpeechVersionCodec binds MAP-MS-DataTypes.ChosenSpeechVersion.
func ChosenSpeechVersionCodec() ValueCodec[BERValue[ChosenSpeechVersion]] {
	return octetValueCodec[ChosenSpeechVersion]("MAP-MS-DataTypes.ChosenSpeechVersion", "ChosenSpeechVersion", []primitiveRule[ChosenSpeechVersion]{{invalid: func(value ChosenSpeechVersion) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value ChosenSpeechVersion) int { return len(value) }}})
}

// PrepareSubsequentHOArgCodec binds MAP-MS-DataTypes.PrepareSubsequentHO-Arg.
func PrepareSubsequentHOArgCodec() ValueCodec[PrepareSubsequentHOArg] {
	return compositeValueCodec[PrepareSubsequentHOArg, *PrepareSubsequentHOArg]()
}

// PrepareSubsequentHOResCodec binds MAP-MS-DataTypes.PrepareSubsequentHO-Res.
func PrepareSubsequentHOResCodec() ValueCodec[PrepareSubsequentHORes] {
	return compositeValueCodec[PrepareSubsequentHORes, *PrepareSubsequentHORes]()
}

// ProcessAccessSignallingArgCodec binds MAP-MS-DataTypes.ProcessAccessSignalling-Arg.
func ProcessAccessSignallingArgCodec() ValueCodec[ProcessAccessSignallingArg] {
	return compositeValueCodec[ProcessAccessSignallingArg, *ProcessAccessSignallingArg]()
}

// AoIPCodecsListCodec binds MAP-MS-DataTypes.AoIPCodecsList.
func AoIPCodecsListCodec() ValueCodec[AoIPCodecsList] {
	return compositeValueCodec[AoIPCodecsList, *AoIPCodecsList]()
}

// AoIPCodecCodec binds MAP-MS-DataTypes.AoIPCodec.
func AoIPCodecCodec() ValueCodec[BERValue[AoIPCodec]] {
	return octetValueCodec[AoIPCodec]("MAP-MS-DataTypes.AoIPCodec", "AoIPCodec", []primitiveRule[AoIPCodec]{{invalid: func(value AoIPCodec) bool { return !(len(value) >= 1 && len(value) <= 3) }, description: "SIZE (1..3)", clause: "51.5", length: func(value AoIPCodec) int { return len(value) }}})
}

// SupportedCodecsListCodec binds MAP-MS-DataTypes.SupportedCodecsList.
func SupportedCodecsListCodec() ValueCodec[SupportedCodecsList] {
	return compositeValueCodec[SupportedCodecsList, *SupportedCodecsList]()
}

// CodecListCodec binds MAP-MS-DataTypes.CodecList.
func CodecListCodec() ValueCodec[CodecList] {
	return compositeValueCodec[CodecList, *CodecList]()
}

// CodecCodec binds MAP-MS-DataTypes.Codec.
func CodecCodec() ValueCodec[BERValue[Codec]] {
	return octetValueCodec[Codec]("MAP-MS-DataTypes.Codec", "Codec", []primitiveRule[Codec]{{invalid: func(value Codec) bool { return !(len(value) >= 1 && len(value) <= 4) }, description: "SIZE (1..4)", clause: "51.5", length: func(value Codec) int { return len(value) }}})
}

// GERANClassmarkCodec binds MAP-MS-DataTypes.GERAN-Classmark.
func GERANClassmarkCodec() ValueCodec[BERValue[GERANClassmark]] {
	return octetValueCodec[GERANClassmark]("MAP-MS-DataTypes.GERAN-Classmark", "GERAN-Classmark", []primitiveRule[GERANClassmark]{{invalid: func(value GERANClassmark) bool { return !(len(value) >= 2 && len(value) <= 87) }, description: "SIZE (2..87)", clause: "51.5", length: func(value GERANClassmark) int { return len(value) }}})
}

// SelectedGSMAlgorithmCodec binds MAP-MS-DataTypes.SelectedGSM-Algorithm.
func SelectedGSMAlgorithmCodec() ValueCodec[BERValue[SelectedGSMAlgorithm]] {
	return octetValueCodec[SelectedGSMAlgorithm]("MAP-MS-DataTypes.SelectedGSM-Algorithm", "SelectedGSM-Algorithm", []primitiveRule[SelectedGSMAlgorithm]{{invalid: func(value SelectedGSMAlgorithm) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value SelectedGSMAlgorithm) int { return len(value) }}})
}

// SendEndSignalArgCodec binds MAP-MS-DataTypes.SendEndSignal-Arg.
func SendEndSignalArgCodec() ValueCodec[SendEndSignalArg] {
	return compositeValueCodec[SendEndSignalArg, *SendEndSignalArg]()
}

// SendEndSignalResCodec binds MAP-MS-DataTypes.SendEndSignal-Res.
func SendEndSignalResCodec() ValueCodec[SendEndSignalRes] {
	return compositeValueCodec[SendEndSignalRes, *SendEndSignalRes]()
}

// RNCIdCodec binds MAP-MS-DataTypes.RNCId.
func RNCIdCodec() ValueCodec[BERValue[RNCId]] {
	return octetValueCodec[RNCId]("MAP-MS-DataTypes.RNCId", "RNCId", []primitiveRule[RNCId]{{invalid: func(value RNCId) bool { return !(len(value) == 7) }, description: "SIZE (7)", clause: "51.5", length: func(value RNCId) int { return len(value) }}})
}

// RelocationNumberListCodec binds MAP-MS-DataTypes.RelocationNumberList.
func RelocationNumberListCodec() ValueCodec[RelocationNumberList] {
	return pointerValueCodec(UnmarshalBERRelocationNumberList, MarshalBERRelocationNumberList, MarshalDERRelocationNumberList)
}

// MulticallBearerInfoCodec binds MAP-MS-DataTypes.MulticallBearerInfo.
func MulticallBearerInfoCodec() ValueCodec[BERValue[MulticallBearerInfo]] {
	return integerValueCodec[MulticallBearerInfo]("MAP-MS-DataTypes.MulticallBearerInfo", "MulticallBearerInfo", []primitiveRule[MulticallBearerInfo]{{invalid: func(value MulticallBearerInfo) bool { return !(int64(value) >= 1 && int64(value) <= 7) }, description: "(1..7)", clause: "51.4", observed: func(value MulticallBearerInfo) any { return int64(value) }}}, false)
}

// RelocationNumberCodec binds MAP-MS-DataTypes.RelocationNumber.
func RelocationNumberCodec() ValueCodec[RelocationNumber] {
	return compositeValueCodec[RelocationNumber, *RelocationNumber]()
}

// RABIdCodec binds MAP-MS-DataTypes.RAB-Id.
func RABIdCodec() ValueCodec[BERValue[RABId]] {
	return integerValueCodec[RABId]("MAP-MS-DataTypes.RAB-Id", "RAB-Id", []primitiveRule[RABId]{{invalid: func(value RABId) bool { return !(int64(value) >= 1 && int64(value) <= 255) }, description: "(1..255)", clause: "51.4", observed: func(value RABId) any { return int64(value) }}}, false)
}

// RadioResourceInformationCodec binds MAP-MS-DataTypes.RadioResourceInformation.
func RadioResourceInformationCodec() ValueCodec[BERValue[RadioResourceInformation]] {
	return octetValueCodec[RadioResourceInformation]("MAP-MS-DataTypes.RadioResourceInformation", "RadioResourceInformation", []primitiveRule[RadioResourceInformation]{{invalid: func(value RadioResourceInformation) bool { return !(len(value) >= 3 && len(value) <= 13) }, description: "SIZE (3..13)", clause: "51.5", length: func(value RadioResourceInformation) int { return len(value) }}})
}

// IntegrityProtectionInformationCodec binds MAP-MS-DataTypes.IntegrityProtectionInformation.
func IntegrityProtectionInformationCodec() ValueCodec[BERValue[IntegrityProtectionInformation]] {
	return octetValueCodec[IntegrityProtectionInformation]("MAP-MS-DataTypes.IntegrityProtectionInformation", "IntegrityProtectionInformation", []primitiveRule[IntegrityProtectionInformation]{{invalid: func(value IntegrityProtectionInformation) bool { return !(len(value) >= 18 && len(value) <= 100) }, description: "SIZE (18..100)", clause: "51.5", length: func(value IntegrityProtectionInformation) int { return len(value) }}})
}

// EncryptionInformationCodec binds MAP-MS-DataTypes.EncryptionInformation.
func EncryptionInformationCodec() ValueCodec[BERValue[EncryptionInformation]] {
	return octetValueCodec[EncryptionInformation]("MAP-MS-DataTypes.EncryptionInformation", "EncryptionInformation", []primitiveRule[EncryptionInformation]{{invalid: func(value EncryptionInformation) bool { return !(len(value) >= 18 && len(value) <= 100) }, description: "SIZE (18..100)", clause: "51.5", length: func(value EncryptionInformation) int { return len(value) }}})
}

// SendAuthenticationInfoArgCodec binds MAP-MS-DataTypes.SendAuthenticationInfoArg.
func SendAuthenticationInfoArgCodec() ValueCodec[SendAuthenticationInfoArg] {
	return compositeValueCodec[SendAuthenticationInfoArg, *SendAuthenticationInfoArg]()
}

// NumberOfRequestedVectorsCodec binds MAP-MS-DataTypes.NumberOfRequestedVectors.
func NumberOfRequestedVectorsCodec() ValueCodec[BERValue[NumberOfRequestedVectors]] {
	return integerValueCodec[NumberOfRequestedVectors]("MAP-MS-DataTypes.NumberOfRequestedVectors", "NumberOfRequestedVectors", []primitiveRule[NumberOfRequestedVectors]{{invalid: func(value NumberOfRequestedVectors) bool { return !(int64(value) >= 1 && int64(value) <= 5) }, description: "(1..5)", clause: "51.4", observed: func(value NumberOfRequestedVectors) any { return int64(value) }}}, false)
}

// ReSynchronisationInfoCodec binds MAP-MS-DataTypes.Re-synchronisationInfo.
func ReSynchronisationInfoCodec() ValueCodec[ReSynchronisationInfo] {
	return compositeValueCodec[ReSynchronisationInfo, *ReSynchronisationInfo]()
}

// SendAuthenticationInfoResCodec binds MAP-MS-DataTypes.SendAuthenticationInfoRes.
func SendAuthenticationInfoResCodec() ValueCodec[SendAuthenticationInfoRes] {
	return compositeValueCodec[SendAuthenticationInfoRes, *SendAuthenticationInfoRes]()
}

// EPSAuthenticationSetListCodec binds MAP-MS-DataTypes.EPS-AuthenticationSetList.
func EPSAuthenticationSetListCodec() ValueCodec[EPSAuthenticationSetList] {
	return pointerValueCodec(UnmarshalBEREPSAuthenticationSetList, MarshalBEREPSAuthenticationSetList, MarshalDEREPSAuthenticationSetList)
}

// UEUsageTypeCodec binds MAP-MS-DataTypes.UE-UsageType.
func UEUsageTypeCodec() ValueCodec[BERValue[UEUsageType]] {
	return octetValueCodec[UEUsageType]("MAP-MS-DataTypes.UE-UsageType", "UE-UsageType", []primitiveRule[UEUsageType]{{invalid: func(value UEUsageType) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value UEUsageType) int { return len(value) }}})
}

// EPCAVCodec binds MAP-MS-DataTypes.EPC-AV.
func EPCAVCodec() ValueCodec[EPCAV] {
	return compositeValueCodec[EPCAV, *EPCAV]()
}

// KASMECodec binds MAP-MS-DataTypes.KASME.
func KASMECodec() ValueCodec[BERValue[KASME]] {
	return octetValueCodec[KASME]("MAP-MS-DataTypes.KASME", "KASME", []primitiveRule[KASME]{{invalid: func(value KASME) bool { return !(len(value) == 32) }, description: "SIZE (32)", clause: "51.5", length: func(value KASME) int { return len(value) }}})
}

// RequestingNodeTypeCodec binds MAP-MS-DataTypes.RequestingNodeType.
func RequestingNodeTypeCodec() ValueCodec[BERValue[RequestingNodeType]] {
	return integerValueCodec[RequestingNodeType]("MAP-MS-DataTypes.RequestingNodeType", "RequestingNodeType", nil, true)
}

// CheckIMEIArgCodec binds MAP-MS-DataTypes.CheckIMEI-Arg.
func CheckIMEIArgCodec() ValueCodec[CheckIMEIArg] {
	return compositeValueCodec[CheckIMEIArg, *CheckIMEIArg]()
}

// CheckIMEIResCodec binds MAP-MS-DataTypes.CheckIMEI-Res.
func CheckIMEIResCodec() ValueCodec[CheckIMEIRes] {
	return compositeValueCodec[CheckIMEIRes, *CheckIMEIRes]()
}

// RequestedEquipmentInfoCodec binds MAP-MS-DataTypes.RequestedEquipmentInfo.
func RequestedEquipmentInfoCodec() ValueCodec[BERValue[RequestedEquipmentInfo]] {
	return bitValueCodec("MAP-MS-DataTypes.RequestedEquipmentInfo", "RequestedEquipmentInfo", []primitiveRule[RequestedEquipmentInfo]{{invalid: func(value RequestedEquipmentInfo) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value RequestedEquipmentInfo) int { return value.BitLength }, encodedLength: func(value RequestedEquipmentInfo) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// UESBIIuCodec binds MAP-MS-DataTypes.UESBI-Iu.
func UESBIIuCodec() ValueCodec[UESBIIu] {
	return compositeValueCodec[UESBIIu, *UESBIIu]()
}

// UESBIIuACodec binds MAP-MS-DataTypes.UESBI-IuA.
func UESBIIuACodec() ValueCodec[BERValue[UESBIIuA]] {
	return bitValueCodec("MAP-MS-DataTypes.UESBI-IuA", "UESBI-IuA", []primitiveRule[UESBIIuA]{{invalid: func(value UESBIIuA) bool { return !(value.BitLength >= 1 && value.BitLength <= 128) }, description: "SIZE (1..128)", clause: "51.5", length: func(value UESBIIuA) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 1, Max: 128}}})
}

// UESBIIuBCodec binds MAP-MS-DataTypes.UESBI-IuB.
func UESBIIuBCodec() ValueCodec[BERValue[UESBIIuB]] {
	return bitValueCodec("MAP-MS-DataTypes.UESBI-IuB", "UESBI-IuB", []primitiveRule[UESBIIuB]{{invalid: func(value UESBIIuB) bool { return !(value.BitLength >= 1 && value.BitLength <= 128) }, description: "SIZE (1..128)", clause: "51.5", length: func(value UESBIIuB) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 1, Max: 128}}})
}

// EquipmentStatusCodec binds MAP-MS-DataTypes.EquipmentStatus.
func EquipmentStatusCodec() ValueCodec[BERValue[EquipmentStatus]] {
	return integerValueCodec[EquipmentStatus]("MAP-MS-DataTypes.EquipmentStatus", "EquipmentStatus", []primitiveRule[EquipmentStatus]{{invalid: func(value EquipmentStatus) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value EquipmentStatus) any { return int64(value) }}}, true)
}

// InsertSubscriberDataArgCodec binds MAP-MS-DataTypes.InsertSubscriberDataArg.
func InsertSubscriberDataArgCodec() ValueCodec[InsertSubscriberDataArg] {
	return compositeValueCodec[InsertSubscriberDataArg, *InsertSubscriberDataArg]()
}

// EDRXCycleLengthListCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length-List.
func EDRXCycleLengthListCodec() ValueCodec[EDRXCycleLengthList] {
	return pointerValueCodec(UnmarshalBEREDRXCycleLengthList, MarshalBEREDRXCycleLengthList, MarshalDEREDRXCycleLengthList)
}

// EDRXCycleLengthCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length.
func EDRXCycleLengthCodec() ValueCodec[EDRXCycleLength] {
	return compositeValueCodec[EDRXCycleLength, *EDRXCycleLength]()
}

// EDRXCycleLengthValueCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length-Value.
func EDRXCycleLengthValueCodec() ValueCodec[BERValue[EDRXCycleLengthValue]] {
	return octetValueCodec[EDRXCycleLengthValue]("MAP-MS-DataTypes.EDRX-Cycle-Length-Value", "EDRX-Cycle-Length-Value", []primitiveRule[EDRXCycleLengthValue]{{invalid: func(value EDRXCycleLengthValue) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value EDRXCycleLengthValue) int { return len(value) }}})
}

// ResetIdListCodec binds MAP-MS-DataTypes.Reset-Id-List.
func ResetIdListCodec() ValueCodec[ResetIdList] {
	return pointerValueCodec(UnmarshalBERResetIdList, MarshalBERResetIdList, MarshalDERResetIdList)
}

// ResetIdCodec binds MAP-MS-DataTypes.Reset-Id.
func ResetIdCodec() ValueCodec[BERValue[ResetId]] {
	return octetValueCodec[ResetId]("MAP-MS-DataTypes.Reset-Id", "Reset-Id", []primitiveRule[ResetId]{{invalid: func(value ResetId) bool { return !(len(value) >= 1 && len(value) <= 4) }, description: "SIZE (1..4)", clause: "51.5", length: func(value ResetId) int { return len(value) }}})
}

// DLBufferingSuggestedPacketCountCodec binds MAP-MS-DataTypes.DL-Buffering-Suggested-Packet-Count.
func DLBufferingSuggestedPacketCountCodec() ValueCodec[BERValue[DLBufferingSuggestedPacketCount]] {
	return integerValueCodec[DLBufferingSuggestedPacketCount]("MAP-MS-DataTypes.DL-Buffering-Suggested-Packet-Count", "DL-Buffering-Suggested-Packet-Count", []primitiveRule[DLBufferingSuggestedPacketCount]{{invalid: func(value DLBufferingSuggestedPacketCount) bool {
		return !(int64(value) >= -1 && int64(value) <= 2147483647)
	}, description: "(-1..2147483647)", clause: "51.4", observed: func(value DLBufferingSuggestedPacketCount) any { return int64(value) }}}, false)
}

// GroupServiceIDCodec binds MAP-MS-DataTypes.Group-Service-ID.
func GroupServiceIDCodec() ValueCodec[BERValue[GroupServiceID]] {
	return integerValueCodec[GroupServiceID]("MAP-MS-DataTypes.Group-Service-ID", "Group-Service-ID", []primitiveRule[GroupServiceID]{{invalid: func(value GroupServiceID) bool { return !(int64(value) >= 0 && int64(value) <= 4294967295) }, description: "(0..4294967295)", clause: "51.4", observed: func(value GroupServiceID) any { return int64(value) }}}, false)
}

// LocalGroupIDCodec binds MAP-MS-DataTypes.Local-GroupID.
func LocalGroupIDCodec() ValueCodec[BERValue[LocalGroupID]] {
	return octetValueCodec[LocalGroupID]("MAP-MS-DataTypes.Local-GroupID", "Local-GroupID", []primitiveRule[LocalGroupID]{{invalid: func(value LocalGroupID) bool { return !(len(value) >= 1 && len(value) <= 10) }, description: "SIZE (1..10)", clause: "51.5", length: func(value LocalGroupID) int { return len(value) }}})
}

// IMSIGroupIdListCodec binds MAP-MS-DataTypes.IMSI-GroupIdList.
func IMSIGroupIdListCodec() ValueCodec[IMSIGroupIdList] {
	return pointerValueCodec(UnmarshalBERIMSIGroupIdList, MarshalBERIMSIGroupIdList, MarshalDERIMSIGroupIdList)
}

// IMSIGroupIdCodec binds MAP-MS-DataTypes.IMSI-GroupId.
func IMSIGroupIdCodec() ValueCodec[IMSIGroupId] {
	return compositeValueCodec[IMSIGroupId, *IMSIGroupId]()
}

// SubscribedPeriodicRAUTAUtimerCodec binds MAP-MS-DataTypes.SubscribedPeriodicRAUTAUtimer.
func SubscribedPeriodicRAUTAUtimerCodec() ValueCodec[BERValue[SubscribedPeriodicRAUTAUtimer]] {
	return integerValueCodec[SubscribedPeriodicRAUTAUtimer]("MAP-MS-DataTypes.SubscribedPeriodicRAUTAUtimer", "SubscribedPeriodicRAUTAUtimer", []primitiveRule[SubscribedPeriodicRAUTAUtimer]{{invalid: func(value SubscribedPeriodicRAUTAUtimer) bool {
		return !(int64(value) >= 0 && int64(value) <= 4294967295)
	}, description: "(0..4294967295)", clause: "51.4", observed: func(value SubscribedPeriodicRAUTAUtimer) any { return int64(value) }}}, false)
}

// SubscribedPeriodicLAUtimerCodec binds MAP-MS-DataTypes.SubscribedPeriodicLAUtimer.
func SubscribedPeriodicLAUtimerCodec() ValueCodec[BERValue[SubscribedPeriodicLAUtimer]] {
	return integerValueCodec[SubscribedPeriodicLAUtimer]("MAP-MS-DataTypes.SubscribedPeriodicLAUtimer", "SubscribedPeriodicLAUtimer", []primitiveRule[SubscribedPeriodicLAUtimer]{{invalid: func(value SubscribedPeriodicLAUtimer) bool { return !(int64(value) >= 0 && int64(value) <= 4294967295) }, description: "(0..4294967295)", clause: "51.4", observed: func(value SubscribedPeriodicLAUtimer) any { return int64(value) }}}, false)
}

// CSGSubscriptionDataListCodec binds MAP-MS-DataTypes.CSG-SubscriptionDataList.
func CSGSubscriptionDataListCodec() ValueCodec[CSGSubscriptionDataList] {
	return pointerValueCodec(UnmarshalBERCSGSubscriptionDataList, MarshalBERCSGSubscriptionDataList, MarshalDERCSGSubscriptionDataList)
}

// CSGSubscriptionDataCodec binds MAP-MS-DataTypes.CSG-SubscriptionData.
func CSGSubscriptionDataCodec() ValueCodec[CSGSubscriptionData] {
	return compositeValueCodec[CSGSubscriptionData, *CSGSubscriptionData]()
}

// VPLMNCSGSubscriptionDataListCodec binds MAP-MS-DataTypes.VPLMN-CSG-SubscriptionDataList.
func VPLMNCSGSubscriptionDataListCodec() ValueCodec[VPLMNCSGSubscriptionDataList] {
	return pointerValueCodec(UnmarshalBERVPLMNCSGSubscriptionDataList, MarshalBERVPLMNCSGSubscriptionDataList, MarshalDERVPLMNCSGSubscriptionDataList)
}

// CSGIdCodec binds MAP-MS-DataTypes.CSG-Id.
func CSGIdCodec() ValueCodec[BERValue[CSGId]] {
	return bitValueCodec("MAP-MS-DataTypes.CSG-Id", "CSG-Id", []primitiveRule[CSGId]{{invalid: func(value CSGId) bool { return !(value.BitLength == 27) }, description: "SIZE (27)", clause: "51.5", length: func(value CSGId) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 27, Max: 27}}})
}

// LIPAAllowedAPNListCodec binds MAP-MS-DataTypes.LIPA-AllowedAPNList.
func LIPAAllowedAPNListCodec() ValueCodec[LIPAAllowedAPNList] {
	return pointerValueCodec(UnmarshalBERLIPAAllowedAPNList, MarshalBERLIPAAllowedAPNList, MarshalDERLIPAAllowedAPNList)
}

// EPSSubscriptionDataCodec binds MAP-MS-DataTypes.EPS-SubscriptionData.
func EPSSubscriptionDataCodec() ValueCodec[EPSSubscriptionData] {
	return compositeValueCodec[EPSSubscriptionData, *EPSSubscriptionData]()
}

// APNOIReplacementCodec binds MAP-MS-DataTypes.APN-OI-Replacement.
func APNOIReplacementCodec() ValueCodec[BERValue[APNOIReplacement]] {
	return octetValueCodec[APNOIReplacement]("MAP-MS-DataTypes.APN-OI-Replacement", "APN-OI-Replacement", []primitiveRule[APNOIReplacement]{{invalid: func(value APNOIReplacement) bool { return !(len(value) >= 9 && len(value) <= 100) }, description: "SIZE (9..100)", clause: "51.5", length: func(value APNOIReplacement) int { return len(value) }}})
}

// RFSPIDCodec binds MAP-MS-DataTypes.RFSP-ID.
func RFSPIDCodec() ValueCodec[BERValue[RFSPID]] {
	return integerValueCodec[RFSPID]("MAP-MS-DataTypes.RFSP-ID", "RFSP-ID", []primitiveRule[RFSPID]{{invalid: func(value RFSPID) bool { return !(int64(value) >= 1 && int64(value) <= 256) }, description: "(1..256)", clause: "51.4", observed: func(value RFSPID) any { return int64(value) }}}, false)
}

// APNConfigurationProfileCodec binds MAP-MS-DataTypes.APN-ConfigurationProfile.
func APNConfigurationProfileCodec() ValueCodec[APNConfigurationProfile] {
	return compositeValueCodec[APNConfigurationProfile, *APNConfigurationProfile]()
}

// EPSDataListCodec binds MAP-MS-DataTypes.EPS-DataList.
func EPSDataListCodec() ValueCodec[EPSDataList] {
	return pointerValueCodec(UnmarshalBEREPSDataList, MarshalBEREPSDataList, MarshalDEREPSDataList)
}

// APNConfigurationCodec binds MAP-MS-DataTypes.APN-Configuration.
func APNConfigurationCodec() ValueCodec[APNConfiguration] {
	return compositeValueCodec[APNConfiguration, *APNConfiguration]()
}

// PDNConnectionContinuityCodec binds MAP-MS-DataTypes.PDN-ConnectionContinuity.
func PDNConnectionContinuityCodec() ValueCodec[BERValue[PDNConnectionContinuity]] {
	return integerValueCodec[PDNConnectionContinuity]("MAP-MS-DataTypes.PDN-ConnectionContinuity", "PDN-ConnectionContinuity", []primitiveRule[PDNConnectionContinuity]{{invalid: func(value PDNConnectionContinuity) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value PDNConnectionContinuity) any { return int64(value) }}}, true)
}

// NIDDMechanismCodec binds MAP-MS-DataTypes.NIDD-Mechanism.
func NIDDMechanismCodec() ValueCodec[BERValue[NIDDMechanism]] {
	return integerValueCodec[NIDDMechanism]("MAP-MS-DataTypes.NIDD-Mechanism", "NIDD-Mechanism", []primitiveRule[NIDDMechanism]{{invalid: func(value NIDDMechanism) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value NIDDMechanism) any { return int64(value) }}}, true)
}

// PDNTypeCodec binds MAP-MS-DataTypes.PDN-Type.
func PDNTypeCodec() ValueCodec[BERValue[PDNType]] {
	return octetValueCodec[PDNType]("MAP-MS-DataTypes.PDN-Type", "PDN-Type", []primitiveRule[PDNType]{{invalid: func(value PDNType) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value PDNType) int { return len(value) }}})
}

// EPSQoSSubscribedCodec binds MAP-MS-DataTypes.EPS-QoS-Subscribed.
func EPSQoSSubscribedCodec() ValueCodec[EPSQoSSubscribed] {
	return compositeValueCodec[EPSQoSSubscribed, *EPSQoSSubscribed]()
}

// AMBRCodec binds MAP-MS-DataTypes.AMBR.
func AMBRCodec() ValueCodec[AMBR] {
	return compositeValueCodec[AMBR, *AMBR]()
}

// SpecificAPNInfoListCodec binds MAP-MS-DataTypes.SpecificAPNInfoList.
func SpecificAPNInfoListCodec() ValueCodec[SpecificAPNInfoList] {
	return pointerValueCodec(UnmarshalBERSpecificAPNInfoList, MarshalBERSpecificAPNInfoList, MarshalDERSpecificAPNInfoList)
}

// SpecificAPNInfoCodec binds MAP-MS-DataTypes.SpecificAPNInfo.
func SpecificAPNInfoCodec() ValueCodec[SpecificAPNInfo] {
	return compositeValueCodec[SpecificAPNInfo, *SpecificAPNInfo]()
}

// BandwidthCodec binds MAP-MS-DataTypes.Bandwidth.
func BandwidthCodec() ValueCodec[BERValue[Bandwidth]] {
	return bigIntegerValueCodec("MAP-MS-DataTypes.Bandwidth", "Bandwidth")
}

// BandwidthExtCodec binds MAP-MS-DataTypes.BandwidthExt.
func BandwidthExtCodec() ValueCodec[BERValue[BandwidthExt]] {
	return bigIntegerValueCodec("MAP-MS-DataTypes.BandwidthExt", "BandwidthExt")
}

// QoSClassIdentifierCodec binds MAP-MS-DataTypes.QoS-Class-Identifier.
func QoSClassIdentifierCodec() ValueCodec[BERValue[QoSClassIdentifier]] {
	return integerValueCodec[QoSClassIdentifier]("MAP-MS-DataTypes.QoS-Class-Identifier", "QoS-Class-Identifier", []primitiveRule[QoSClassIdentifier]{{invalid: func(value QoSClassIdentifier) bool { return !(int64(value) >= 1 && int64(value) <= 9) }, description: "(1..9)", clause: "51.4", observed: func(value QoSClassIdentifier) any { return int64(value) }}}, false)
}

// AllocationRetentionPriorityCodec binds MAP-MS-DataTypes.Allocation-Retention-Priority.
func AllocationRetentionPriorityCodec() ValueCodec[AllocationRetentionPriority] {
	return compositeValueCodec[AllocationRetentionPriority, *AllocationRetentionPriority]()
}

// PDNGWIdentityCodec binds MAP-MS-DataTypes.PDN-GW-Identity.
func PDNGWIdentityCodec() ValueCodec[PDNGWIdentity] {
	return compositeValueCodec[PDNGWIdentity, *PDNGWIdentity]()
}

// FQDNCodec binds MAP-MS-DataTypes.FQDN.
func FQDNCodec() ValueCodec[BERValue[FQDN]] {
	return octetValueCodec[FQDN]("MAP-MS-DataTypes.FQDN", "FQDN", []primitiveRule[FQDN]{{invalid: func(value FQDN) bool { return !(len(value) >= 9 && len(value) <= 255) }, description: "SIZE (9..255)", clause: "51.5", length: func(value FQDN) int { return len(value) }}})
}

// PDNGWAllocationTypeCodec binds MAP-MS-DataTypes.PDN-GW-AllocationType.
func PDNGWAllocationTypeCodec() ValueCodec[BERValue[PDNGWAllocationType]] {
	return integerValueCodec[PDNGWAllocationType]("MAP-MS-DataTypes.PDN-GW-AllocationType", "PDN-GW-AllocationType", []primitiveRule[PDNGWAllocationType]{{invalid: func(value PDNGWAllocationType) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value PDNGWAllocationType) any { return int64(value) }}}, true)
}

// WLANOffloadabilityCodec binds MAP-MS-DataTypes.WLAN-Offloadability.
func WLANOffloadabilityCodec() ValueCodec[WLANOffloadability] {
	return compositeValueCodec[WLANOffloadability, *WLANOffloadability]()
}

// WLANOffloadabilityIndicationCodec binds MAP-MS-DataTypes.WLAN-Offloadability-Indication.
func WLANOffloadabilityIndicationCodec() ValueCodec[BERValue[WLANOffloadabilityIndication]] {
	return integerValueCodec[WLANOffloadabilityIndication]("MAP-MS-DataTypes.WLAN-Offloadability-Indication", "WLAN-Offloadability-Indication", []primitiveRule[WLANOffloadabilityIndication]{{invalid: func(value WLANOffloadabilityIndication) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value WLANOffloadabilityIndication) any { return int64(value) }}}, true)
}

// AccessRestrictionDataCodec binds MAP-MS-DataTypes.AccessRestrictionData.
func AccessRestrictionDataCodec() ValueCodec[BERValue[AccessRestrictionData]] {
	return bitValueCodec("MAP-MS-DataTypes.AccessRestrictionData", "AccessRestrictionData", []primitiveRule[AccessRestrictionData]{{invalid: func(value AccessRestrictionData) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value AccessRestrictionData) int { return value.BitLength }, encodedLength: func(value AccessRestrictionData) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// ExtAccessRestrictionDataCodec binds MAP-MS-DataTypes.Ext-AccessRestrictionData.
func ExtAccessRestrictionDataCodec() ValueCodec[BERValue[ExtAccessRestrictionData]] {
	return bitValueCodec("MAP-MS-DataTypes.Ext-AccessRestrictionData", "Ext-AccessRestrictionData", []primitiveRule[ExtAccessRestrictionData]{{invalid: func(value ExtAccessRestrictionData) bool { return !(value.BitLength >= 1 && value.BitLength <= 32) }, description: "SIZE (1..32)", clause: "51.5", length: func(value ExtAccessRestrictionData) int { return value.BitLength }, encodedLength: func(value ExtAccessRestrictionData) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 32}}})
}

// AdjacentAccessRestrictionDataListCodec binds MAP-MS-DataTypes.AdjacentAccessRestrictionDataList.
func AdjacentAccessRestrictionDataListCodec() ValueCodec[AdjacentAccessRestrictionDataList] {
	return pointerValueCodec(UnmarshalBERAdjacentAccessRestrictionDataList, MarshalBERAdjacentAccessRestrictionDataList, MarshalDERAdjacentAccessRestrictionDataList)
}

// AdjacentAccessRestrictionDataCodec binds MAP-MS-DataTypes.AdjacentAccessRestrictionData.
func AdjacentAccessRestrictionDataCodec() ValueCodec[AdjacentAccessRestrictionData] {
	return compositeValueCodec[AdjacentAccessRestrictionData, *AdjacentAccessRestrictionData]()
}

// CSAllocationRetentionPriorityCodec binds MAP-MS-DataTypes.CS-AllocationRetentionPriority.
func CSAllocationRetentionPriorityCodec() ValueCodec[BERValue[CSAllocationRetentionPriority]] {
	return octetValueCodec[CSAllocationRetentionPriority]("MAP-MS-DataTypes.CS-AllocationRetentionPriority", "CS-AllocationRetentionPriority", []primitiveRule[CSAllocationRetentionPriority]{{invalid: func(value CSAllocationRetentionPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value CSAllocationRetentionPriority) int { return len(value) }}})
}

// ISTAlertTimerValueCodec binds MAP-MS-DataTypes.IST-AlertTimerValue.
func ISTAlertTimerValueCodec() ValueCodec[BERValue[ISTAlertTimerValue]] {
	return integerValueCodec[ISTAlertTimerValue]("MAP-MS-DataTypes.IST-AlertTimerValue", "IST-AlertTimerValue", []primitiveRule[ISTAlertTimerValue]{{invalid: func(value ISTAlertTimerValue) bool { return !(int64(value) >= 15 && int64(value) <= 255) }, description: "(15..255)", clause: "51.4", observed: func(value ISTAlertTimerValue) any { return int64(value) }}}, false)
}

// LCSInformationCodec binds MAP-MS-DataTypes.LCSInformation.
func LCSInformationCodec() ValueCodec[LCSInformation] {
	return compositeValueCodec[LCSInformation, *LCSInformation]()
}

// GMLCListCodec binds MAP-MS-DataTypes.GMLC-List.
func GMLCListCodec() ValueCodec[GMLCList] {
	return pointerValueCodec(UnmarshalBERGMLCList, MarshalBERGMLCList, MarshalDERGMLCList)
}

// NetworkAccessModeCodec binds MAP-MS-DataTypes.NetworkAccessMode.
func NetworkAccessModeCodec() ValueCodec[BERValue[NetworkAccessMode]] {
	return integerValueCodec[NetworkAccessMode]("MAP-MS-DataTypes.NetworkAccessMode", "NetworkAccessMode", nil, true)
}

// GPRSDataListCodec binds MAP-MS-DataTypes.GPRSDataList.
func GPRSDataListCodec() ValueCodec[GPRSDataList] {
	return pointerValueCodec(UnmarshalBERGPRSDataList, MarshalBERGPRSDataList, MarshalDERGPRSDataList)
}

// PDPContextCodec binds MAP-MS-DataTypes.PDP-Context.
func PDPContextCodec() ValueCodec[PDPContext] {
	return compositeValueCodec[PDPContext, *PDPContext]()
}

// RestorationPriorityCodec binds MAP-MS-DataTypes.Restoration-Priority.
func RestorationPriorityCodec() ValueCodec[BERValue[RestorationPriority]] {
	return octetValueCodec[RestorationPriority]("MAP-MS-DataTypes.Restoration-Priority", "Restoration-Priority", []primitiveRule[RestorationPriority]{{invalid: func(value RestorationPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value RestorationPriority) int { return len(value) }}})
}

// SIPTOPermissionCodec binds MAP-MS-DataTypes.SIPTO-Permission.
func SIPTOPermissionCodec() ValueCodec[BERValue[SIPTOPermission]] {
	return integerValueCodec[SIPTOPermission]("MAP-MS-DataTypes.SIPTO-Permission", "SIPTO-Permission", []primitiveRule[SIPTOPermission]{{invalid: func(value SIPTOPermission) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SIPTOPermission) any { return int64(value) }}}, true)
}

// SIPTOLocalNetworkPermissionCodec binds MAP-MS-DataTypes.SIPTO-Local-Network-Permission.
func SIPTOLocalNetworkPermissionCodec() ValueCodec[BERValue[SIPTOLocalNetworkPermission]] {
	return integerValueCodec[SIPTOLocalNetworkPermission]("MAP-MS-DataTypes.SIPTO-Local-Network-Permission", "SIPTO-Local-Network-Permission", []primitiveRule[SIPTOLocalNetworkPermission]{{invalid: func(value SIPTOLocalNetworkPermission) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SIPTOLocalNetworkPermission) any { return int64(value) }}}, true)
}

// LIPAPermissionCodec binds MAP-MS-DataTypes.LIPA-Permission.
func LIPAPermissionCodec() ValueCodec[BERValue[LIPAPermission]] {
	return integerValueCodec[LIPAPermission]("MAP-MS-DataTypes.LIPA-Permission", "LIPA-Permission", []primitiveRule[LIPAPermission]{{invalid: func(value LIPAPermission) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value LIPAPermission) any { return int64(value) }}}, true)
}

// ContextIdCodec binds MAP-MS-DataTypes.ContextId.
func ContextIdCodec() ValueCodec[BERValue[ContextId]] {
	return integerValueCodec[ContextId]("MAP-MS-DataTypes.ContextId", "ContextId", []primitiveRule[ContextId]{{invalid: func(value ContextId) bool { return !(int64(value) >= 1 && int64(value) <= 50) }, description: "(1..50)", clause: "51.4", observed: func(value ContextId) any { return int64(value) }}}, false)
}

// GPRSSubscriptionDataCodec binds MAP-MS-DataTypes.GPRSSubscriptionData.
func GPRSSubscriptionDataCodec() ValueCodec[GPRSSubscriptionData] {
	return compositeValueCodec[GPRSSubscriptionData, *GPRSSubscriptionData]()
}

// SGSNCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.SGSN-CAMEL-SubscriptionInfo.
func SGSNCAMELSubscriptionInfoCodec() ValueCodec[SGSNCAMELSubscriptionInfo] {
	return compositeValueCodec[SGSNCAMELSubscriptionInfo, *SGSNCAMELSubscriptionInfo]()
}

// GPRSCSICodec binds MAP-MS-DataTypes.GPRS-CSI.
func GPRSCSICodec() ValueCodec[GPRSCSI] {
	return compositeValueCodec[GPRSCSI, *GPRSCSI]()
}

// GPRSCamelTDPDataListCodec binds MAP-MS-DataTypes.GPRS-CamelTDPDataList.
func GPRSCamelTDPDataListCodec() ValueCodec[GPRSCamelTDPDataList] {
	return pointerValueCodec(UnmarshalBERGPRSCamelTDPDataList, MarshalBERGPRSCamelTDPDataList, MarshalDERGPRSCamelTDPDataList)
}

// GPRSCamelTDPDataCodec binds MAP-MS-DataTypes.GPRS-CamelTDPData.
func GPRSCamelTDPDataCodec() ValueCodec[GPRSCamelTDPData] {
	return compositeValueCodec[GPRSCamelTDPData, *GPRSCamelTDPData]()
}

// DefaultGPRSHandlingCodec binds MAP-MS-DataTypes.DefaultGPRS-Handling.
func DefaultGPRSHandlingCodec() ValueCodec[BERValue[DefaultGPRSHandling]] {
	return integerValueCodec[DefaultGPRSHandling]("MAP-MS-DataTypes.DefaultGPRS-Handling", "DefaultGPRS-Handling", nil, true)
}

// GPRSTriggerDetectionPointCodec binds MAP-MS-DataTypes.GPRS-TriggerDetectionPoint.
func GPRSTriggerDetectionPointCodec() ValueCodec[BERValue[GPRSTriggerDetectionPoint]] {
	return integerValueCodec[GPRSTriggerDetectionPoint]("MAP-MS-DataTypes.GPRS-TriggerDetectionPoint", "GPRS-TriggerDetectionPoint", nil, true)
}

// APNCodec binds MAP-MS-DataTypes.APN.
func APNCodec() ValueCodec[BERValue[APN]] {
	return octetValueCodec[APN]("MAP-MS-DataTypes.APN", "APN", []primitiveRule[APN]{{invalid: func(value APN) bool { return !(len(value) >= 2 && len(value) <= 63) }, description: "SIZE (2..63)", clause: "51.5", length: func(value APN) int { return len(value) }}})
}

// PDPTypeCodec binds MAP-MS-DataTypes.PDP-Type.
func PDPTypeCodec() ValueCodec[BERValue[PDPType]] {
	return octetValueCodec[PDPType]("MAP-MS-DataTypes.PDP-Type", "PDP-Type", []primitiveRule[PDPType]{{invalid: func(value PDPType) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value PDPType) int { return len(value) }}})
}

// ExtPDPTypeCodec binds MAP-MS-DataTypes.Ext-PDP-Type.
func ExtPDPTypeCodec() ValueCodec[BERValue[ExtPDPType]] {
	return octetValueCodec[ExtPDPType]("MAP-MS-DataTypes.Ext-PDP-Type", "Ext-PDP-Type", []primitiveRule[ExtPDPType]{{invalid: func(value ExtPDPType) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value ExtPDPType) int { return len(value) }}})
}

// PDPAddressCodec binds MAP-MS-DataTypes.PDP-Address.
func PDPAddressCodec() ValueCodec[BERValue[PDPAddress]] {
	return octetValueCodec[PDPAddress]("MAP-MS-DataTypes.PDP-Address", "PDP-Address", []primitiveRule[PDPAddress]{{invalid: func(value PDPAddress) bool { return !(len(value) >= 1 && len(value) <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value PDPAddress) int { return len(value) }}})
}

// QoSSubscribedCodec binds MAP-MS-DataTypes.QoS-Subscribed.
func QoSSubscribedCodec() ValueCodec[BERValue[QoSSubscribed]] {
	return octetValueCodec[QoSSubscribed]("MAP-MS-DataTypes.QoS-Subscribed", "QoS-Subscribed", []primitiveRule[QoSSubscribed]{{invalid: func(value QoSSubscribed) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value QoSSubscribed) int { return len(value) }}})
}

// ExtQoSSubscribedCodec binds MAP-MS-DataTypes.Ext-QoS-Subscribed.
func ExtQoSSubscribedCodec() ValueCodec[BERValue[ExtQoSSubscribed]] {
	return octetValueCodec[ExtQoSSubscribed]("MAP-MS-DataTypes.Ext-QoS-Subscribed", "Ext-QoS-Subscribed", []primitiveRule[ExtQoSSubscribed]{{invalid: func(value ExtQoSSubscribed) bool { return !(len(value) >= 1 && len(value) <= 9) }, description: "SIZE (1..9)", clause: "51.5", length: func(value ExtQoSSubscribed) int { return len(value) }}})
}

// Ext2QoSSubscribedCodec binds MAP-MS-DataTypes.Ext2-QoS-Subscribed.
func Ext2QoSSubscribedCodec() ValueCodec[BERValue[Ext2QoSSubscribed]] {
	return octetValueCodec[Ext2QoSSubscribed]("MAP-MS-DataTypes.Ext2-QoS-Subscribed", "Ext2-QoS-Subscribed", []primitiveRule[Ext2QoSSubscribed]{{invalid: func(value Ext2QoSSubscribed) bool { return !(len(value) >= 1 && len(value) <= 3) }, description: "SIZE (1..3)", clause: "51.5", length: func(value Ext2QoSSubscribed) int { return len(value) }}})
}

// Ext3QoSSubscribedCodec binds MAP-MS-DataTypes.Ext3-QoS-Subscribed.
func Ext3QoSSubscribedCodec() ValueCodec[BERValue[Ext3QoSSubscribed]] {
	return octetValueCodec[Ext3QoSSubscribed]("MAP-MS-DataTypes.Ext3-QoS-Subscribed", "Ext3-QoS-Subscribed", []primitiveRule[Ext3QoSSubscribed]{{invalid: func(value Ext3QoSSubscribed) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value Ext3QoSSubscribed) int { return len(value) }}})
}

// Ext4QoSSubscribedCodec binds MAP-MS-DataTypes.Ext4-QoS-Subscribed.
func Ext4QoSSubscribedCodec() ValueCodec[BERValue[Ext4QoSSubscribed]] {
	return octetValueCodec[Ext4QoSSubscribed]("MAP-MS-DataTypes.Ext4-QoS-Subscribed", "Ext4-QoS-Subscribed", []primitiveRule[Ext4QoSSubscribed]{{invalid: func(value Ext4QoSSubscribed) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value Ext4QoSSubscribed) int { return len(value) }}})
}

// ChargingCharacteristicsCodec binds MAP-MS-DataTypes.ChargingCharacteristics.
func ChargingCharacteristicsCodec() ValueCodec[BERValue[ChargingCharacteristics]] {
	return octetValueCodec[ChargingCharacteristics]("MAP-MS-DataTypes.ChargingCharacteristics", "ChargingCharacteristics", []primitiveRule[ChargingCharacteristics]{{invalid: func(value ChargingCharacteristics) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value ChargingCharacteristics) int { return len(value) }}})
}

// LSAOnlyAccessIndicatorCodec binds MAP-MS-DataTypes.LSAOnlyAccessIndicator.
func LSAOnlyAccessIndicatorCodec() ValueCodec[BERValue[LSAOnlyAccessIndicator]] {
	return integerValueCodec[LSAOnlyAccessIndicator]("MAP-MS-DataTypes.LSAOnlyAccessIndicator", "LSAOnlyAccessIndicator", []primitiveRule[LSAOnlyAccessIndicator]{{invalid: func(value LSAOnlyAccessIndicator) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value LSAOnlyAccessIndicator) any { return int64(value) }}}, true)
}

// LSADataListCodec binds MAP-MS-DataTypes.LSADataList.
func LSADataListCodec() ValueCodec[LSADataList] {
	return pointerValueCodec(UnmarshalBERLSADataList, MarshalBERLSADataList, MarshalDERLSADataList)
}

// LSADataCodec binds MAP-MS-DataTypes.LSAData.
func LSADataCodec() ValueCodec[LSAData] {
	return compositeValueCodec[LSAData, *LSAData]()
}

// LSAInformationCodec binds MAP-MS-DataTypes.LSAInformation.
func LSAInformationCodec() ValueCodec[LSAInformation] {
	return compositeValueCodec[LSAInformation, *LSAInformation]()
}

// LSAIdentityCodec binds MAP-MS-DataTypes.LSAIdentity.
func LSAIdentityCodec() ValueCodec[BERValue[LSAIdentity]] {
	return octetValueCodec[LSAIdentity]("MAP-MS-DataTypes.LSAIdentity", "LSAIdentity", []primitiveRule[LSAIdentity]{{invalid: func(value LSAIdentity) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value LSAIdentity) int { return len(value) }}})
}

// LSAAttributesCodec binds MAP-MS-DataTypes.LSAAttributes.
func LSAAttributesCodec() ValueCodec[BERValue[LSAAttributes]] {
	return octetValueCodec[LSAAttributes]("MAP-MS-DataTypes.LSAAttributes", "LSAAttributes", []primitiveRule[LSAAttributes]{{invalid: func(value LSAAttributes) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value LSAAttributes) int { return len(value) }}})
}

// SubscriberDataCodec binds MAP-MS-DataTypes.SubscriberData.
func SubscriberDataCodec() ValueCodec[SubscriberData] {
	return compositeValueCodec[SubscriberData, *SubscriberData]()
}

// CategoryCodec binds MAP-MS-DataTypes.Category.
func CategoryCodec() ValueCodec[BERValue[Category]] {
	return octetValueCodec[Category]("MAP-MS-DataTypes.Category", "Category", []primitiveRule[Category]{{invalid: func(value Category) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value Category) int { return len(value) }}})
}

// SubscriberStatusCodec binds MAP-MS-DataTypes.SubscriberStatus.
func SubscriberStatusCodec() ValueCodec[BERValue[SubscriberStatus]] {
	return integerValueCodec[SubscriberStatus]("MAP-MS-DataTypes.SubscriberStatus", "SubscriberStatus", []primitiveRule[SubscriberStatus]{{invalid: func(value SubscriberStatus) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SubscriberStatus) any { return int64(value) }}}, true)
}

// BearerServiceListCodec binds MAP-MS-DataTypes.BearerServiceList.
func BearerServiceListCodec() ValueCodec[BearerServiceList] {
	return pointerValueCodec(UnmarshalBERBearerServiceList, MarshalBERBearerServiceList, MarshalDERBearerServiceList)
}

// TeleserviceListCodec binds MAP-MS-DataTypes.TeleserviceList.
func TeleserviceListCodec() ValueCodec[TeleserviceList] {
	return pointerValueCodec(UnmarshalBERTeleserviceList, MarshalBERTeleserviceList, MarshalDERTeleserviceList)
}

// ODBDataCodec binds MAP-MS-DataTypes.ODB-Data.
func ODBDataCodec() ValueCodec[ODBData] {
	return compositeValueCodec[ODBData, *ODBData]()
}

// ODBGeneralDataCodec binds MAP-MS-DataTypes.ODB-GeneralData.
func ODBGeneralDataCodec() ValueCodec[BERValue[ODBGeneralData]] {
	return bitValueCodec("MAP-MS-DataTypes.ODB-GeneralData", "ODB-GeneralData", []primitiveRule[ODBGeneralData]{{invalid: func(value ODBGeneralData) bool { return !(value.BitLength >= 15 && value.BitLength <= 32) }, description: "SIZE (15..32)", clause: "51.5", length: func(value ODBGeneralData) int { return value.BitLength }, encodedLength: func(value ODBGeneralData) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 15, Max: 32}}})
}

// ODBHPLMNDataCodec binds MAP-MS-DataTypes.ODB-HPLMN-Data.
func ODBHPLMNDataCodec() ValueCodec[BERValue[ODBHPLMNData]] {
	return bitValueCodec("MAP-MS-DataTypes.ODB-HPLMN-Data", "ODB-HPLMN-Data", []primitiveRule[ODBHPLMNData]{{invalid: func(value ODBHPLMNData) bool { return !(value.BitLength >= 4 && value.BitLength <= 32) }, description: "SIZE (4..32)", clause: "51.5", length: func(value ODBHPLMNData) int { return value.BitLength }, encodedLength: func(value ODBHPLMNData) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 32}}})
}

// ExtSSInfoListCodec binds MAP-MS-DataTypes.Ext-SS-InfoList.
func ExtSSInfoListCodec() ValueCodec[ExtSSInfoList] {
	return pointerValueCodec(UnmarshalBERExtSSInfoList, MarshalBERExtSSInfoList, MarshalDERExtSSInfoList)
}

// ExtSSInfoCodec binds MAP-MS-DataTypes.Ext-SS-Info.
func ExtSSInfoCodec() ValueCodec[ExtSSInfo] {
	return compositeValueCodec[ExtSSInfo, *ExtSSInfo]()
}

// ExtForwInfoCodec binds MAP-MS-DataTypes.Ext-ForwInfo.
func ExtForwInfoCodec() ValueCodec[ExtForwInfo] {
	return compositeValueCodec[ExtForwInfo, *ExtForwInfo]()
}

// ExtForwFeatureListCodec binds MAP-MS-DataTypes.Ext-ForwFeatureList.
func ExtForwFeatureListCodec() ValueCodec[ExtForwFeatureList] {
	return pointerValueCodec(UnmarshalBERExtForwFeatureList, MarshalBERExtForwFeatureList, MarshalDERExtForwFeatureList)
}

// ExtForwFeatureCodec binds MAP-MS-DataTypes.Ext-ForwFeature.
func ExtForwFeatureCodec() ValueCodec[ExtForwFeature] {
	return compositeValueCodec[ExtForwFeature, *ExtForwFeature]()
}

// ExtForwOptionsCodec binds MAP-MS-DataTypes.Ext-ForwOptions.
func ExtForwOptionsCodec() ValueCodec[BERValue[ExtForwOptions]] {
	return octetValueCodec[ExtForwOptions]("MAP-MS-DataTypes.Ext-ForwOptions", "Ext-ForwOptions", []primitiveRule[ExtForwOptions]{{invalid: func(value ExtForwOptions) bool { return !(len(value) >= 1 && len(value) <= 5) }, description: "SIZE (1..5)", clause: "51.5", length: func(value ExtForwOptions) int { return len(value) }}})
}

// ExtNoRepCondTimeCodec binds MAP-MS-DataTypes.Ext-NoRepCondTime.
func ExtNoRepCondTimeCodec() ValueCodec[BERValue[ExtNoRepCondTime]] {
	return integerValueCodec[ExtNoRepCondTime]("MAP-MS-DataTypes.Ext-NoRepCondTime", "Ext-NoRepCondTime", []primitiveRule[ExtNoRepCondTime]{{invalid: func(value ExtNoRepCondTime) bool { return !(int64(value) >= 1 && int64(value) <= 100) }, description: "(1..100)", clause: "51.4", observed: func(value ExtNoRepCondTime) any { return int64(value) }}}, false)
}

// ExtCallBarInfoCodec binds MAP-MS-DataTypes.Ext-CallBarInfo.
func ExtCallBarInfoCodec() ValueCodec[ExtCallBarInfo] {
	return compositeValueCodec[ExtCallBarInfo, *ExtCallBarInfo]()
}

// ExtCallBarFeatureListCodec binds MAP-MS-DataTypes.Ext-CallBarFeatureList.
func ExtCallBarFeatureListCodec() ValueCodec[ExtCallBarFeatureList] {
	return pointerValueCodec(UnmarshalBERExtCallBarFeatureList, MarshalBERExtCallBarFeatureList, MarshalDERExtCallBarFeatureList)
}

// ExtCallBarringFeatureCodec binds MAP-MS-DataTypes.Ext-CallBarringFeature.
func ExtCallBarringFeatureCodec() ValueCodec[ExtCallBarringFeature] {
	return compositeValueCodec[ExtCallBarringFeature, *ExtCallBarringFeature]()
}

// CUGInfoCodec binds MAP-MS-DataTypes.CUG-Info.
func CUGInfoCodec() ValueCodec[CUGInfo] {
	return compositeValueCodec[CUGInfo, *CUGInfo]()
}

// CUGSubscriptionListCodec binds MAP-MS-DataTypes.CUG-SubscriptionList.
func CUGSubscriptionListCodec() ValueCodec[CUGSubscriptionList] {
	return pointerValueCodec(UnmarshalBERCUGSubscriptionList, MarshalBERCUGSubscriptionList, MarshalDERCUGSubscriptionList)
}

// CUGSubscriptionCodec binds MAP-MS-DataTypes.CUG-Subscription.
func CUGSubscriptionCodec() ValueCodec[CUGSubscription] {
	return compositeValueCodec[CUGSubscription, *CUGSubscription]()
}

// CUGIndexCodec binds MAP-MS-DataTypes.CUG-Index.
func CUGIndexCodec() ValueCodec[BERValue[CUGIndex]] {
	return integerValueCodec[CUGIndex]("MAP-MS-DataTypes.CUG-Index", "CUG-Index", []primitiveRule[CUGIndex]{{invalid: func(value CUGIndex) bool { return !(int64(value) >= 0 && int64(value) <= 32767) }, description: "(0..32767)", clause: "51.4", observed: func(value CUGIndex) any { return int64(value) }}}, false)
}

// CUGInterlockCodec binds MAP-MS-DataTypes.CUG-Interlock.
func CUGInterlockCodec() ValueCodec[BERValue[CUGInterlock]] {
	return octetValueCodec[CUGInterlock]("MAP-MS-DataTypes.CUG-Interlock", "CUG-Interlock", []primitiveRule[CUGInterlock]{{invalid: func(value CUGInterlock) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value CUGInterlock) int { return len(value) }}})
}

// IntraCUGOptionsCodec binds MAP-MS-DataTypes.IntraCUG-Options.
func IntraCUGOptionsCodec() ValueCodec[BERValue[IntraCUGOptions]] {
	return integerValueCodec[IntraCUGOptions]("MAP-MS-DataTypes.IntraCUG-Options", "IntraCUG-Options", []primitiveRule[IntraCUGOptions]{{invalid: func(value IntraCUGOptions) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value IntraCUGOptions) any { return int64(value) }}}, true)
}

// CUGFeatureListCodec binds MAP-MS-DataTypes.CUG-FeatureList.
func CUGFeatureListCodec() ValueCodec[CUGFeatureList] {
	return pointerValueCodec(UnmarshalBERCUGFeatureList, MarshalBERCUGFeatureList, MarshalDERCUGFeatureList)
}

// ExtBasicServiceGroupListCodec binds MAP-MS-DataTypes.Ext-BasicServiceGroupList.
func ExtBasicServiceGroupListCodec() ValueCodec[ExtBasicServiceGroupList] {
	return pointerValueCodec(UnmarshalBERExtBasicServiceGroupList, MarshalBERExtBasicServiceGroupList, MarshalDERExtBasicServiceGroupList)
}

// CUGFeatureCodec binds MAP-MS-DataTypes.CUG-Feature.
func CUGFeatureCodec() ValueCodec[CUGFeature] {
	return compositeValueCodec[CUGFeature, *CUGFeature]()
}

// InterCUGRestrictionsCodec binds MAP-MS-DataTypes.InterCUG-Restrictions.
func InterCUGRestrictionsCodec() ValueCodec[BERValue[InterCUGRestrictions]] {
	return octetValueCodec[InterCUGRestrictions]("MAP-MS-DataTypes.InterCUG-Restrictions", "InterCUG-Restrictions", []primitiveRule[InterCUGRestrictions]{{invalid: func(value InterCUGRestrictions) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value InterCUGRestrictions) int { return len(value) }}})
}

// ExtSSDataCodec binds MAP-MS-DataTypes.Ext-SS-Data.
func ExtSSDataCodec() ValueCodec[ExtSSData] {
	return compositeValueCodec[ExtSSData, *ExtSSData]()
}

// LCSPrivacyExceptionListCodec binds MAP-MS-DataTypes.LCS-PrivacyExceptionList.
func LCSPrivacyExceptionListCodec() ValueCodec[LCSPrivacyExceptionList] {
	return pointerValueCodec(UnmarshalBERLCSPrivacyExceptionList, MarshalBERLCSPrivacyExceptionList, MarshalDERLCSPrivacyExceptionList)
}

// LCSPrivacyClassCodec binds MAP-MS-DataTypes.LCS-PrivacyClass.
func LCSPrivacyClassCodec() ValueCodec[LCSPrivacyClass] {
	return compositeValueCodec[LCSPrivacyClass, *LCSPrivacyClass]()
}

// ExternalClientListCodec binds MAP-MS-DataTypes.ExternalClientList.
func ExternalClientListCodec() ValueCodec[ExternalClientList] {
	return pointerValueCodec(UnmarshalBERExternalClientList, MarshalBERExternalClientList, MarshalDERExternalClientList)
}

// PLMNClientListCodec binds MAP-MS-DataTypes.PLMNClientList.
func PLMNClientListCodec() ValueCodec[PLMNClientList] {
	return pointerValueCodec(UnmarshalBERPLMNClientList, MarshalBERPLMNClientList, MarshalDERPLMNClientList)
}

// ExtExternalClientListCodec binds MAP-MS-DataTypes.Ext-ExternalClientList.
func ExtExternalClientListCodec() ValueCodec[ExtExternalClientList] {
	return pointerValueCodec(UnmarshalBERExtExternalClientList, MarshalBERExtExternalClientList, MarshalDERExtExternalClientList)
}

// ExternalClientCodec binds MAP-MS-DataTypes.ExternalClient.
func ExternalClientCodec() ValueCodec[ExternalClient] {
	return compositeValueCodec[ExternalClient, *ExternalClient]()
}

// GMLCRestrictionCodec binds MAP-MS-DataTypes.GMLC-Restriction.
func GMLCRestrictionCodec() ValueCodec[BERValue[GMLCRestriction]] {
	return integerValueCodec[GMLCRestriction]("MAP-MS-DataTypes.GMLC-Restriction", "GMLC-Restriction", nil, true)
}

// NotificationToMSUserCodec binds MAP-MS-DataTypes.NotificationToMSUser.
func NotificationToMSUserCodec() ValueCodec[BERValue[NotificationToMSUser]] {
	return integerValueCodec[NotificationToMSUser]("MAP-MS-DataTypes.NotificationToMSUser", "NotificationToMSUser", nil, true)
}

// ServiceTypeListCodec binds MAP-MS-DataTypes.ServiceTypeList.
func ServiceTypeListCodec() ValueCodec[ServiceTypeList] {
	return pointerValueCodec(UnmarshalBERServiceTypeList, MarshalBERServiceTypeList, MarshalDERServiceTypeList)
}

// ServiceTypeCodec binds MAP-MS-DataTypes.ServiceType.
func ServiceTypeCodec() ValueCodec[ServiceType] {
	return compositeValueCodec[ServiceType, *ServiceType]()
}

// MOLRListCodec binds MAP-MS-DataTypes.MOLR-List.
func MOLRListCodec() ValueCodec[MOLRList] {
	return pointerValueCodec(UnmarshalBERMOLRList, MarshalBERMOLRList, MarshalDERMOLRList)
}

// MOLRClassCodec binds MAP-MS-DataTypes.MOLR-Class.
func MOLRClassCodec() ValueCodec[MOLRClass] {
	return compositeValueCodec[MOLRClass, *MOLRClass]()
}

// ZoneCodeListCodec binds MAP-MS-DataTypes.ZoneCodeList.
func ZoneCodeListCodec() ValueCodec[ZoneCodeList] {
	return pointerValueCodec(UnmarshalBERZoneCodeList, MarshalBERZoneCodeList, MarshalDERZoneCodeList)
}

// ZoneCodeCodec binds MAP-MS-DataTypes.ZoneCode.
func ZoneCodeCodec() ValueCodec[BERValue[ZoneCode]] {
	return octetValueCodec[ZoneCode]("MAP-MS-DataTypes.ZoneCode", "ZoneCode", []primitiveRule[ZoneCode]{{invalid: func(value ZoneCode) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value ZoneCode) int { return len(value) }}})
}

// InsertSubscriberDataResCodec binds MAP-MS-DataTypes.InsertSubscriberDataRes.
func InsertSubscriberDataResCodec() ValueCodec[InsertSubscriberDataRes] {
	return compositeValueCodec[InsertSubscriberDataRes, *InsertSubscriberDataRes]()
}

// RegionalSubscriptionResponseCodec binds MAP-MS-DataTypes.RegionalSubscriptionResponse.
func RegionalSubscriptionResponseCodec() ValueCodec[BERValue[RegionalSubscriptionResponse]] {
	return integerValueCodec[RegionalSubscriptionResponse]("MAP-MS-DataTypes.RegionalSubscriptionResponse", "RegionalSubscriptionResponse", []primitiveRule[RegionalSubscriptionResponse]{{invalid: func(value RegionalSubscriptionResponse) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3)
	}, description: "ENUMERATED {0, 1, 2, 3}", clause: "20", observed: func(value RegionalSubscriptionResponse) any { return int64(value) }}}, true)
}

// DeleteSubscriberDataArgCodec binds MAP-MS-DataTypes.DeleteSubscriberDataArg.
func DeleteSubscriberDataArgCodec() ValueCodec[DeleteSubscriberDataArg] {
	return compositeValueCodec[DeleteSubscriberDataArg, *DeleteSubscriberDataArg]()
}

// SpecificCSIWithdrawCodec binds MAP-MS-DataTypes.SpecificCSI-Withdraw.
func SpecificCSIWithdrawCodec() ValueCodec[BERValue[SpecificCSIWithdraw]] {
	return bitValueCodec("MAP-MS-DataTypes.SpecificCSI-Withdraw", "SpecificCSI-Withdraw", []primitiveRule[SpecificCSIWithdraw]{{invalid: func(value SpecificCSIWithdraw) bool { return !(value.BitLength >= 8 && value.BitLength <= 32) }, description: "SIZE (8..32)", clause: "51.5", length: func(value SpecificCSIWithdraw) int { return value.BitLength }, encodedLength: func(value SpecificCSIWithdraw) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 8, Max: 32}}})
}

// GPRSSubscriptionDataWithdrawCodec binds MAP-MS-DataTypes.GPRSSubscriptionDataWithdraw.
func GPRSSubscriptionDataWithdrawCodec() ValueCodec[GPRSSubscriptionDataWithdraw] {
	return compositeValueCodec[GPRSSubscriptionDataWithdraw, *GPRSSubscriptionDataWithdraw]()
}

// EPSSubscriptionDataWithdrawCodec binds MAP-MS-DataTypes.EPS-SubscriptionDataWithdraw.
func EPSSubscriptionDataWithdrawCodec() ValueCodec[EPSSubscriptionDataWithdraw] {
	return compositeValueCodec[EPSSubscriptionDataWithdraw, *EPSSubscriptionDataWithdraw]()
}

// ContextIdListCodec binds MAP-MS-DataTypes.ContextIdList.
func ContextIdListCodec() ValueCodec[ContextIdList] {
	return pointerValueCodec(UnmarshalBERContextIdList, MarshalBERContextIdList, MarshalDERContextIdList)
}

// LSAInformationWithdrawCodec binds MAP-MS-DataTypes.LSAInformationWithdraw.
func LSAInformationWithdrawCodec() ValueCodec[LSAInformationWithdraw] {
	return compositeValueCodec[LSAInformationWithdraw, *LSAInformationWithdraw]()
}

// LSAIdentityListCodec binds MAP-MS-DataTypes.LSAIdentityList.
func LSAIdentityListCodec() ValueCodec[LSAIdentityList] {
	return pointerValueCodec(UnmarshalBERLSAIdentityList, MarshalBERLSAIdentityList, MarshalDERLSAIdentityList)
}

// BasicServiceListCodec binds MAP-MS-DataTypes.BasicServiceList.
func BasicServiceListCodec() ValueCodec[BasicServiceList] {
	return pointerValueCodec(UnmarshalBERBasicServiceList, MarshalBERBasicServiceList, MarshalDERBasicServiceList)
}

// DeleteSubscriberDataResCodec binds MAP-MS-DataTypes.DeleteSubscriberDataRes.
func DeleteSubscriberDataResCodec() ValueCodec[DeleteSubscriberDataRes] {
	return compositeValueCodec[DeleteSubscriberDataRes, *DeleteSubscriberDataRes]()
}

// VlrCamelSubscriptionInfoCodec binds MAP-MS-DataTypes.VlrCamelSubscriptionInfo.
func VlrCamelSubscriptionInfoCodec() ValueCodec[VlrCamelSubscriptionInfo] {
	return compositeValueCodec[VlrCamelSubscriptionInfo, *VlrCamelSubscriptionInfo]()
}

// MTSmsCAMELTDPCriteriaListCodec binds MAP-MS-DataTypes.MT-smsCAMELTDP-CriteriaList.
func MTSmsCAMELTDPCriteriaListCodec() ValueCodec[MTSmsCAMELTDPCriteriaList] {
	return pointerValueCodec(UnmarshalBERMTSmsCAMELTDPCriteriaList, MarshalBERMTSmsCAMELTDPCriteriaList, MarshalDERMTSmsCAMELTDPCriteriaList)
}

// MTSmsCAMELTDPCriteriaCodec binds MAP-MS-DataTypes.MT-smsCAMELTDP-Criteria.
func MTSmsCAMELTDPCriteriaCodec() ValueCodec[MTSmsCAMELTDPCriteria] {
	return compositeValueCodec[MTSmsCAMELTDPCriteria, *MTSmsCAMELTDPCriteria]()
}

// TPDUTypeCriterionCodec binds MAP-MS-DataTypes.TPDU-TypeCriterion.
func TPDUTypeCriterionCodec() ValueCodec[TPDUTypeCriterion] {
	return pointerValueCodec(UnmarshalBERTPDUTypeCriterion, MarshalBERTPDUTypeCriterion, MarshalDERTPDUTypeCriterion)
}

// MTSMSTPDUTypeCodec binds MAP-MS-DataTypes.MT-SMS-TPDU-Type.
func MTSMSTPDUTypeCodec() ValueCodec[BERValue[MTSMSTPDUType]] {
	return integerValueCodec[MTSMSTPDUType]("MAP-MS-DataTypes.MT-SMS-TPDU-Type", "MT-SMS-TPDU-Type", nil, true)
}

// DCSICodec binds MAP-MS-DataTypes.D-CSI.
func DCSICodec() ValueCodec[DCSI] {
	return compositeValueCodec[DCSI, *DCSI]()
}

// DPAnalysedInfoCriteriaListCodec binds MAP-MS-DataTypes.DP-AnalysedInfoCriteriaList.
func DPAnalysedInfoCriteriaListCodec() ValueCodec[DPAnalysedInfoCriteriaList] {
	return pointerValueCodec(UnmarshalBERDPAnalysedInfoCriteriaList, MarshalBERDPAnalysedInfoCriteriaList, MarshalDERDPAnalysedInfoCriteriaList)
}

// DPAnalysedInfoCriteriumCodec binds MAP-MS-DataTypes.DP-AnalysedInfoCriterium.
func DPAnalysedInfoCriteriumCodec() ValueCodec[DPAnalysedInfoCriterium] {
	return compositeValueCodec[DPAnalysedInfoCriterium, *DPAnalysedInfoCriterium]()
}

// SSCSICodec binds MAP-MS-DataTypes.SS-CSI.
func SSCSICodec() ValueCodec[SSCSI] {
	return compositeValueCodec[SSCSI, *SSCSI]()
}

// SSCamelDataCodec binds MAP-MS-DataTypes.SS-CamelData.
func SSCamelDataCodec() ValueCodec[SSCamelData] {
	return compositeValueCodec[SSCamelData, *SSCamelData]()
}

// SSEventListCodec binds MAP-MS-DataTypes.SS-EventList.
func SSEventListCodec() ValueCodec[SSEventList] {
	return pointerValueCodec(UnmarshalBERSSEventList, MarshalBERSSEventList, MarshalDERSSEventList)
}

// OCSICodec binds MAP-MS-DataTypes.O-CSI.
func OCSICodec() ValueCodec[OCSI] {
	return compositeValueCodec[OCSI, *OCSI]()
}

// OBcsmCamelTDPDataListCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPDataList.
func OBcsmCamelTDPDataListCodec() ValueCodec[OBcsmCamelTDPDataList] {
	return pointerValueCodec(UnmarshalBEROBcsmCamelTDPDataList, MarshalBEROBcsmCamelTDPDataList, MarshalDEROBcsmCamelTDPDataList)
}

// OBcsmCamelTDPDataCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPData.
func OBcsmCamelTDPDataCodec() ValueCodec[OBcsmCamelTDPData] {
	return compositeValueCodec[OBcsmCamelTDPData, *OBcsmCamelTDPData]()
}

// ServiceKeyCodec binds MAP-MS-DataTypes.ServiceKey.
func ServiceKeyCodec() ValueCodec[BERValue[ServiceKey]] {
	return integerValueCodec[ServiceKey]("MAP-MS-DataTypes.ServiceKey", "ServiceKey", []primitiveRule[ServiceKey]{{invalid: func(value ServiceKey) bool { return !(int64(value) >= 0 && int64(value) <= 2147483647) }, description: "(0..2147483647)", clause: "51.4", observed: func(value ServiceKey) any { return int64(value) }}}, false)
}

// OBcsmTriggerDetectionPointCodec binds MAP-MS-DataTypes.O-BcsmTriggerDetectionPoint.
func OBcsmTriggerDetectionPointCodec() ValueCodec[BERValue[OBcsmTriggerDetectionPoint]] {
	return integerValueCodec[OBcsmTriggerDetectionPoint]("MAP-MS-DataTypes.O-BcsmTriggerDetectionPoint", "O-BcsmTriggerDetectionPoint", nil, true)
}

// OBcsmCamelTDPCriteriaListCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPCriteriaList.
func OBcsmCamelTDPCriteriaListCodec() ValueCodec[OBcsmCamelTDPCriteriaList] {
	return pointerValueCodec(UnmarshalBEROBcsmCamelTDPCriteriaList, MarshalBEROBcsmCamelTDPCriteriaList, MarshalDEROBcsmCamelTDPCriteriaList)
}

// TBCSMCAMELTDPCriteriaListCodec binds MAP-MS-DataTypes.T-BCSM-CAMEL-TDP-CriteriaList.
func TBCSMCAMELTDPCriteriaListCodec() ValueCodec[TBCSMCAMELTDPCriteriaList] {
	return pointerValueCodec(UnmarshalBERTBCSMCAMELTDPCriteriaList, MarshalBERTBCSMCAMELTDPCriteriaList, MarshalDERTBCSMCAMELTDPCriteriaList)
}

// OBcsmCamelTDPCriteriaCodec binds MAP-MS-DataTypes.O-BcsmCamelTDP-Criteria.
func OBcsmCamelTDPCriteriaCodec() ValueCodec[OBcsmCamelTDPCriteria] {
	return compositeValueCodec[OBcsmCamelTDPCriteria, *OBcsmCamelTDPCriteria]()
}

// TBCSMCAMELTDPCriteriaCodec binds MAP-MS-DataTypes.T-BCSM-CAMEL-TDP-Criteria.
func TBCSMCAMELTDPCriteriaCodec() ValueCodec[TBCSMCAMELTDPCriteria] {
	return compositeValueCodec[TBCSMCAMELTDPCriteria, *TBCSMCAMELTDPCriteria]()
}

// DestinationNumberCriteriaCodec binds MAP-MS-DataTypes.DestinationNumberCriteria.
func DestinationNumberCriteriaCodec() ValueCodec[DestinationNumberCriteria] {
	return compositeValueCodec[DestinationNumberCriteria, *DestinationNumberCriteria]()
}

// DestinationNumberListCodec binds MAP-MS-DataTypes.DestinationNumberList.
func DestinationNumberListCodec() ValueCodec[DestinationNumberList] {
	return pointerValueCodec(UnmarshalBERDestinationNumberList, MarshalBERDestinationNumberList, MarshalDERDestinationNumberList)
}

// DestinationNumberLengthListCodec binds MAP-MS-DataTypes.DestinationNumberLengthList.
func DestinationNumberLengthListCodec() ValueCodec[DestinationNumberLengthList] {
	return pointerValueCodec(UnmarshalBERDestinationNumberLengthList, MarshalBERDestinationNumberLengthList, MarshalDERDestinationNumberLengthList)
}

// BasicServiceCriteriaCodec binds MAP-MS-DataTypes.BasicServiceCriteria.
func BasicServiceCriteriaCodec() ValueCodec[BasicServiceCriteria] {
	return pointerValueCodec(UnmarshalBERBasicServiceCriteria, MarshalBERBasicServiceCriteria, MarshalDERBasicServiceCriteria)
}

// CallTypeCriteriaCodec binds MAP-MS-DataTypes.CallTypeCriteria.
func CallTypeCriteriaCodec() ValueCodec[BERValue[CallTypeCriteria]] {
	return integerValueCodec[CallTypeCriteria]("MAP-MS-DataTypes.CallTypeCriteria", "CallTypeCriteria", []primitiveRule[CallTypeCriteria]{{invalid: func(value CallTypeCriteria) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value CallTypeCriteria) any { return int64(value) }}}, true)
}

// MatchTypeCodec binds MAP-MS-DataTypes.MatchType.
func MatchTypeCodec() ValueCodec[BERValue[MatchType]] {
	return integerValueCodec[MatchType]("MAP-MS-DataTypes.MatchType", "MatchType", []primitiveRule[MatchType]{{invalid: func(value MatchType) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MatchType) any { return int64(value) }}}, true)
}

// OCauseValueCriteriaCodec binds MAP-MS-DataTypes.O-CauseValueCriteria.
func OCauseValueCriteriaCodec() ValueCodec[OCauseValueCriteria] {
	return pointerValueCodec(UnmarshalBEROCauseValueCriteria, MarshalBEROCauseValueCriteria, MarshalDEROCauseValueCriteria)
}

// TCauseValueCriteriaCodec binds MAP-MS-DataTypes.T-CauseValueCriteria.
func TCauseValueCriteriaCodec() ValueCodec[TCauseValueCriteria] {
	return pointerValueCodec(UnmarshalBERTCauseValueCriteria, MarshalBERTCauseValueCriteria, MarshalDERTCauseValueCriteria)
}

// CauseValueCodec binds MAP-MS-DataTypes.CauseValue.
func CauseValueCodec() ValueCodec[BERValue[CauseValue]] {
	return octetValueCodec[CauseValue]("MAP-MS-DataTypes.CauseValue", "CauseValue", []primitiveRule[CauseValue]{{invalid: func(value CauseValue) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value CauseValue) int { return len(value) }}})
}

// DefaultCallHandlingCodec binds MAP-MS-DataTypes.DefaultCallHandling.
func DefaultCallHandlingCodec() ValueCodec[BERValue[DefaultCallHandling]] {
	return integerValueCodec[DefaultCallHandling]("MAP-MS-DataTypes.DefaultCallHandling", "DefaultCallHandling", nil, true)
}

// CamelCapabilityHandlingCodec binds MAP-MS-DataTypes.CamelCapabilityHandling.
func CamelCapabilityHandlingCodec() ValueCodec[BERValue[CamelCapabilityHandling]] {
	return integerValueCodec[CamelCapabilityHandling]("MAP-MS-DataTypes.CamelCapabilityHandling", "CamelCapabilityHandling", []primitiveRule[CamelCapabilityHandling]{{invalid: func(value CamelCapabilityHandling) bool { return !(int64(value) >= 1 && int64(value) <= 16) }, description: "(1..16)", clause: "51.4", observed: func(value CamelCapabilityHandling) any { return int64(value) }}}, false)
}

// SupportedCamelPhasesCodec binds MAP-MS-DataTypes.SupportedCamelPhases.
func SupportedCamelPhasesCodec() ValueCodec[BERValue[SupportedCamelPhases]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedCamelPhases", "SupportedCamelPhases", []primitiveRule[SupportedCamelPhases]{{invalid: func(value SupportedCamelPhases) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value SupportedCamelPhases) int { return value.BitLength }, encodedLength: func(value SupportedCamelPhases) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// OfferedCamel4CSIsCodec binds MAP-MS-DataTypes.OfferedCamel4CSIs.
func OfferedCamel4CSIsCodec() ValueCodec[BERValue[OfferedCamel4CSIs]] {
	return bitValueCodec("MAP-MS-DataTypes.OfferedCamel4CSIs", "OfferedCamel4CSIs", []primitiveRule[OfferedCamel4CSIs]{{invalid: func(value OfferedCamel4CSIs) bool { return !(value.BitLength >= 7 && value.BitLength <= 16) }, description: "SIZE (7..16)", clause: "51.5", length: func(value OfferedCamel4CSIs) int { return value.BitLength }, encodedLength: func(value OfferedCamel4CSIs) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}})
}

// OfferedCamel4FunctionalitiesCodec binds MAP-MS-DataTypes.OfferedCamel4Functionalities.
func OfferedCamel4FunctionalitiesCodec() ValueCodec[BERValue[OfferedCamel4Functionalities]] {
	return bitValueCodec("MAP-MS-DataTypes.OfferedCamel4Functionalities", "OfferedCamel4Functionalities", []primitiveRule[OfferedCamel4Functionalities]{{invalid: func(value OfferedCamel4Functionalities) bool {
		return !(value.BitLength >= 15 && value.BitLength <= 64)
	}, description: "SIZE (15..64)", clause: "51.5", length: func(value OfferedCamel4Functionalities) int { return value.BitLength }, encodedLength: func(value OfferedCamel4Functionalities) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 15, Max: 64}}})
}

// SMSCSICodec binds MAP-MS-DataTypes.SMS-CSI.
func SMSCSICodec() ValueCodec[SMSCSI] {
	return compositeValueCodec[SMSCSI, *SMSCSI]()
}

// SMSCAMELTDPDataListCodec binds MAP-MS-DataTypes.SMS-CAMEL-TDP-DataList.
func SMSCAMELTDPDataListCodec() ValueCodec[SMSCAMELTDPDataList] {
	return pointerValueCodec(UnmarshalBERSMSCAMELTDPDataList, MarshalBERSMSCAMELTDPDataList, MarshalDERSMSCAMELTDPDataList)
}

// SMSCAMELTDPDataCodec binds MAP-MS-DataTypes.SMS-CAMEL-TDP-Data.
func SMSCAMELTDPDataCodec() ValueCodec[SMSCAMELTDPData] {
	return compositeValueCodec[SMSCAMELTDPData, *SMSCAMELTDPData]()
}

// SMSTriggerDetectionPointCodec binds MAP-MS-DataTypes.SMS-TriggerDetectionPoint.
func SMSTriggerDetectionPointCodec() ValueCodec[BERValue[SMSTriggerDetectionPoint]] {
	return integerValueCodec[SMSTriggerDetectionPoint]("MAP-MS-DataTypes.SMS-TriggerDetectionPoint", "SMS-TriggerDetectionPoint", nil, true)
}

// DefaultSMSHandlingCodec binds MAP-MS-DataTypes.DefaultSMS-Handling.
func DefaultSMSHandlingCodec() ValueCodec[BERValue[DefaultSMSHandling]] {
	return integerValueCodec[DefaultSMSHandling]("MAP-MS-DataTypes.DefaultSMS-Handling", "DefaultSMS-Handling", nil, true)
}

// MCSICodec binds MAP-MS-DataTypes.M-CSI.
func MCSICodec() ValueCodec[MCSI] {
	return compositeValueCodec[MCSI, *MCSI]()
}

// MGCSICodec binds MAP-MS-DataTypes.MG-CSI.
func MGCSICodec() ValueCodec[MGCSI] {
	return compositeValueCodec[MGCSI, *MGCSI]()
}

// MobilityTriggersCodec binds MAP-MS-DataTypes.MobilityTriggers.
func MobilityTriggersCodec() ValueCodec[MobilityTriggers] {
	return pointerValueCodec(UnmarshalBERMobilityTriggers, MarshalBERMobilityTriggers, MarshalDERMobilityTriggers)
}

// MMCodeCodec binds MAP-MS-DataTypes.MM-Code.
func MMCodeCodec() ValueCodec[BERValue[MMCode]] {
	return octetValueCodec[MMCode]("MAP-MS-DataTypes.MM-Code", "MM-Code", []primitiveRule[MMCode]{{invalid: func(value MMCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MMCode) int { return len(value) }}})
}

// TCSICodec binds MAP-MS-DataTypes.T-CSI.
func TCSICodec() ValueCodec[TCSI] {
	return compositeValueCodec[TCSI, *TCSI]()
}

// TBcsmCamelTDPDataListCodec binds MAP-MS-DataTypes.T-BcsmCamelTDPDataList.
func TBcsmCamelTDPDataListCodec() ValueCodec[TBcsmCamelTDPDataList] {
	return pointerValueCodec(UnmarshalBERTBcsmCamelTDPDataList, MarshalBERTBcsmCamelTDPDataList, MarshalDERTBcsmCamelTDPDataList)
}

// TBcsmCamelTDPDataCodec binds MAP-MS-DataTypes.T-BcsmCamelTDPData.
func TBcsmCamelTDPDataCodec() ValueCodec[TBcsmCamelTDPData] {
	return compositeValueCodec[TBcsmCamelTDPData, *TBcsmCamelTDPData]()
}

// TBcsmTriggerDetectionPointCodec binds MAP-MS-DataTypes.T-BcsmTriggerDetectionPoint.
func TBcsmTriggerDetectionPointCodec() ValueCodec[BERValue[TBcsmTriggerDetectionPoint]] {
	return integerValueCodec[TBcsmTriggerDetectionPoint]("MAP-MS-DataTypes.T-BcsmTriggerDetectionPoint", "T-BcsmTriggerDetectionPoint", nil, true)
}

// SendRoutingInfoForGprsArgCodec binds MAP-MS-DataTypes.SendRoutingInfoForGprsArg.
func SendRoutingInfoForGprsArgCodec() ValueCodec[SendRoutingInfoForGprsArg] {
	return compositeValueCodec[SendRoutingInfoForGprsArg, *SendRoutingInfoForGprsArg]()
}

// SendRoutingInfoForGprsResCodec binds MAP-MS-DataTypes.SendRoutingInfoForGprsRes.
func SendRoutingInfoForGprsResCodec() ValueCodec[SendRoutingInfoForGprsRes] {
	return compositeValueCodec[SendRoutingInfoForGprsRes, *SendRoutingInfoForGprsRes]()
}

// FailureReportArgCodec binds MAP-MS-DataTypes.FailureReportArg.
func FailureReportArgCodec() ValueCodec[FailureReportArg] {
	return compositeValueCodec[FailureReportArg, *FailureReportArg]()
}

// FailureReportResCodec binds MAP-MS-DataTypes.FailureReportRes.
func FailureReportResCodec() ValueCodec[FailureReportRes] {
	return compositeValueCodec[FailureReportRes, *FailureReportRes]()
}

// NoteMsPresentForGprsArgCodec binds MAP-MS-DataTypes.NoteMsPresentForGprsArg.
func NoteMsPresentForGprsArgCodec() ValueCodec[NoteMsPresentForGprsArg] {
	return compositeValueCodec[NoteMsPresentForGprsArg, *NoteMsPresentForGprsArg]()
}

// NoteMsPresentForGprsResCodec binds MAP-MS-DataTypes.NoteMsPresentForGprsRes.
func NoteMsPresentForGprsResCodec() ValueCodec[NoteMsPresentForGprsRes] {
	return compositeValueCodec[NoteMsPresentForGprsRes, *NoteMsPresentForGprsRes]()
}

// ResetArgCodec binds MAP-MS-DataTypes.ResetArg.
func ResetArgCodec() ValueCodec[ResetArg] {
	return compositeValueCodec[ResetArg, *ResetArg]()
}

// SendingNodeNumberCodec binds MAP-MS-DataTypes.SendingNode-Number.
func SendingNodeNumberCodec() ValueCodec[SendingNodeNumber] {
	return compositeValueCodec[SendingNodeNumber, *SendingNodeNumber]()
}

// RestoreDataArgCodec binds MAP-MS-DataTypes.RestoreDataArg.
func RestoreDataArgCodec() ValueCodec[RestoreDataArg] {
	return compositeValueCodec[RestoreDataArg, *RestoreDataArg]()
}

// RestoreDataResCodec binds MAP-MS-DataTypes.RestoreDataRes.
func RestoreDataResCodec() ValueCodec[RestoreDataRes] {
	return compositeValueCodec[RestoreDataRes, *RestoreDataRes]()
}

// VBSDataListCodec binds MAP-MS-DataTypes.VBSDataList.
func VBSDataListCodec() ValueCodec[VBSDataList] {
	return pointerValueCodec(UnmarshalBERVBSDataList, MarshalBERVBSDataList, MarshalDERVBSDataList)
}

// VGCSDataListCodec binds MAP-MS-DataTypes.VGCSDataList.
func VGCSDataListCodec() ValueCodec[VGCSDataList] {
	return pointerValueCodec(UnmarshalBERVGCSDataList, MarshalBERVGCSDataList, MarshalDERVGCSDataList)
}

// VoiceGroupCallDataCodec binds MAP-MS-DataTypes.VoiceGroupCallData.
func VoiceGroupCallDataCodec() ValueCodec[VoiceGroupCallData] {
	return compositeValueCodec[VoiceGroupCallData, *VoiceGroupCallData]()
}

// AdditionalInfoCodec binds MAP-MS-DataTypes.AdditionalInfo.
func AdditionalInfoCodec() ValueCodec[BERValue[AdditionalInfo]] {
	return bitValueCodec("MAP-MS-DataTypes.AdditionalInfo", "AdditionalInfo", []primitiveRule[AdditionalInfo]{{invalid: func(value AdditionalInfo) bool { return !(value.BitLength >= 1 && value.BitLength <= 136) }, description: "SIZE (1..136)", clause: "51.5", length: func(value AdditionalInfo) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 1, Max: 136}}})
}

// AdditionalSubscriptionsCodec binds MAP-MS-DataTypes.AdditionalSubscriptions.
func AdditionalSubscriptionsCodec() ValueCodec[BERValue[AdditionalSubscriptions]] {
	return bitValueCodec("MAP-MS-DataTypes.AdditionalSubscriptions", "AdditionalSubscriptions", []primitiveRule[AdditionalSubscriptions]{{invalid: func(value AdditionalSubscriptions) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value AdditionalSubscriptions) int { return value.BitLength }, encodedLength: func(value AdditionalSubscriptions) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// VoiceBroadcastDataCodec binds MAP-MS-DataTypes.VoiceBroadcastData.
func VoiceBroadcastDataCodec() ValueCodec[VoiceBroadcastData] {
	return compositeValueCodec[VoiceBroadcastData, *VoiceBroadcastData]()
}

// GroupIdCodec binds MAP-MS-DataTypes.GroupId.
func GroupIdCodec() ValueCodec[BERValue[GroupId]] {
	return pointerValueCodec(UnmarshalBERGroupId, MarshalBERGroupId, MarshalDERGroupId)
}

// LongGroupIdCodec binds MAP-MS-DataTypes.Long-GroupId.
func LongGroupIdCodec() ValueCodec[BERValue[LongGroupId]] {
	return pointerValueCodec(UnmarshalBERLongGroupId, MarshalBERLongGroupId, MarshalDERLongGroupId)
}

// ProvideSubscriberInfoArgCodec binds MAP-MS-DataTypes.ProvideSubscriberInfoArg.
func ProvideSubscriberInfoArgCodec() ValueCodec[ProvideSubscriberInfoArg] {
	return compositeValueCodec[ProvideSubscriberInfoArg, *ProvideSubscriberInfoArg]()
}

// ProvideSubscriberInfoResCodec binds MAP-MS-DataTypes.ProvideSubscriberInfoRes.
func ProvideSubscriberInfoResCodec() ValueCodec[ProvideSubscriberInfoRes] {
	return compositeValueCodec[ProvideSubscriberInfoRes, *ProvideSubscriberInfoRes]()
}

// SubscriberInfoCodec binds MAP-MS-DataTypes.SubscriberInfo.
func SubscriberInfoCodec() ValueCodec[SubscriberInfo] {
	return compositeValueCodec[SubscriberInfo, *SubscriberInfo]()
}

// IMSVoiceOverPSSessionsIndCodec binds MAP-MS-DataTypes.IMS-VoiceOverPS-SessionsInd.
func IMSVoiceOverPSSessionsIndCodec() ValueCodec[BERValue[IMSVoiceOverPSSessionsInd]] {
	return integerValueCodec[IMSVoiceOverPSSessionsInd]("MAP-MS-DataTypes.IMS-VoiceOverPS-SessionsInd", "IMS-VoiceOverPS-SessionsInd", []primitiveRule[IMSVoiceOverPSSessionsInd]{{invalid: func(value IMSVoiceOverPSSessionsInd) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value IMSVoiceOverPSSessionsInd) any { return int64(value) }}}, true)
}

// TimeZoneCodec binds MAP-MS-DataTypes.TimeZone.
func TimeZoneCodec() ValueCodec[BERValue[TimeZone]] {
	return octetValueCodec[TimeZone]("MAP-MS-DataTypes.TimeZone", "TimeZone", []primitiveRule[TimeZone]{{invalid: func(value TimeZone) bool { return !(len(value) >= 2 && len(value) <= 3) }, description: "SIZE (2..3)", clause: "51.5", length: func(value TimeZone) int { return len(value) }}})
}

// DaylightSavingTimeCodec binds MAP-MS-DataTypes.DaylightSavingTime.
func DaylightSavingTimeCodec() ValueCodec[BERValue[DaylightSavingTime]] {
	return integerValueCodec[DaylightSavingTime]("MAP-MS-DataTypes.DaylightSavingTime", "DaylightSavingTime", []primitiveRule[DaylightSavingTime]{{invalid: func(value DaylightSavingTime) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value DaylightSavingTime) any { return int64(value) }}}, true)
}

// MNPInfoResCodec binds MAP-MS-DataTypes.MNPInfoRes.
func MNPInfoResCodec() ValueCodec[MNPInfoRes] {
	return compositeValueCodec[MNPInfoRes, *MNPInfoRes]()
}

// RouteingNumberCodec binds MAP-MS-DataTypes.RouteingNumber.
func RouteingNumberCodec() ValueCodec[BERValue[RouteingNumber]] {
	return pointerValueCodec(UnmarshalBERRouteingNumber, MarshalBERRouteingNumber, MarshalDERRouteingNumber)
}

// NumberPortabilityStatusCodec binds MAP-MS-DataTypes.NumberPortabilityStatus.
func NumberPortabilityStatusCodec() ValueCodec[BERValue[NumberPortabilityStatus]] {
	return integerValueCodec[NumberPortabilityStatus]("MAP-MS-DataTypes.NumberPortabilityStatus", "NumberPortabilityStatus", nil, true)
}

// MSClassmark2Codec binds MAP-MS-DataTypes.MS-Classmark2.
func MSClassmark2Codec() ValueCodec[BERValue[MSClassmark2]] {
	return octetValueCodec[MSClassmark2]("MAP-MS-DataTypes.MS-Classmark2", "MS-Classmark2", []primitiveRule[MSClassmark2]{{invalid: func(value MSClassmark2) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value MSClassmark2) int { return len(value) }}})
}

// GPRSMSClassCodec binds MAP-MS-DataTypes.GPRSMSClass.
func GPRSMSClassCodec() ValueCodec[GPRSMSClass] {
	return compositeValueCodec[GPRSMSClass, *GPRSMSClass]()
}

// MSNetworkCapabilityCodec binds MAP-MS-DataTypes.MSNetworkCapability.
func MSNetworkCapabilityCodec() ValueCodec[BERValue[MSNetworkCapability]] {
	return octetValueCodec[MSNetworkCapability]("MAP-MS-DataTypes.MSNetworkCapability", "MSNetworkCapability", []primitiveRule[MSNetworkCapability]{{invalid: func(value MSNetworkCapability) bool { return !(len(value) >= 1 && len(value) <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value MSNetworkCapability) int { return len(value) }}})
}

// MSRadioAccessCapabilityCodec binds MAP-MS-DataTypes.MSRadioAccessCapability.
func MSRadioAccessCapabilityCodec() ValueCodec[BERValue[MSRadioAccessCapability]] {
	return octetValueCodec[MSRadioAccessCapability]("MAP-MS-DataTypes.MSRadioAccessCapability", "MSRadioAccessCapability", []primitiveRule[MSRadioAccessCapability]{{invalid: func(value MSRadioAccessCapability) bool { return !(len(value) >= 1 && len(value) <= 50) }, description: "SIZE (1..50)", clause: "51.5", length: func(value MSRadioAccessCapability) int { return len(value) }}})
}

// RequestedInfoCodec binds MAP-MS-DataTypes.RequestedInfo.
func RequestedInfoCodec() ValueCodec[RequestedInfo] {
	return compositeValueCodec[RequestedInfo, *RequestedInfo]()
}

// DomainTypeCodec binds MAP-MS-DataTypes.DomainType.
func DomainTypeCodec() ValueCodec[BERValue[DomainType]] {
	return integerValueCodec[DomainType]("MAP-MS-DataTypes.DomainType", "DomainType", nil, true)
}

// RequestedNodesCodec binds MAP-MS-DataTypes.RequestedNodes.
func RequestedNodesCodec() ValueCodec[BERValue[RequestedNodes]] {
	return bitValueCodec("MAP-MS-DataTypes.RequestedNodes", "RequestedNodes", []primitiveRule[RequestedNodes]{{invalid: func(value RequestedNodes) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value RequestedNodes) int { return value.BitLength }, encodedLength: func(value RequestedNodes) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// LocationInformationCodec binds MAP-MS-DataTypes.LocationInformation.
func LocationInformationCodec() ValueCodec[LocationInformation] {
	return compositeValueCodec[LocationInformation, *LocationInformation]()
}

// LocationInformationEPSCodec binds MAP-MS-DataTypes.LocationInformationEPS.
func LocationInformationEPSCodec() ValueCodec[LocationInformationEPS] {
	return compositeValueCodec[LocationInformationEPS, *LocationInformationEPS]()
}

// LocationInformationGPRSCodec binds MAP-MS-DataTypes.LocationInformationGPRS.
func LocationInformationGPRSCodec() ValueCodec[LocationInformationGPRS] {
	return compositeValueCodec[LocationInformationGPRS, *LocationInformationGPRS]()
}

// LocationInformation5GSCodec binds MAP-MS-DataTypes.LocationInformation5GS.
func LocationInformation5GSCodec() ValueCodec[LocationInformation5GS] {
	return compositeValueCodec[LocationInformation5GS, *LocationInformation5GS]()
}

// UserCSGInformationCodec binds MAP-MS-DataTypes.UserCSGInformation.
func UserCSGInformationCodec() ValueCodec[UserCSGInformation] {
	return compositeValueCodec[UserCSGInformation, *UserCSGInformation]()
}

// GeographicalInformationCodec binds MAP-MS-DataTypes.GeographicalInformation.
func GeographicalInformationCodec() ValueCodec[BERValue[GeographicalInformation]] {
	return octetValueCodec[GeographicalInformation]("MAP-MS-DataTypes.GeographicalInformation", "GeographicalInformation", []primitiveRule[GeographicalInformation]{{invalid: func(value GeographicalInformation) bool { return !(len(value) == 8) }, description: "SIZE (8)", clause: "51.5", length: func(value GeographicalInformation) int { return len(value) }}})
}

// GeodeticInformationCodec binds MAP-MS-DataTypes.GeodeticInformation.
func GeodeticInformationCodec() ValueCodec[BERValue[GeodeticInformation]] {
	return octetValueCodec[GeodeticInformation]("MAP-MS-DataTypes.GeodeticInformation", "GeodeticInformation", []primitiveRule[GeodeticInformation]{{invalid: func(value GeodeticInformation) bool { return !(len(value) == 10) }, description: "SIZE (10)", clause: "51.5", length: func(value GeodeticInformation) int { return len(value) }}})
}

// LocationNumberCodec binds MAP-MS-DataTypes.LocationNumber.
func LocationNumberCodec() ValueCodec[BERValue[LocationNumber]] {
	return octetValueCodec[LocationNumber]("MAP-MS-DataTypes.LocationNumber", "LocationNumber", []primitiveRule[LocationNumber]{{invalid: func(value LocationNumber) bool { return !(len(value) >= 2 && len(value) <= 10) }, description: "SIZE (2..10)", clause: "51.5", length: func(value LocationNumber) int { return len(value) }}})
}

// SubscriberStateCodec binds MAP-MS-DataTypes.SubscriberState.
func SubscriberStateCodec() ValueCodec[SubscriberState] {
	return compositeValueCodec[SubscriberState, *SubscriberState]()
}

// PSSubscriberStateCodec binds MAP-MS-DataTypes.PS-SubscriberState.
func PSSubscriberStateCodec() ValueCodec[PSSubscriberState] {
	return compositeValueCodec[PSSubscriberState, *PSSubscriberState]()
}

// PDPContextInfoListCodec binds MAP-MS-DataTypes.PDP-ContextInfoList.
func PDPContextInfoListCodec() ValueCodec[PDPContextInfoList] {
	return pointerValueCodec(UnmarshalBERPDPContextInfoList, MarshalBERPDPContextInfoList, MarshalDERPDPContextInfoList)
}

// PDPContextInfoCodec binds MAP-MS-DataTypes.PDP-ContextInfo.
func PDPContextInfoCodec() ValueCodec[PDPContextInfo] {
	return compositeValueCodec[PDPContextInfo, *PDPContextInfo]()
}

// NSAPICodec binds MAP-MS-DataTypes.NSAPI.
func NSAPICodec() ValueCodec[BERValue[NSAPI]] {
	return integerValueCodec[NSAPI]("MAP-MS-DataTypes.NSAPI", "NSAPI", []primitiveRule[NSAPI]{{invalid: func(value NSAPI) bool { return !(int64(value) >= 0 && int64(value) <= 15) }, description: "(0..15)", clause: "51.4", observed: func(value NSAPI) any { return int64(value) }}}, false)
}

// TransactionIdCodec binds MAP-MS-DataTypes.TransactionId.
func TransactionIdCodec() ValueCodec[BERValue[TransactionId]] {
	return octetValueCodec[TransactionId]("MAP-MS-DataTypes.TransactionId", "TransactionId", []primitiveRule[TransactionId]{{invalid: func(value TransactionId) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value TransactionId) int { return len(value) }}})
}

// TEIDCodec binds MAP-MS-DataTypes.TEID.
func TEIDCodec() ValueCodec[BERValue[TEID]] {
	return octetValueCodec[TEID]("MAP-MS-DataTypes.TEID", "TEID", []primitiveRule[TEID]{{invalid: func(value TEID) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value TEID) int { return len(value) }}})
}

// GPRSChargingIDCodec binds MAP-MS-DataTypes.GPRSChargingID.
func GPRSChargingIDCodec() ValueCodec[BERValue[GPRSChargingID]] {
	return octetValueCodec[GPRSChargingID]("MAP-MS-DataTypes.GPRSChargingID", "GPRSChargingID", []primitiveRule[GPRSChargingID]{{invalid: func(value GPRSChargingID) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value GPRSChargingID) int { return len(value) }}})
}

// NotReachableReasonCodec binds MAP-MS-DataTypes.NotReachableReason.
func NotReachableReasonCodec() ValueCodec[BERValue[NotReachableReason]] {
	return integerValueCodec[NotReachableReason]("MAP-MS-DataTypes.NotReachableReason", "NotReachableReason", []primitiveRule[NotReachableReason]{{invalid: func(value NotReachableReason) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3)
	}, description: "ENUMERATED {0, 1, 2, 3}", clause: "20", observed: func(value NotReachableReason) any { return int64(value) }}}, true)
}

// AnyTimeInterrogationArgCodec binds MAP-MS-DataTypes.AnyTimeInterrogationArg.
func AnyTimeInterrogationArgCodec() ValueCodec[AnyTimeInterrogationArg] {
	return compositeValueCodec[AnyTimeInterrogationArg, *AnyTimeInterrogationArg]()
}

// AnyTimeInterrogationResCodec binds MAP-MS-DataTypes.AnyTimeInterrogationRes.
func AnyTimeInterrogationResCodec() ValueCodec[AnyTimeInterrogationRes] {
	return compositeValueCodec[AnyTimeInterrogationRes, *AnyTimeInterrogationRes]()
}

// AnyTimeSubscriptionInterrogationArgCodec binds MAP-MS-DataTypes.AnyTimeSubscriptionInterrogationArg.
func AnyTimeSubscriptionInterrogationArgCodec() ValueCodec[AnyTimeSubscriptionInterrogationArg] {
	return compositeValueCodec[AnyTimeSubscriptionInterrogationArg, *AnyTimeSubscriptionInterrogationArg]()
}

// AnyTimeSubscriptionInterrogationResCodec binds MAP-MS-DataTypes.AnyTimeSubscriptionInterrogationRes.
func AnyTimeSubscriptionInterrogationResCodec() ValueCodec[AnyTimeSubscriptionInterrogationRes] {
	return compositeValueCodec[AnyTimeSubscriptionInterrogationRes, *AnyTimeSubscriptionInterrogationRes]()
}

// CallWaitingDataCodec binds MAP-MS-DataTypes.CallWaitingData.
func CallWaitingDataCodec() ValueCodec[CallWaitingData] {
	return compositeValueCodec[CallWaitingData, *CallWaitingData]()
}

// ExtCwFeatureListCodec binds MAP-MS-DataTypes.Ext-CwFeatureList.
func ExtCwFeatureListCodec() ValueCodec[ExtCwFeatureList] {
	return pointerValueCodec(UnmarshalBERExtCwFeatureList, MarshalBERExtCwFeatureList, MarshalDERExtCwFeatureList)
}

// ExtCwFeatureCodec binds MAP-MS-DataTypes.Ext-CwFeature.
func ExtCwFeatureCodec() ValueCodec[ExtCwFeature] {
	return compositeValueCodec[ExtCwFeature, *ExtCwFeature]()
}

// ClipDataCodec binds MAP-MS-DataTypes.ClipData.
func ClipDataCodec() ValueCodec[ClipData] {
	return compositeValueCodec[ClipData, *ClipData]()
}

// ClirDataCodec binds MAP-MS-DataTypes.ClirData.
func ClirDataCodec() ValueCodec[ClirData] {
	return compositeValueCodec[ClirData, *ClirData]()
}

// CallHoldDataCodec binds MAP-MS-DataTypes.CallHoldData.
func CallHoldDataCodec() ValueCodec[CallHoldData] {
	return compositeValueCodec[CallHoldData, *CallHoldData]()
}

// EctDataCodec binds MAP-MS-DataTypes.EctData.
func EctDataCodec() ValueCodec[EctData] {
	return compositeValueCodec[EctData, *EctData]()
}

// RequestedSubscriptionInfoCodec binds MAP-MS-DataTypes.RequestedSubscriptionInfo.
func RequestedSubscriptionInfoCodec() ValueCodec[RequestedSubscriptionInfo] {
	return compositeValueCodec[RequestedSubscriptionInfo, *RequestedSubscriptionInfo]()
}

// MSISDNBSListCodec binds MAP-MS-DataTypes.MSISDN-BS-List.
func MSISDNBSListCodec() ValueCodec[MSISDNBSList] {
	return pointerValueCodec(UnmarshalBERMSISDNBSList, MarshalBERMSISDNBSList, MarshalDERMSISDNBSList)
}

// MSISDNBSCodec binds MAP-MS-DataTypes.MSISDN-BS.
func MSISDNBSCodec() ValueCodec[MSISDNBS] {
	return compositeValueCodec[MSISDNBS, *MSISDNBS]()
}

// RequestedCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.RequestedCAMEL-SubscriptionInfo.
func RequestedCAMELSubscriptionInfoCodec() ValueCodec[BERValue[RequestedCAMELSubscriptionInfo]] {
	return integerValueCodec[RequestedCAMELSubscriptionInfo]("MAP-MS-DataTypes.RequestedCAMEL-SubscriptionInfo", "RequestedCAMEL-SubscriptionInfo", []primitiveRule[RequestedCAMELSubscriptionInfo]{{invalid: func(value RequestedCAMELSubscriptionInfo) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7 && int64(value) != 8)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8}", clause: "20", observed: func(value RequestedCAMELSubscriptionInfo) any { return int64(value) }}}, true)
}

// AdditionalRequestedCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.AdditionalRequestedCAMEL-SubscriptionInfo.
func AdditionalRequestedCAMELSubscriptionInfoCodec() ValueCodec[BERValue[AdditionalRequestedCAMELSubscriptionInfo]] {
	return integerValueCodec[AdditionalRequestedCAMELSubscriptionInfo]("MAP-MS-DataTypes.AdditionalRequestedCAMEL-SubscriptionInfo", "AdditionalRequestedCAMEL-SubscriptionInfo", nil, true)
}

// CallForwardingDataCodec binds MAP-MS-DataTypes.CallForwardingData.
func CallForwardingDataCodec() ValueCodec[CallForwardingData] {
	return compositeValueCodec[CallForwardingData, *CallForwardingData]()
}

// CallBarringDataCodec binds MAP-MS-DataTypes.CallBarringData.
func CallBarringDataCodec() ValueCodec[CallBarringData] {
	return compositeValueCodec[CallBarringData, *CallBarringData]()
}

// WrongPasswordAttemptsCounterCodec binds MAP-MS-DataTypes.WrongPasswordAttemptsCounter.
func WrongPasswordAttemptsCounterCodec() ValueCodec[BERValue[WrongPasswordAttemptsCounter]] {
	return integerValueCodec[WrongPasswordAttemptsCounter]("MAP-MS-DataTypes.WrongPasswordAttemptsCounter", "WrongPasswordAttemptsCounter", []primitiveRule[WrongPasswordAttemptsCounter]{{invalid: func(value WrongPasswordAttemptsCounter) bool { return !(int64(value) >= 0 && int64(value) <= 4) }, description: "(0..4)", clause: "51.4", observed: func(value WrongPasswordAttemptsCounter) any { return int64(value) }}}, false)
}

// ODBInfoCodec binds MAP-MS-DataTypes.ODB-Info.
func ODBInfoCodec() ValueCodec[ODBInfo] {
	return compositeValueCodec[ODBInfo, *ODBInfo]()
}

// CAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.CAMEL-SubscriptionInfo.
func CAMELSubscriptionInfoCodec() ValueCodec[CAMELSubscriptionInfo] {
	return compositeValueCodec[CAMELSubscriptionInfo, *CAMELSubscriptionInfo]()
}

// AnyTimeModificationArgCodec binds MAP-MS-DataTypes.AnyTimeModificationArg.
func AnyTimeModificationArgCodec() ValueCodec[AnyTimeModificationArg] {
	return compositeValueCodec[AnyTimeModificationArg, *AnyTimeModificationArg]()
}

// ModificationRequestForCWInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CW-Info.
func ModificationRequestForCWInfoCodec() ValueCodec[ModificationRequestForCWInfo] {
	return compositeValueCodec[ModificationRequestForCWInfo, *ModificationRequestForCWInfo]()
}

// ModificationRequestForCHInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CH-Info.
func ModificationRequestForCHInfoCodec() ValueCodec[ModificationRequestForCHInfo] {
	return compositeValueCodec[ModificationRequestForCHInfo, *ModificationRequestForCHInfo]()
}

// ModificationRequestForECTInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-ECT-Info.
func ModificationRequestForECTInfoCodec() ValueCodec[ModificationRequestForECTInfo] {
	return compositeValueCodec[ModificationRequestForECTInfo, *ModificationRequestForECTInfo]()
}

// ModificationRequestForCLIRInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CLIR-Info.
func ModificationRequestForCLIRInfoCodec() ValueCodec[ModificationRequestForCLIRInfo] {
	return compositeValueCodec[ModificationRequestForCLIRInfo, *ModificationRequestForCLIRInfo]()
}

// ModificationRequestForCLIPInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CLIP-Info.
func ModificationRequestForCLIPInfoCodec() ValueCodec[ModificationRequestForCLIPInfo] {
	return compositeValueCodec[ModificationRequestForCLIPInfo, *ModificationRequestForCLIPInfo]()
}

// ModificationRequestForCSGCodec binds MAP-MS-DataTypes.ModificationRequestFor-CSG.
func ModificationRequestForCSGCodec() ValueCodec[ModificationRequestForCSG] {
	return compositeValueCodec[ModificationRequestForCSG, *ModificationRequestForCSG]()
}

// RequestedServingNodeCodec binds MAP-MS-DataTypes.RequestedServingNode.
func RequestedServingNodeCodec() ValueCodec[BERValue[RequestedServingNode]] {
	return bitValueCodec("MAP-MS-DataTypes.RequestedServingNode", "RequestedServingNode", []primitiveRule[RequestedServingNode]{{invalid: func(value RequestedServingNode) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value RequestedServingNode) int { return value.BitLength }, encodedLength: func(value RequestedServingNode) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// ServingNodeCodec binds MAP-MS-DataTypes.ServingNode.
func ServingNodeCodec() ValueCodec[BERValue[ServingNode]] {
	return bitValueCodec("MAP-MS-DataTypes.ServingNode", "ServingNode", []primitiveRule[ServingNode]{{invalid: func(value ServingNode) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value ServingNode) int { return value.BitLength }, encodedLength: func(value ServingNode) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// AnyTimeModificationResCodec binds MAP-MS-DataTypes.AnyTimeModificationRes.
func AnyTimeModificationResCodec() ValueCodec[AnyTimeModificationRes] {
	return compositeValueCodec[AnyTimeModificationRes, *AnyTimeModificationRes]()
}

// ModificationRequestForCFInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CF-Info.
func ModificationRequestForCFInfoCodec() ValueCodec[ModificationRequestForCFInfo] {
	return compositeValueCodec[ModificationRequestForCFInfo, *ModificationRequestForCFInfo]()
}

// ModificationRequestForCBInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CB-Info.
func ModificationRequestForCBInfoCodec() ValueCodec[ModificationRequestForCBInfo] {
	return compositeValueCodec[ModificationRequestForCBInfo, *ModificationRequestForCBInfo]()
}

// ModificationRequestForODBDataCodec binds MAP-MS-DataTypes.ModificationRequestFor-ODB-data.
func ModificationRequestForODBDataCodec() ValueCodec[ModificationRequestForODBData] {
	return compositeValueCodec[ModificationRequestForODBData, *ModificationRequestForODBData]()
}

// ModificationRequestForCSICodec binds MAP-MS-DataTypes.ModificationRequestFor-CSI.
func ModificationRequestForCSICodec() ValueCodec[ModificationRequestForCSI] {
	return compositeValueCodec[ModificationRequestForCSI, *ModificationRequestForCSI]()
}

// ModificationRequestForIPSMGWDataCodec binds MAP-MS-DataTypes.ModificationRequestFor-IP-SM-GW-Data.
func ModificationRequestForIPSMGWDataCodec() ValueCodec[ModificationRequestForIPSMGWData] {
	return compositeValueCodec[ModificationRequestForIPSMGWData, *ModificationRequestForIPSMGWData]()
}

// ModificationInstructionCodec binds MAP-MS-DataTypes.ModificationInstruction.
func ModificationInstructionCodec() ValueCodec[BERValue[ModificationInstruction]] {
	return integerValueCodec[ModificationInstruction]("MAP-MS-DataTypes.ModificationInstruction", "ModificationInstruction", []primitiveRule[ModificationInstruction]{{invalid: func(value ModificationInstruction) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value ModificationInstruction) any { return int64(value) }}}, true)
}

// NoteSubscriberDataModifiedArgCodec binds MAP-MS-DataTypes.NoteSubscriberDataModifiedArg.
func NoteSubscriberDataModifiedArgCodec() ValueCodec[NoteSubscriberDataModifiedArg] {
	return compositeValueCodec[NoteSubscriberDataModifiedArg, *NoteSubscriberDataModifiedArg]()
}

// NoteSubscriberDataModifiedResCodec binds MAP-MS-DataTypes.NoteSubscriberDataModifiedRes.
func NoteSubscriberDataModifiedResCodec() ValueCodec[NoteSubscriberDataModifiedRes] {
	return compositeValueCodec[NoteSubscriberDataModifiedRes, *NoteSubscriberDataModifiedRes]()
}

// NoteMMEventArgCodec binds MAP-MS-DataTypes.NoteMM-EventArg.
func NoteMMEventArgCodec() ValueCodec[NoteMMEventArg] {
	return compositeValueCodec[NoteMMEventArg, *NoteMMEventArg]()
}

// NoteMMEventResCodec binds MAP-MS-DataTypes.NoteMM-EventRes.
func NoteMMEventResCodec() ValueCodec[NoteMMEventRes] {
	return compositeValueCodec[NoteMMEventRes, *NoteMMEventRes]()
}

// ExtSSInfoForCSECodec binds MAP-MS-DataTypes.Ext-SS-InfoFor-CSE.
func ExtSSInfoForCSECodec() ValueCodec[ExtSSInfoForCSE] {
	return compositeValueCodec[ExtSSInfoForCSE, *ExtSSInfoForCSE]()
}

// ExtForwardingInfoForCSECodec binds MAP-MS-DataTypes.Ext-ForwardingInfoFor-CSE.
func ExtForwardingInfoForCSECodec() ValueCodec[ExtForwardingInfoForCSE] {
	return compositeValueCodec[ExtForwardingInfoForCSE, *ExtForwardingInfoForCSE]()
}

// ExtCallBarringInfoForCSECodec binds MAP-MS-DataTypes.Ext-CallBarringInfoFor-CSE.
func ExtCallBarringInfoForCSECodec() ValueCodec[ExtCallBarringInfoForCSE] {
	return compositeValueCodec[ExtCallBarringInfoForCSE, *ExtCallBarringInfoForCSE]()
}

// UpdateVcsgLocationArgCodec binds MAP-MS-DataTypes.UpdateVcsgLocationArg.
func UpdateVcsgLocationArgCodec() ValueCodec[UpdateVcsgLocationArg] {
	return compositeValueCodec[UpdateVcsgLocationArg, *UpdateVcsgLocationArg]()
}

// UpdateVcsgLocationResCodec binds MAP-MS-DataTypes.UpdateVcsgLocationRes.
func UpdateVcsgLocationResCodec() ValueCodec[UpdateVcsgLocationRes] {
	return compositeValueCodec[UpdateVcsgLocationRes, *UpdateVcsgLocationRes]()
}

// CancelVcsgLocationArgCodec binds MAP-MS-DataTypes.CancelVcsgLocationArg.
func CancelVcsgLocationArgCodec() ValueCodec[CancelVcsgLocationArg] {
	return compositeValueCodec[CancelVcsgLocationArg, *CancelVcsgLocationArg]()
}

// CancelVcsgLocationResCodec binds MAP-MS-DataTypes.CancelVcsgLocationRes.
func CancelVcsgLocationResCodec() ValueCodec[CancelVcsgLocationRes] {
	return compositeValueCodec[CancelVcsgLocationRes, *CancelVcsgLocationRes]()
}

// CUGCheckInfoCodec binds MAP-CH-DataTypes.CUG-CheckInfo.
func CUGCheckInfoCodec() ValueCodec[CUGCheckInfo] {
	return compositeValueCodec[CUGCheckInfo, *CUGCheckInfo]()
}

// NumberOfForwardingCodec binds MAP-CH-DataTypes.NumberOfForwarding.
func NumberOfForwardingCodec() ValueCodec[BERValue[NumberOfForwarding]] {
	return integerValueCodec[NumberOfForwarding]("MAP-CH-DataTypes.NumberOfForwarding", "NumberOfForwarding", []primitiveRule[NumberOfForwarding]{{invalid: func(value NumberOfForwarding) bool { return !(int64(value) >= 1 && int64(value) <= 5) }, description: "(1..5)", clause: "51.4", observed: func(value NumberOfForwarding) any { return int64(value) }}}, false)
}

// SendRoutingInfoArgCodec binds MAP-CH-DataTypes.SendRoutingInfoArg.
func SendRoutingInfoArgCodec() ValueCodec[SendRoutingInfoArg] {
	return compositeValueCodec[SendRoutingInfoArg, *SendRoutingInfoArg]()
}

// SuppressionOfAnnouncementCodec binds MAP-CH-DataTypes.SuppressionOfAnnouncement.
func SuppressionOfAnnouncementCodec() ValueCodec[BERValue[SuppressionOfAnnouncement]] {
	return pointerValueCodec(UnmarshalBERSuppressionOfAnnouncement, MarshalBERSuppressionOfAnnouncement, MarshalDERSuppressionOfAnnouncement)
}

// SuppressMTSSCodec binds MAP-CH-DataTypes.SuppressMTSS.
func SuppressMTSSCodec() ValueCodec[BERValue[SuppressMTSS]] {
	return bitValueCodec("MAP-CH-DataTypes.SuppressMTSS", "SuppressMTSS", []primitiveRule[SuppressMTSS]{{invalid: func(value SuppressMTSS) bool { return !(value.BitLength >= 2 && value.BitLength <= 16) }, description: "SIZE (2..16)", clause: "51.5", length: func(value SuppressMTSS) int { return value.BitLength }, encodedLength: func(value SuppressMTSS) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}})
}

// InterrogationTypeCodec binds MAP-CH-DataTypes.InterrogationType.
func InterrogationTypeCodec() ValueCodec[BERValue[InterrogationType]] {
	return integerValueCodec[InterrogationType]("MAP-CH-DataTypes.InterrogationType", "InterrogationType", []primitiveRule[InterrogationType]{{invalid: func(value InterrogationType) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value InterrogationType) any { return int64(value) }}}, true)
}

// ORPhaseCodec binds MAP-CH-DataTypes.OR-Phase.
func ORPhaseCodec() ValueCodec[BERValue[ORPhase]] {
	return integerValueCodec[ORPhase]("MAP-CH-DataTypes.OR-Phase", "OR-Phase", []primitiveRule[ORPhase]{{invalid: func(value ORPhase) bool { return !(int64(value) >= 1 && int64(value) <= 127) }, description: "(1..127)", clause: "51.4", observed: func(value ORPhase) any { return int64(value) }}}, false)
}

// CallReferenceNumberCodec binds MAP-CH-DataTypes.CallReferenceNumber.
func CallReferenceNumberCodec() ValueCodec[BERValue[CallReferenceNumber]] {
	return octetValueCodec[CallReferenceNumber]("MAP-CH-DataTypes.CallReferenceNumber", "CallReferenceNumber", []primitiveRule[CallReferenceNumber]{{invalid: func(value CallReferenceNumber) bool { return !(len(value) >= 1 && len(value) <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value CallReferenceNumber) int { return len(value) }}})
}

// ForwardingReasonCodec binds MAP-CH-DataTypes.ForwardingReason.
func ForwardingReasonCodec() ValueCodec[BERValue[ForwardingReason]] {
	return integerValueCodec[ForwardingReason]("MAP-CH-DataTypes.ForwardingReason", "ForwardingReason", []primitiveRule[ForwardingReason]{{invalid: func(value ForwardingReason) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value ForwardingReason) any { return int64(value) }}}, true)
}

// SupportedCCBSPhaseCodec binds MAP-CH-DataTypes.SupportedCCBS-Phase.
func SupportedCCBSPhaseCodec() ValueCodec[BERValue[SupportedCCBSPhase]] {
	return integerValueCodec[SupportedCCBSPhase]("MAP-CH-DataTypes.SupportedCCBS-Phase", "SupportedCCBS-Phase", []primitiveRule[SupportedCCBSPhase]{{invalid: func(value SupportedCCBSPhase) bool { return !(int64(value) >= 1 && int64(value) <= 127) }, description: "(1..127)", clause: "51.4", observed: func(value SupportedCCBSPhase) any { return int64(value) }}}, false)
}

// CallDiversionTreatmentIndicatorCodec binds MAP-CH-DataTypes.CallDiversionTreatmentIndicator.
func CallDiversionTreatmentIndicatorCodec() ValueCodec[BERValue[CallDiversionTreatmentIndicator]] {
	return octetValueCodec[CallDiversionTreatmentIndicator]("MAP-CH-DataTypes.CallDiversionTreatmentIndicator", "CallDiversionTreatmentIndicator", []primitiveRule[CallDiversionTreatmentIndicator]{{invalid: func(value CallDiversionTreatmentIndicator) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value CallDiversionTreatmentIndicator) int { return len(value) }}})
}

// SendRoutingInfoResCodec binds MAP-CH-DataTypes.SendRoutingInfoRes.
func SendRoutingInfoResCodec() ValueCodec[SendRoutingInfoRes] {
	return compositeValueCodec[SendRoutingInfoRes, *SendRoutingInfoRes]()
}

// AllowedServicesCodec binds MAP-CH-DataTypes.AllowedServices.
func AllowedServicesCodec() ValueCodec[BERValue[AllowedServices]] {
	return bitValueCodec("MAP-CH-DataTypes.AllowedServices", "AllowedServices", []primitiveRule[AllowedServices]{{invalid: func(value AllowedServices) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value AllowedServices) int { return value.BitLength }, encodedLength: func(value AllowedServices) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// UnavailabilityCauseCodec binds MAP-CH-DataTypes.UnavailabilityCause.
func UnavailabilityCauseCodec() ValueCodec[BERValue[UnavailabilityCause]] {
	return integerValueCodec[UnavailabilityCause]("MAP-CH-DataTypes.UnavailabilityCause", "UnavailabilityCause", nil, true)
}

// CCBSIndicatorsCodec binds MAP-CH-DataTypes.CCBS-Indicators.
func CCBSIndicatorsCodec() ValueCodec[CCBSIndicators] {
	return compositeValueCodec[CCBSIndicators, *CCBSIndicators]()
}

// RoutingInfoCodec binds MAP-CH-DataTypes.RoutingInfo.
func RoutingInfoCodec() ValueCodec[RoutingInfo] {
	return compositeValueCodec[RoutingInfo, *RoutingInfo]()
}

// ForwardingDataCodec binds MAP-CH-DataTypes.ForwardingData.
func ForwardingDataCodec() ValueCodec[ForwardingData] {
	return compositeValueCodec[ForwardingData, *ForwardingData]()
}

// ProvideRoamingNumberArgCodec binds MAP-CH-DataTypes.ProvideRoamingNumberArg.
func ProvideRoamingNumberArgCodec() ValueCodec[ProvideRoamingNumberArg] {
	return compositeValueCodec[ProvideRoamingNumberArg, *ProvideRoamingNumberArg]()
}

// ProvideRoamingNumberResCodec binds MAP-CH-DataTypes.ProvideRoamingNumberRes.
func ProvideRoamingNumberResCodec() ValueCodec[ProvideRoamingNumberRes] {
	return compositeValueCodec[ProvideRoamingNumberRes, *ProvideRoamingNumberRes]()
}

// ResumeCallHandlingArgCodec binds MAP-CH-DataTypes.ResumeCallHandlingArg.
func ResumeCallHandlingArgCodec() ValueCodec[ResumeCallHandlingArg] {
	return compositeValueCodec[ResumeCallHandlingArg, *ResumeCallHandlingArg]()
}

// UUDataCodec binds MAP-CH-DataTypes.UU-Data.
func UUDataCodec() ValueCodec[UUData] {
	return compositeValueCodec[UUData, *UUData]()
}

// UUIndicatorCodec binds MAP-CH-DataTypes.UUIndicator.
func UUIndicatorCodec() ValueCodec[BERValue[UUIndicator]] {
	return octetValueCodec[UUIndicator]("MAP-CH-DataTypes.UUIndicator", "UUIndicator", []primitiveRule[UUIndicator]{{invalid: func(value UUIndicator) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value UUIndicator) int { return len(value) }}})
}

// UUICodec binds MAP-CH-DataTypes.UUI.
func UUICodec() ValueCodec[BERValue[UUI]] {
	return octetValueCodec[UUI]("MAP-CH-DataTypes.UUI", "UUI", []primitiveRule[UUI]{{invalid: func(value UUI) bool { return !(len(value) >= 1 && len(value) <= 131) }, description: "SIZE (1..131)", clause: "51.5", length: func(value UUI) int { return len(value) }}})
}

// ResumeCallHandlingResCodec binds MAP-CH-DataTypes.ResumeCallHandlingRes.
func ResumeCallHandlingResCodec() ValueCodec[ResumeCallHandlingRes] {
	return compositeValueCodec[ResumeCallHandlingRes, *ResumeCallHandlingRes]()
}

// CamelInfoCodec binds MAP-CH-DataTypes.CamelInfo.
func CamelInfoCodec() ValueCodec[CamelInfo] {
	return compositeValueCodec[CamelInfo, *CamelInfo]()
}

// ExtendedRoutingInfoCodec binds MAP-CH-DataTypes.ExtendedRoutingInfo.
func ExtendedRoutingInfoCodec() ValueCodec[ExtendedRoutingInfo] {
	return compositeValueCodec[ExtendedRoutingInfo, *ExtendedRoutingInfo]()
}

// CamelRoutingInfoCodec binds MAP-CH-DataTypes.CamelRoutingInfo.
func CamelRoutingInfoCodec() ValueCodec[CamelRoutingInfo] {
	return compositeValueCodec[CamelRoutingInfo, *CamelRoutingInfo]()
}

// GmscCamelSubscriptionInfoCodec binds MAP-CH-DataTypes.GmscCamelSubscriptionInfo.
func GmscCamelSubscriptionInfoCodec() ValueCodec[GmscCamelSubscriptionInfo] {
	return compositeValueCodec[GmscCamelSubscriptionInfo, *GmscCamelSubscriptionInfo]()
}

// SetReportingStateArgCodec binds MAP-CH-DataTypes.SetReportingStateArg.
func SetReportingStateArgCodec() ValueCodec[SetReportingStateArg] {
	return compositeValueCodec[SetReportingStateArg, *SetReportingStateArg]()
}

// ReportingStateCodec binds MAP-CH-DataTypes.ReportingState.
func ReportingStateCodec() ValueCodec[BERValue[ReportingState]] {
	return integerValueCodec[ReportingState]("MAP-CH-DataTypes.ReportingState", "ReportingState", nil, true)
}

// SetReportingStateResCodec binds MAP-CH-DataTypes.SetReportingStateRes.
func SetReportingStateResCodec() ValueCodec[SetReportingStateRes] {
	return compositeValueCodec[SetReportingStateRes, *SetReportingStateRes]()
}

// CCBSSubscriberStatusCodec binds MAP-CH-DataTypes.CCBS-SubscriberStatus.
func CCBSSubscriberStatusCodec() ValueCodec[BERValue[CCBSSubscriberStatus]] {
	return integerValueCodec[CCBSSubscriberStatus]("MAP-CH-DataTypes.CCBS-SubscriberStatus", "CCBS-SubscriberStatus", nil, true)
}

// StatusReportArgCodec binds MAP-CH-DataTypes.StatusReportArg.
func StatusReportArgCodec() ValueCodec[StatusReportArg] {
	return compositeValueCodec[StatusReportArg, *StatusReportArg]()
}

// EventReportDataCodec binds MAP-CH-DataTypes.EventReportData.
func EventReportDataCodec() ValueCodec[EventReportData] {
	return compositeValueCodec[EventReportData, *EventReportData]()
}

// CallReportDataCodec binds MAP-CH-DataTypes.CallReportData.
func CallReportDataCodec() ValueCodec[CallReportData] {
	return compositeValueCodec[CallReportData, *CallReportData]()
}

// MonitoringModeCodec binds MAP-CH-DataTypes.MonitoringMode.
func MonitoringModeCodec() ValueCodec[BERValue[MonitoringMode]] {
	return integerValueCodec[MonitoringMode]("MAP-CH-DataTypes.MonitoringMode", "MonitoringMode", nil, true)
}

// CallOutcomeCodec binds MAP-CH-DataTypes.CallOutcome.
func CallOutcomeCodec() ValueCodec[BERValue[CallOutcome]] {
	return integerValueCodec[CallOutcome]("MAP-CH-DataTypes.CallOutcome", "CallOutcome", nil, true)
}

// StatusReportResCodec binds MAP-CH-DataTypes.StatusReportRes.
func StatusReportResCodec() ValueCodec[StatusReportRes] {
	return compositeValueCodec[StatusReportRes, *StatusReportRes]()
}

// RemoteUserFreeArgCodec binds MAP-CH-DataTypes.RemoteUserFreeArg.
func RemoteUserFreeArgCodec() ValueCodec[RemoteUserFreeArg] {
	return compositeValueCodec[RemoteUserFreeArg, *RemoteUserFreeArg]()
}

// RemoteUserFreeResCodec binds MAP-CH-DataTypes.RemoteUserFreeRes.
func RemoteUserFreeResCodec() ValueCodec[RemoteUserFreeRes] {
	return compositeValueCodec[RemoteUserFreeRes, *RemoteUserFreeRes]()
}

// RUFOutcomeCodec binds MAP-CH-DataTypes.RUF-Outcome.
func RUFOutcomeCodec() ValueCodec[BERValue[RUFOutcome]] {
	return integerValueCodec[RUFOutcome]("MAP-CH-DataTypes.RUF-Outcome", "RUF-Outcome", nil, true)
}

// ISTAlertArgCodec binds MAP-CH-DataTypes.IST-AlertArg.
func ISTAlertArgCodec() ValueCodec[ISTAlertArg] {
	return compositeValueCodec[ISTAlertArg, *ISTAlertArg]()
}

// ISTAlertResCodec binds MAP-CH-DataTypes.IST-AlertRes.
func ISTAlertResCodec() ValueCodec[ISTAlertRes] {
	return compositeValueCodec[ISTAlertRes, *ISTAlertRes]()
}

// ISTCommandArgCodec binds MAP-CH-DataTypes.IST-CommandArg.
func ISTCommandArgCodec() ValueCodec[ISTCommandArg] {
	return compositeValueCodec[ISTCommandArg, *ISTCommandArg]()
}

// ISTCommandResCodec binds MAP-CH-DataTypes.IST-CommandRes.
func ISTCommandResCodec() ValueCodec[ISTCommandRes] {
	return compositeValueCodec[ISTCommandRes, *ISTCommandRes]()
}

// CallTerminationIndicatorCodec binds MAP-CH-DataTypes.CallTerminationIndicator.
func CallTerminationIndicatorCodec() ValueCodec[BERValue[CallTerminationIndicator]] {
	return integerValueCodec[CallTerminationIndicator]("MAP-CH-DataTypes.CallTerminationIndicator", "CallTerminationIndicator", nil, true)
}

// ReleaseResourcesArgCodec binds MAP-CH-DataTypes.ReleaseResourcesArg.
func ReleaseResourcesArgCodec() ValueCodec[ReleaseResourcesArg] {
	return compositeValueCodec[ReleaseResourcesArg, *ReleaseResourcesArg]()
}

// ReleaseResourcesResCodec binds MAP-CH-DataTypes.ReleaseResourcesRes.
func ReleaseResourcesResCodec() ValueCodec[ReleaseResourcesRes] {
	return compositeValueCodec[ReleaseResourcesRes, *ReleaseResourcesRes]()
}

// MAPDialoguePDUCodec binds MAP-DialogueInformation.MAP-DialoguePDU.
func MAPDialoguePDUCodec() ValueCodec[MAPDialoguePDU] {
	return compositeValueCodec[MAPDialoguePDU, *MAPDialoguePDU]()
}

// MAPOpenInfoCodec binds MAP-DialogueInformation.MAP-OpenInfo.
func MAPOpenInfoCodec() ValueCodec[MAPOpenInfo] {
	return compositeValueCodec[MAPOpenInfo, *MAPOpenInfo]()
}

// MAPAcceptInfoCodec binds MAP-DialogueInformation.MAP-AcceptInfo.
func MAPAcceptInfoCodec() ValueCodec[MAPAcceptInfo] {
	return compositeValueCodec[MAPAcceptInfo, *MAPAcceptInfo]()
}

// MAPCloseInfoCodec binds MAP-DialogueInformation.MAP-CloseInfo.
func MAPCloseInfoCodec() ValueCodec[MAPCloseInfo] {
	return compositeValueCodec[MAPCloseInfo, *MAPCloseInfo]()
}

// MAPRefuseInfoCodec binds MAP-DialogueInformation.MAP-RefuseInfo.
func MAPRefuseInfoCodec() ValueCodec[MAPRefuseInfo] {
	return compositeValueCodec[MAPRefuseInfo, *MAPRefuseInfo]()
}

// ReasonCodec binds MAP-DialogueInformation.Reason.
func ReasonCodec() ValueCodec[BERValue[Reason]] {
	return integerValueCodec[Reason]("MAP-DialogueInformation.Reason", "Reason", []primitiveRule[Reason]{{invalid: func(value Reason) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value Reason) any { return int64(value) }}}, true)
}

// MAPUserAbortInfoCodec binds MAP-DialogueInformation.MAP-UserAbortInfo.
func MAPUserAbortInfoCodec() ValueCodec[MAPUserAbortInfo] {
	return compositeValueCodec[MAPUserAbortInfo, *MAPUserAbortInfo]()
}

// MAPUserAbortChoiceCodec binds MAP-DialogueInformation.MAP-UserAbortChoice.
func MAPUserAbortChoiceCodec() ValueCodec[MAPUserAbortChoice] {
	return compositeValueCodec[MAPUserAbortChoice, *MAPUserAbortChoice]()
}

// ResourceUnavailableReasonCodec binds MAP-DialogueInformation.ResourceUnavailableReason.
func ResourceUnavailableReasonCodec() ValueCodec[BERValue[ResourceUnavailableReason]] {
	return integerValueCodec[ResourceUnavailableReason]("MAP-DialogueInformation.ResourceUnavailableReason", "ResourceUnavailableReason", []primitiveRule[ResourceUnavailableReason]{{invalid: func(value ResourceUnavailableReason) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value ResourceUnavailableReason) any { return int64(value) }}}, true)
}

// ProcedureCancellationReasonCodec binds MAP-DialogueInformation.ProcedureCancellationReason.
func ProcedureCancellationReasonCodec() ValueCodec[BERValue[ProcedureCancellationReason]] {
	return integerValueCodec[ProcedureCancellationReason]("MAP-DialogueInformation.ProcedureCancellationReason", "ProcedureCancellationReason", []primitiveRule[ProcedureCancellationReason]{{invalid: func(value ProcedureCancellationReason) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value ProcedureCancellationReason) any { return int64(value) }}}, true)
}

// MAPProviderAbortInfoCodec binds MAP-DialogueInformation.MAP-ProviderAbortInfo.
func MAPProviderAbortInfoCodec() ValueCodec[MAPProviderAbortInfo] {
	return compositeValueCodec[MAPProviderAbortInfo, *MAPProviderAbortInfo]()
}

// MAPProviderAbortReasonCodec binds MAP-DialogueInformation.MAP-ProviderAbortReason.
func MAPProviderAbortReasonCodec() ValueCodec[BERValue[MAPProviderAbortReason]] {
	return integerValueCodec[MAPProviderAbortReason]("MAP-DialogueInformation.MAP-ProviderAbortReason", "MAP-ProviderAbortReason", []primitiveRule[MAPProviderAbortReason]{{invalid: func(value MAPProviderAbortReason) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MAPProviderAbortReason) any { return int64(value) }}}, true)
}

// PrepareGroupCallArgCodec binds MAP-GR-DataTypes.PrepareGroupCallArg.
func PrepareGroupCallArgCodec() ValueCodec[PrepareGroupCallArg] {
	return compositeValueCodec[PrepareGroupCallArg, *PrepareGroupCallArg]()
}

// VSTKCodec binds MAP-GR-DataTypes.VSTK.
func VSTKCodec() ValueCodec[BERValue[VSTK]] {
	return octetValueCodec[VSTK]("MAP-GR-DataTypes.VSTK", "VSTK", []primitiveRule[VSTK]{{invalid: func(value VSTK) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value VSTK) int { return len(value) }}})
}

// VSTKRANDCodec binds MAP-GR-DataTypes.VSTK-RAND.
func VSTKRANDCodec() ValueCodec[BERValue[VSTKRAND]] {
	return octetValueCodec[VSTKRAND]("MAP-GR-DataTypes.VSTK-RAND", "VSTK-RAND", []primitiveRule[VSTKRAND]{{invalid: func(value VSTKRAND) bool { return !(len(value) == 5) }, description: "SIZE (5)", clause: "51.5", length: func(value VSTKRAND) int { return len(value) }}})
}

// PrepareGroupCallResCodec binds MAP-GR-DataTypes.PrepareGroupCallRes.
func PrepareGroupCallResCodec() ValueCodec[PrepareGroupCallRes] {
	return compositeValueCodec[PrepareGroupCallRes, *PrepareGroupCallRes]()
}

// SendGroupCallEndSignalArgCodec binds MAP-GR-DataTypes.SendGroupCallEndSignalArg.
func SendGroupCallEndSignalArgCodec() ValueCodec[SendGroupCallEndSignalArg] {
	return compositeValueCodec[SendGroupCallEndSignalArg, *SendGroupCallEndSignalArg]()
}

// TalkerPriorityCodec binds MAP-GR-DataTypes.TalkerPriority.
func TalkerPriorityCodec() ValueCodec[BERValue[TalkerPriority]] {
	return integerValueCodec[TalkerPriority]("MAP-GR-DataTypes.TalkerPriority", "TalkerPriority", []primitiveRule[TalkerPriority]{{invalid: func(value TalkerPriority) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value TalkerPriority) any { return int64(value) }}}, true)
}

// SendGroupCallEndSignalResCodec binds MAP-GR-DataTypes.SendGroupCallEndSignalRes.
func SendGroupCallEndSignalResCodec() ValueCodec[SendGroupCallEndSignalRes] {
	return compositeValueCodec[SendGroupCallEndSignalRes, *SendGroupCallEndSignalRes]()
}

// ForwardGroupCallSignallingArgCodec binds MAP-GR-DataTypes.ForwardGroupCallSignallingArg.
func ForwardGroupCallSignallingArgCodec() ValueCodec[ForwardGroupCallSignallingArg] {
	return compositeValueCodec[ForwardGroupCallSignallingArg, *ForwardGroupCallSignallingArg]()
}

// ProcessGroupCallSignallingArgCodec binds MAP-GR-DataTypes.ProcessGroupCallSignallingArg.
func ProcessGroupCallSignallingArgCodec() ValueCodec[ProcessGroupCallSignallingArg] {
	return compositeValueCodec[ProcessGroupCallSignallingArg, *ProcessGroupCallSignallingArg]()
}

// GroupKeyNumberCodec binds MAP-GR-DataTypes.GroupKeyNumber.
func GroupKeyNumberCodec() ValueCodec[BERValue[GroupKeyNumber]] {
	return integerValueCodec[GroupKeyNumber]("MAP-GR-DataTypes.GroupKeyNumber", "GroupKeyNumber", []primitiveRule[GroupKeyNumber]{{invalid: func(value GroupKeyNumber) bool { return !(int64(value) >= 0 && int64(value) <= 15) }, description: "(0..15)", clause: "51.4", observed: func(value GroupKeyNumber) any { return int64(value) }}}, false)
}

// CODECInfoCodec binds MAP-GR-DataTypes.CODEC-Info.
func CODECInfoCodec() ValueCodec[BERValue[CODECInfo]] {
	return octetValueCodec[CODECInfo]("MAP-GR-DataTypes.CODEC-Info", "CODEC-Info", []primitiveRule[CODECInfo]{{invalid: func(value CODECInfo) bool { return !(len(value) >= 5 && len(value) <= 10) }, description: "SIZE (5..10)", clause: "51.5", length: func(value CODECInfo) int { return len(value) }}})
}

// CipheringAlgorithmCodec binds MAP-GR-DataTypes.CipheringAlgorithm.
func CipheringAlgorithmCodec() ValueCodec[BERValue[CipheringAlgorithm]] {
	return octetValueCodec[CipheringAlgorithm]("MAP-GR-DataTypes.CipheringAlgorithm", "CipheringAlgorithm", []primitiveRule[CipheringAlgorithm]{{invalid: func(value CipheringAlgorithm) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value CipheringAlgorithm) int { return len(value) }}})
}

// StateAttributesCodec binds MAP-GR-DataTypes.StateAttributes.
func StateAttributesCodec() ValueCodec[StateAttributes] {
	return compositeValueCodec[StateAttributes, *StateAttributes]()
}

// SendGroupCallInfoArgCodec binds MAP-GR-DataTypes.SendGroupCallInfoArg.
func SendGroupCallInfoArgCodec() ValueCodec[SendGroupCallInfoArg] {
	return compositeValueCodec[SendGroupCallInfoArg, *SendGroupCallInfoArg]()
}

// GRRequestedInfoCodec binds MAP-GR-DataTypes.RequestedInfo.
func GRRequestedInfoCodec() ValueCodec[BERValue[GRRequestedInfo]] {
	return integerValueCodec[GRRequestedInfo]("MAP-GR-DataTypes.RequestedInfo", "RequestedInfo", nil, true)
}

// SendGroupCallInfoResCodec binds MAP-GR-DataTypes.SendGroupCallInfoRes.
func SendGroupCallInfoResCodec() ValueCodec[SendGroupCallInfoRes] {
	return compositeValueCodec[SendGroupCallInfoRes, *SendGroupCallInfoRes]()
}

// RoutingInfoForSMArgCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Arg.
func RoutingInfoForSMArgCodec() ValueCodec[RoutingInfoForSMArg] {
	return compositeValueCodec[RoutingInfoForSMArg, *RoutingInfoForSMArg]()
}

// SMDeliveryNotIntendedCodec binds MAP-SM-DataTypes.SM-DeliveryNotIntended.
func SMDeliveryNotIntendedCodec() ValueCodec[BERValue[SMDeliveryNotIntended]] {
	return integerValueCodec[SMDeliveryNotIntended]("MAP-SM-DataTypes.SM-DeliveryNotIntended", "SM-DeliveryNotIntended", nil, true)
}

// SMRPMTICodec binds MAP-SM-DataTypes.SM-RP-MTI.
func SMRPMTICodec() ValueCodec[BERValue[SMRPMTI]] {
	return integerValueCodec[SMRPMTI]("MAP-SM-DataTypes.SM-RP-MTI", "SM-RP-MTI", []primitiveRule[SMRPMTI]{{invalid: func(value SMRPMTI) bool { return !(int64(value) >= 0 && int64(value) <= 10) }, description: "(0..10)", clause: "51.4", observed: func(value SMRPMTI) any { return int64(value) }}}, false)
}

// SMRPSMEACodec binds MAP-SM-DataTypes.SM-RP-SMEA.
func SMRPSMEACodec() ValueCodec[BERValue[SMRPSMEA]] {
	return octetValueCodec[SMRPSMEA]("MAP-SM-DataTypes.SM-RP-SMEA", "SM-RP-SMEA", []primitiveRule[SMRPSMEA]{{invalid: func(value SMRPSMEA) bool { return !(len(value) >= 1 && len(value) <= 12) }, description: "SIZE (1..12)", clause: "51.5", length: func(value SMRPSMEA) int { return len(value) }}})
}

// RoutingInfoForSMResCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Res.
func RoutingInfoForSMResCodec() ValueCodec[RoutingInfoForSMRes] {
	return compositeValueCodec[RoutingInfoForSMRes, *RoutingInfoForSMRes]()
}

// IPSMGWGuidanceCodec binds MAP-SM-DataTypes.IP-SM-GW-Guidance.
func IPSMGWGuidanceCodec() ValueCodec[IPSMGWGuidance] {
	return compositeValueCodec[IPSMGWGuidance, *IPSMGWGuidance]()
}

// LocationInfoWithLMSICodec binds MAP-SM-DataTypes.LocationInfoWithLMSI.
func LocationInfoWithLMSICodec() ValueCodec[LocationInfoWithLMSI] {
	return compositeValueCodec[LocationInfoWithLMSI, *LocationInfoWithLMSI]()
}

// AdditionalNumberCodec binds MAP-SM-DataTypes.Additional-Number.
func AdditionalNumberCodec() ValueCodec[AdditionalNumber] {
	return compositeValueCodec[AdditionalNumber, *AdditionalNumber]()
}

// MOForwardSMArgCodec binds MAP-SM-DataTypes.MO-ForwardSM-Arg.
func MOForwardSMArgCodec() ValueCodec[MOForwardSMArg] {
	return compositeValueCodec[MOForwardSMArg, *MOForwardSMArg]()
}

// MOForwardSMResCodec binds MAP-SM-DataTypes.MO-ForwardSM-Res.
func MOForwardSMResCodec() ValueCodec[MOForwardSMRes] {
	return compositeValueCodec[MOForwardSMRes, *MOForwardSMRes]()
}

// MTForwardSMArgCodec binds MAP-SM-DataTypes.MT-ForwardSM-Arg.
func MTForwardSMArgCodec() ValueCodec[MTForwardSMArg] {
	return compositeValueCodec[MTForwardSMArg, *MTForwardSMArg]()
}

// CorrelationIDCodec binds MAP-SM-DataTypes.CorrelationID.
func CorrelationIDCodec() ValueCodec[CorrelationID] {
	return compositeValueCodec[CorrelationID, *CorrelationID]()
}

// SIPURICodec binds MAP-SM-DataTypes.SIP-URI.
func SIPURICodec() ValueCodec[BERValue[SIPURI]] {
	return octetValueCodec[SIPURI]("MAP-SM-DataTypes.SIP-URI", "SIP-URI", nil)
}

// MTForwardSMResCodec binds MAP-SM-DataTypes.MT-ForwardSM-Res.
func MTForwardSMResCodec() ValueCodec[MTForwardSMRes] {
	return compositeValueCodec[MTForwardSMRes, *MTForwardSMRes]()
}

// SMRPDACodec binds MAP-SM-DataTypes.SM-RP-DA.
func SMRPDACodec() ValueCodec[SMRPDA] {
	return compositeValueCodec[SMRPDA, *SMRPDA]()
}

// SMRPOACodec binds MAP-SM-DataTypes.SM-RP-OA.
func SMRPOACodec() ValueCodec[SMRPOA] {
	return compositeValueCodec[SMRPOA, *SMRPOA]()
}

// SMDeliveryTimerValueCodec binds MAP-SM-DataTypes.SM-DeliveryTimerValue.
func SMDeliveryTimerValueCodec() ValueCodec[BERValue[SMDeliveryTimerValue]] {
	return integerValueCodec[SMDeliveryTimerValue]("MAP-SM-DataTypes.SM-DeliveryTimerValue", "SM-DeliveryTimerValue", []primitiveRule[SMDeliveryTimerValue]{{invalid: func(value SMDeliveryTimerValue) bool { return !(int64(value) >= 30 && int64(value) <= 600) }, description: "(30..600)", clause: "51.4", observed: func(value SMDeliveryTimerValue) any { return int64(value) }}}, false)
}

// ReportSMDeliveryStatusArgCodec binds MAP-SM-DataTypes.ReportSM-DeliveryStatusArg.
func ReportSMDeliveryStatusArgCodec() ValueCodec[ReportSMDeliveryStatusArg] {
	return compositeValueCodec[ReportSMDeliveryStatusArg, *ReportSMDeliveryStatusArg]()
}

// SMDeliveryOutcomeCodec binds MAP-SM-DataTypes.SM-DeliveryOutcome.
func SMDeliveryOutcomeCodec() ValueCodec[BERValue[SMDeliveryOutcome]] {
	return integerValueCodec[SMDeliveryOutcome]("MAP-SM-DataTypes.SM-DeliveryOutcome", "SM-DeliveryOutcome", []primitiveRule[SMDeliveryOutcome]{{invalid: func(value SMDeliveryOutcome) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value SMDeliveryOutcome) any { return int64(value) }}}, true)
}

// ReportSMDeliveryStatusResCodec binds MAP-SM-DataTypes.ReportSM-DeliveryStatusRes.
func ReportSMDeliveryStatusResCodec() ValueCodec[ReportSMDeliveryStatusRes] {
	return compositeValueCodec[ReportSMDeliveryStatusRes, *ReportSMDeliveryStatusRes]()
}

// SMServingNodeAddressListCodec binds MAP-SM-DataTypes.SMServingNodeAddressList.
func SMServingNodeAddressListCodec() ValueCodec[SMServingNodeAddressList] {
	return pointerValueCodec(UnmarshalBERSMServingNodeAddressList, MarshalBERSMServingNodeAddressList, MarshalDERSMServingNodeAddressList)
}

// SMServingNodeAddressCodec binds MAP-SM-DataTypes.SMServingNodeAddress.
func SMServingNodeAddressCodec() ValueCodec[SMServingNodeAddress] {
	return compositeValueCodec[SMServingNodeAddress, *SMServingNodeAddress]()
}

// AlertServiceCentreArgCodec binds MAP-SM-DataTypes.AlertServiceCentreArg.
func AlertServiceCentreArgCodec() ValueCodec[AlertServiceCentreArg] {
	return compositeValueCodec[AlertServiceCentreArg, *AlertServiceCentreArg]()
}

// SmsGmscAlertEventCodec binds MAP-SM-DataTypes.SmsGmsc-Alert-Event.
func SmsGmscAlertEventCodec() ValueCodec[BERValue[SmsGmscAlertEvent]] {
	return integerValueCodec[SmsGmscAlertEvent]("MAP-SM-DataTypes.SmsGmsc-Alert-Event", "SmsGmsc-Alert-Event", []primitiveRule[SmsGmscAlertEvent]{{invalid: func(value SmsGmscAlertEvent) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SmsGmscAlertEvent) any { return int64(value) }}}, true)
}

// InformServiceCentreArgCodec binds MAP-SM-DataTypes.InformServiceCentreArg.
func InformServiceCentreArgCodec() ValueCodec[InformServiceCentreArg] {
	return compositeValueCodec[InformServiceCentreArg, *InformServiceCentreArg]()
}

// MWStatusCodec binds MAP-SM-DataTypes.MW-Status.
func MWStatusCodec() ValueCodec[BERValue[MWStatus]] {
	return bitValueCodec("MAP-SM-DataTypes.MW-Status", "MW-Status", []primitiveRule[MWStatus]{{invalid: func(value MWStatus) bool { return !(value.BitLength >= 6 && value.BitLength <= 16) }, description: "SIZE (6..16)", clause: "51.5", length: func(value MWStatus) int { return value.BitLength }, encodedLength: func(value MWStatus) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}})
}

// ReadyForSMArgCodec binds MAP-SM-DataTypes.ReadyForSM-Arg.
func ReadyForSMArgCodec() ValueCodec[ReadyForSMArg] {
	return compositeValueCodec[ReadyForSMArg, *ReadyForSMArg]()
}

// ReadyForSMResCodec binds MAP-SM-DataTypes.ReadyForSM-Res.
func ReadyForSMResCodec() ValueCodec[ReadyForSMRes] {
	return compositeValueCodec[ReadyForSMRes, *ReadyForSMRes]()
}

// AlertReasonCodec binds MAP-SM-DataTypes.AlertReason.
func AlertReasonCodec() ValueCodec[BERValue[AlertReason]] {
	return integerValueCodec[AlertReason]("MAP-SM-DataTypes.AlertReason", "AlertReason", []primitiveRule[AlertReason]{{invalid: func(value AlertReason) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value AlertReason) any { return int64(value) }}}, true)
}

// MTForwardSMVGCSArgCodec binds MAP-SM-DataTypes.MT-ForwardSM-VGCS-Arg.
func MTForwardSMVGCSArgCodec() ValueCodec[MTForwardSMVGCSArg] {
	return compositeValueCodec[MTForwardSMVGCSArg, *MTForwardSMVGCSArg]()
}

// MTForwardSMVGCSResCodec binds MAP-SM-DataTypes.MT-ForwardSM-VGCS-Res.
func MTForwardSMVGCSResCodec() ValueCodec[MTForwardSMVGCSRes] {
	return compositeValueCodec[MTForwardSMVGCSRes, *MTForwardSMVGCSRes]()
}

// DispatcherListCodec binds MAP-SM-DataTypes.DispatcherList.
func DispatcherListCodec() ValueCodec[DispatcherList] {
	return pointerValueCodec(UnmarshalBERDispatcherList, MarshalBERDispatcherList, MarshalDERDispatcherList)
}

// AdditionalDispatcherListCodec binds MAP-SM-DataTypes.AdditionalDispatcherList.
func AdditionalDispatcherListCodec() ValueCodec[AdditionalDispatcherList] {
	return pointerValueCodec(UnmarshalBERAdditionalDispatcherList, MarshalBERAdditionalDispatcherList, MarshalDERAdditionalDispatcherList)
}

// RoutingInfoForLCSArgCodec binds MAP-LCS-DataTypes.RoutingInfoForLCS-Arg.
func RoutingInfoForLCSArgCodec() ValueCodec[RoutingInfoForLCSArg] {
	return compositeValueCodec[RoutingInfoForLCSArg, *RoutingInfoForLCSArg]()
}

// RoutingInfoForLCSResCodec binds MAP-LCS-DataTypes.RoutingInfoForLCS-Res.
func RoutingInfoForLCSResCodec() ValueCodec[RoutingInfoForLCSRes] {
	return compositeValueCodec[RoutingInfoForLCSRes, *RoutingInfoForLCSRes]()
}

// LCSLocationInfoCodec binds MAP-LCS-DataTypes.LCSLocationInfo.
func LCSLocationInfoCodec() ValueCodec[LCSLocationInfo] {
	return compositeValueCodec[LCSLocationInfo, *LCSLocationInfo]()
}

// ProvideSubscriberLocationArgCodec binds MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg.
func ProvideSubscriberLocationArgCodec() ValueCodec[ProvideSubscriberLocationArg] {
	return compositeValueCodec[ProvideSubscriberLocationArg, *ProvideSubscriberLocationArg]()
}

// LocationTypeCodec binds MAP-LCS-DataTypes.LocationType.
func LocationTypeCodec() ValueCodec[LocationType] {
	return compositeValueCodec[LocationType, *LocationType]()
}

// LocationEstimateTypeCodec binds MAP-LCS-DataTypes.LocationEstimateType.
func LocationEstimateTypeCodec() ValueCodec[BERValue[LocationEstimateType]] {
	return integerValueCodec[LocationEstimateType]("MAP-LCS-DataTypes.LocationEstimateType", "LocationEstimateType", nil, true)
}

// DeferredLocationEventTypeCodec binds MAP-LCS-DataTypes.DeferredLocationEventType.
func DeferredLocationEventTypeCodec() ValueCodec[BERValue[DeferredLocationEventType]] {
	return bitValueCodec("MAP-LCS-DataTypes.DeferredLocationEventType", "DeferredLocationEventType", []primitiveRule[DeferredLocationEventType]{{invalid: func(value DeferredLocationEventType) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value DeferredLocationEventType) int { return value.BitLength }, encodedLength: func(value DeferredLocationEventType) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// LCSClientIDCodec binds MAP-LCS-DataTypes.LCS-ClientID.
func LCSClientIDCodec() ValueCodec[LCSClientID] {
	return compositeValueCodec[LCSClientID, *LCSClientID]()
}

// LCSClientTypeCodec binds MAP-LCS-DataTypes.LCSClientType.
func LCSClientTypeCodec() ValueCodec[BERValue[LCSClientType]] {
	return integerValueCodec[LCSClientType]("MAP-LCS-DataTypes.LCSClientType", "LCSClientType", nil, true)
}

// LCSClientNameCodec binds MAP-LCS-DataTypes.LCSClientName.
func LCSClientNameCodec() ValueCodec[LCSClientName] {
	return compositeValueCodec[LCSClientName, *LCSClientName]()
}

// NameStringCodec binds MAP-LCS-DataTypes.NameString.
func NameStringCodec() ValueCodec[BERValue[NameString]] {
	return pointerValueCodec(UnmarshalBERNameString, MarshalBERNameString, MarshalDERNameString)
}

// LCSRequestorIDCodec binds MAP-LCS-DataTypes.LCSRequestorID.
func LCSRequestorIDCodec() ValueCodec[LCSRequestorID] {
	return compositeValueCodec[LCSRequestorID, *LCSRequestorID]()
}

// RequestorIDStringCodec binds MAP-LCS-DataTypes.RequestorIDString.
func RequestorIDStringCodec() ValueCodec[BERValue[RequestorIDString]] {
	return pointerValueCodec(UnmarshalBERRequestorIDString, MarshalBERRequestorIDString, MarshalDERRequestorIDString)
}

// LCSFormatIndicatorCodec binds MAP-LCS-DataTypes.LCS-FormatIndicator.
func LCSFormatIndicatorCodec() ValueCodec[BERValue[LCSFormatIndicator]] {
	return integerValueCodec[LCSFormatIndicator]("MAP-LCS-DataTypes.LCS-FormatIndicator", "LCS-FormatIndicator", nil, true)
}

// LCSPriorityCodec binds MAP-LCS-DataTypes.LCS-Priority.
func LCSPriorityCodec() ValueCodec[BERValue[LCSPriority]] {
	return octetValueCodec[LCSPriority]("MAP-LCS-DataTypes.LCS-Priority", "LCS-Priority", []primitiveRule[LCSPriority]{{invalid: func(value LCSPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value LCSPriority) int { return len(value) }}})
}

// LCSQoSCodec binds MAP-LCS-DataTypes.LCS-QoS.
func LCSQoSCodec() ValueCodec[LCSQoS] {
	return compositeValueCodec[LCSQoS, *LCSQoS]()
}

// HorizontalAccuracyCodec binds MAP-LCS-DataTypes.Horizontal-Accuracy.
func HorizontalAccuracyCodec() ValueCodec[BERValue[HorizontalAccuracy]] {
	return octetValueCodec[HorizontalAccuracy]("MAP-LCS-DataTypes.Horizontal-Accuracy", "Horizontal-Accuracy", []primitiveRule[HorizontalAccuracy]{{invalid: func(value HorizontalAccuracy) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value HorizontalAccuracy) int { return len(value) }}})
}

// VerticalAccuracyCodec binds MAP-LCS-DataTypes.Vertical-Accuracy.
func VerticalAccuracyCodec() ValueCodec[BERValue[VerticalAccuracy]] {
	return octetValueCodec[VerticalAccuracy]("MAP-LCS-DataTypes.Vertical-Accuracy", "Vertical-Accuracy", []primitiveRule[VerticalAccuracy]{{invalid: func(value VerticalAccuracy) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value VerticalAccuracy) int { return len(value) }}})
}

// ResponseTimeCodec binds MAP-LCS-DataTypes.ResponseTime.
func ResponseTimeCodec() ValueCodec[ResponseTime] {
	return compositeValueCodec[ResponseTime, *ResponseTime]()
}

// ResponseTimeCategoryCodec binds MAP-LCS-DataTypes.ResponseTimeCategory.
func ResponseTimeCategoryCodec() ValueCodec[BERValue[ResponseTimeCategory]] {
	return integerValueCodec[ResponseTimeCategory]("MAP-LCS-DataTypes.ResponseTimeCategory", "ResponseTimeCategory", nil, true)
}

// LCSQoSClassCodec binds MAP-LCS-DataTypes.LCS-QoS-Class.
func LCSQoSClassCodec() ValueCodec[BERValue[LCSQoSClass]] {
	return integerValueCodec[LCSQoSClass]("MAP-LCS-DataTypes.LCS-QoS-Class", "LCS-QoS-Class", nil, true)
}

// SupportedGADShapesCodec binds MAP-LCS-DataTypes.SupportedGADShapes.
func SupportedGADShapesCodec() ValueCodec[BERValue[SupportedGADShapes]] {
	return bitValueCodec("MAP-LCS-DataTypes.SupportedGADShapes", "SupportedGADShapes", []primitiveRule[SupportedGADShapes]{{invalid: func(value SupportedGADShapes) bool { return !(value.BitLength >= 7 && value.BitLength <= 16) }, description: "SIZE (7..16)", clause: "51.5", length: func(value SupportedGADShapes) int { return value.BitLength }, encodedLength: func(value SupportedGADShapes) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}})
}

// LCSReferenceNumberCodec binds MAP-LCS-DataTypes.LCS-ReferenceNumber.
func LCSReferenceNumberCodec() ValueCodec[BERValue[LCSReferenceNumber]] {
	return octetValueCodec[LCSReferenceNumber]("MAP-LCS-DataTypes.LCS-ReferenceNumber", "LCS-ReferenceNumber", []primitiveRule[LCSReferenceNumber]{{invalid: func(value LCSReferenceNumber) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value LCSReferenceNumber) int { return len(value) }}})
}

// LCSCodewordCodec binds MAP-LCS-DataTypes.LCSCodeword.
func LCSCodewordCodec() ValueCodec[LCSCodeword] {
	return compositeValueCodec[LCSCodeword, *LCSCodeword]()
}

// LCSCodewordStringCodec binds MAP-LCS-DataTypes.LCSCodewordString.
func LCSCodewordStringCodec() ValueCodec[BERValue[LCSCodewordString]] {
	return pointerValueCodec(UnmarshalBERLCSCodewordString, MarshalBERLCSCodewordString, MarshalDERLCSCodewordString)
}

// LCSPrivacyCheckCodec binds MAP-LCS-DataTypes.LCS-PrivacyCheck.
func LCSPrivacyCheckCodec() ValueCodec[LCSPrivacyCheck] {
	return compositeValueCodec[LCSPrivacyCheck, *LCSPrivacyCheck]()
}

// PrivacyCheckRelatedActionCodec binds MAP-LCS-DataTypes.PrivacyCheckRelatedAction.
func PrivacyCheckRelatedActionCodec() ValueCodec[BERValue[PrivacyCheckRelatedAction]] {
	return integerValueCodec[PrivacyCheckRelatedAction]("MAP-LCS-DataTypes.PrivacyCheckRelatedAction", "PrivacyCheckRelatedAction", nil, true)
}

// AreaEventInfoCodec binds MAP-LCS-DataTypes.AreaEventInfo.
func AreaEventInfoCodec() ValueCodec[AreaEventInfo] {
	return compositeValueCodec[AreaEventInfo, *AreaEventInfo]()
}

// AreaDefinitionCodec binds MAP-LCS-DataTypes.AreaDefinition.
func AreaDefinitionCodec() ValueCodec[AreaDefinition] {
	return compositeValueCodec[AreaDefinition, *AreaDefinition]()
}

// AreaListCodec binds MAP-LCS-DataTypes.AreaList.
func AreaListCodec() ValueCodec[AreaList] {
	return pointerValueCodec(UnmarshalBERAreaList, MarshalBERAreaList, MarshalDERAreaList)
}

// AreaCodec binds MAP-LCS-DataTypes.Area.
func AreaCodec() ValueCodec[Area] {
	return compositeValueCodec[Area, *Area]()
}

// AreaTypeCodec binds MAP-LCS-DataTypes.AreaType.
func AreaTypeCodec() ValueCodec[BERValue[AreaType]] {
	return integerValueCodec[AreaType]("MAP-LCS-DataTypes.AreaType", "AreaType", nil, true)
}

// AreaIdentificationCodec binds MAP-LCS-DataTypes.AreaIdentification.
func AreaIdentificationCodec() ValueCodec[BERValue[AreaIdentification]] {
	return octetValueCodec[AreaIdentification]("MAP-LCS-DataTypes.AreaIdentification", "AreaIdentification", []primitiveRule[AreaIdentification]{{invalid: func(value AreaIdentification) bool { return !(len(value) >= 2 && len(value) <= 7) }, description: "SIZE (2..7)", clause: "51.5", length: func(value AreaIdentification) int { return len(value) }}})
}

// OccurrenceInfoCodec binds MAP-LCS-DataTypes.OccurrenceInfo.
func OccurrenceInfoCodec() ValueCodec[BERValue[OccurrenceInfo]] {
	return integerValueCodec[OccurrenceInfo]("MAP-LCS-DataTypes.OccurrenceInfo", "OccurrenceInfo", nil, true)
}

// IntervalTimeCodec binds MAP-LCS-DataTypes.IntervalTime.
func IntervalTimeCodec() ValueCodec[BERValue[IntervalTime]] {
	return integerValueCodec[IntervalTime]("MAP-LCS-DataTypes.IntervalTime", "IntervalTime", []primitiveRule[IntervalTime]{{invalid: func(value IntervalTime) bool { return !(int64(value) >= 1 && int64(value) <= 32767) }, description: "(1..32767)", clause: "51.4", observed: func(value IntervalTime) any { return int64(value) }}}, false)
}

// PeriodicLDRInfoCodec binds MAP-LCS-DataTypes.PeriodicLDRInfo.
func PeriodicLDRInfoCodec() ValueCodec[PeriodicLDRInfo] {
	return compositeValueCodec[PeriodicLDRInfo, *PeriodicLDRInfo]()
}

// ReportingAmountCodec binds MAP-LCS-DataTypes.ReportingAmount.
func ReportingAmountCodec() ValueCodec[BERValue[ReportingAmount]] {
	return integerValueCodec[ReportingAmount]("MAP-LCS-DataTypes.ReportingAmount", "ReportingAmount", []primitiveRule[ReportingAmount]{{invalid: func(value ReportingAmount) bool { return !(int64(value) >= 1 && int64(value) <= 8639999) }, description: "(1..8639999)", clause: "51.4", observed: func(value ReportingAmount) any { return int64(value) }}}, false)
}

// ReportingIntervalCodec binds MAP-LCS-DataTypes.ReportingInterval.
func ReportingIntervalCodec() ValueCodec[BERValue[ReportingInterval]] {
	return integerValueCodec[ReportingInterval]("MAP-LCS-DataTypes.ReportingInterval", "ReportingInterval", []primitiveRule[ReportingInterval]{{invalid: func(value ReportingInterval) bool { return !(int64(value) >= 1 && int64(value) <= 8639999) }, description: "(1..8639999)", clause: "51.4", observed: func(value ReportingInterval) any { return int64(value) }}}, false)
}

// ReportingOptionMillisecondsCodec binds MAP-LCS-DataTypes.ReportingOptionMilliseconds.
func ReportingOptionMillisecondsCodec() ValueCodec[ReportingOptionMilliseconds] {
	return compositeValueCodec[ReportingOptionMilliseconds, *ReportingOptionMilliseconds]()
}

// ReportingAmountMillisecondsCodec binds MAP-LCS-DataTypes.ReportingAmountMilliseconds.
func ReportingAmountMillisecondsCodec() ValueCodec[BERValue[ReportingAmountMilliseconds]] {
	return integerValueCodec[ReportingAmountMilliseconds]("MAP-LCS-DataTypes.ReportingAmountMilliseconds", "ReportingAmountMilliseconds", []primitiveRule[ReportingAmountMilliseconds]{{invalid: func(value ReportingAmountMilliseconds) bool {
		return !(int64(value) >= 1 && int64(value) <= 8639999000)
	}, description: "(1..8639999000)", clause: "51.4", observed: func(value ReportingAmountMilliseconds) any { return int64(value) }}}, false)
}

// ReportingIntervalMillisecondsCodec binds MAP-LCS-DataTypes.ReportingIntervalMilliseconds.
func ReportingIntervalMillisecondsCodec() ValueCodec[BERValue[ReportingIntervalMilliseconds]] {
	return integerValueCodec[ReportingIntervalMilliseconds]("MAP-LCS-DataTypes.ReportingIntervalMilliseconds", "ReportingIntervalMilliseconds", []primitiveRule[ReportingIntervalMilliseconds]{{invalid: func(value ReportingIntervalMilliseconds) bool { return !(int64(value) >= 1 && int64(value) <= 999) }, description: "(1..999)", clause: "51.4", observed: func(value ReportingIntervalMilliseconds) any { return int64(value) }}}, false)
}

// ReportingPLMNListCodec binds MAP-LCS-DataTypes.ReportingPLMNList.
func ReportingPLMNListCodec() ValueCodec[ReportingPLMNList] {
	return compositeValueCodec[ReportingPLMNList, *ReportingPLMNList]()
}

// PLMNListCodec binds MAP-LCS-DataTypes.PLMNList.
func PLMNListCodec() ValueCodec[PLMNList] {
	return pointerValueCodec(UnmarshalBERPLMNList, MarshalBERPLMNList, MarshalDERPLMNList)
}

// ReportingPLMNCodec binds MAP-LCS-DataTypes.ReportingPLMN.
func ReportingPLMNCodec() ValueCodec[ReportingPLMN] {
	return compositeValueCodec[ReportingPLMN, *ReportingPLMN]()
}

// RANTechnologyCodec binds MAP-LCS-DataTypes.RAN-Technology.
func RANTechnologyCodec() ValueCodec[BERValue[RANTechnology]] {
	return integerValueCodec[RANTechnology]("MAP-LCS-DataTypes.RAN-Technology", "RAN-Technology", nil, true)
}

// ProvideSubscriberLocationResCodec binds MAP-LCS-DataTypes.ProvideSubscriberLocation-Res.
func ProvideSubscriberLocationResCodec() ValueCodec[ProvideSubscriberLocationRes] {
	return compositeValueCodec[ProvideSubscriberLocationRes, *ProvideSubscriberLocationRes]()
}

// AccuracyFulfilmentIndicatorCodec binds MAP-LCS-DataTypes.AccuracyFulfilmentIndicator.
func AccuracyFulfilmentIndicatorCodec() ValueCodec[BERValue[AccuracyFulfilmentIndicator]] {
	return integerValueCodec[AccuracyFulfilmentIndicator]("MAP-LCS-DataTypes.AccuracyFulfilmentIndicator", "AccuracyFulfilmentIndicator", nil, true)
}

// ExtGeographicalInformationCodec binds MAP-LCS-DataTypes.Ext-GeographicalInformation.
func ExtGeographicalInformationCodec() ValueCodec[BERValue[ExtGeographicalInformation]] {
	return octetValueCodec[ExtGeographicalInformation]("MAP-LCS-DataTypes.Ext-GeographicalInformation", "Ext-GeographicalInformation", []primitiveRule[ExtGeographicalInformation]{{invalid: func(value ExtGeographicalInformation) bool { return !(len(value) >= 1 && len(value) <= 20) }, description: "SIZE (1..20)", clause: "51.5", length: func(value ExtGeographicalInformation) int { return len(value) }}})
}

// VelocityEstimateCodec binds MAP-LCS-DataTypes.VelocityEstimate.
func VelocityEstimateCodec() ValueCodec[BERValue[VelocityEstimate]] {
	return octetValueCodec[VelocityEstimate]("MAP-LCS-DataTypes.VelocityEstimate", "VelocityEstimate", []primitiveRule[VelocityEstimate]{{invalid: func(value VelocityEstimate) bool { return !(len(value) >= 4 && len(value) <= 7) }, description: "SIZE (4..7)", clause: "51.5", length: func(value VelocityEstimate) int { return len(value) }}})
}

// PositioningDataInformationCodec binds MAP-LCS-DataTypes.PositioningDataInformation.
func PositioningDataInformationCodec() ValueCodec[BERValue[PositioningDataInformation]] {
	return octetValueCodec[PositioningDataInformation]("MAP-LCS-DataTypes.PositioningDataInformation", "PositioningDataInformation", []primitiveRule[PositioningDataInformation]{{invalid: func(value PositioningDataInformation) bool { return !(len(value) >= 2 && len(value) <= 10) }, description: "SIZE (2..10)", clause: "51.5", length: func(value PositioningDataInformation) int { return len(value) }}})
}

// UtranPositioningDataInfoCodec binds MAP-LCS-DataTypes.UtranPositioningDataInfo.
func UtranPositioningDataInfoCodec() ValueCodec[BERValue[UtranPositioningDataInfo]] {
	return octetValueCodec[UtranPositioningDataInfo]("MAP-LCS-DataTypes.UtranPositioningDataInfo", "UtranPositioningDataInfo", []primitiveRule[UtranPositioningDataInfo]{{invalid: func(value UtranPositioningDataInfo) bool { return !(len(value) >= 3 && len(value) <= 11) }, description: "SIZE (3..11)", clause: "51.5", length: func(value UtranPositioningDataInfo) int { return len(value) }}})
}

// GeranGANSSpositioningDataCodec binds MAP-LCS-DataTypes.GeranGANSSpositioningData.
func GeranGANSSpositioningDataCodec() ValueCodec[BERValue[GeranGANSSpositioningData]] {
	return octetValueCodec[GeranGANSSpositioningData]("MAP-LCS-DataTypes.GeranGANSSpositioningData", "GeranGANSSpositioningData", []primitiveRule[GeranGANSSpositioningData]{{invalid: func(value GeranGANSSpositioningData) bool { return !(len(value) >= 2 && len(value) <= 10) }, description: "SIZE (2..10)", clause: "51.5", length: func(value GeranGANSSpositioningData) int { return len(value) }}})
}

// UtranGANSSpositioningDataCodec binds MAP-LCS-DataTypes.UtranGANSSpositioningData.
func UtranGANSSpositioningDataCodec() ValueCodec[BERValue[UtranGANSSpositioningData]] {
	return octetValueCodec[UtranGANSSpositioningData]("MAP-LCS-DataTypes.UtranGANSSpositioningData", "UtranGANSSpositioningData", []primitiveRule[UtranGANSSpositioningData]{{invalid: func(value UtranGANSSpositioningData) bool { return !(len(value) >= 1 && len(value) <= 9) }, description: "SIZE (1..9)", clause: "51.5", length: func(value UtranGANSSpositioningData) int { return len(value) }}})
}

// UtranAdditionalPositioningDataCodec binds MAP-LCS-DataTypes.UtranAdditionalPositioningData.
func UtranAdditionalPositioningDataCodec() ValueCodec[BERValue[UtranAdditionalPositioningData]] {
	return octetValueCodec[UtranAdditionalPositioningData]("MAP-LCS-DataTypes.UtranAdditionalPositioningData", "UtranAdditionalPositioningData", []primitiveRule[UtranAdditionalPositioningData]{{invalid: func(value UtranAdditionalPositioningData) bool { return !(len(value) >= 1 && len(value) <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value UtranAdditionalPositioningData) int { return len(value) }}})
}

// UtranBaroPressureMeasCodec binds MAP-LCS-DataTypes.UtranBaroPressureMeas.
func UtranBaroPressureMeasCodec() ValueCodec[BERValue[UtranBaroPressureMeas]] {
	return integerValueCodec[UtranBaroPressureMeas]("MAP-LCS-DataTypes.UtranBaroPressureMeas", "UtranBaroPressureMeas", []primitiveRule[UtranBaroPressureMeas]{{invalid: func(value UtranBaroPressureMeas) bool { return !(int64(value) >= 30000 && int64(value) <= 115000) }, description: "(30000..115000)", clause: "51.4", observed: func(value UtranBaroPressureMeas) any { return int64(value) }}}, false)
}

// UtranCivicAddressCodec binds MAP-LCS-DataTypes.UtranCivicAddress.
func UtranCivicAddressCodec() ValueCodec[BERValue[UtranCivicAddress]] {
	return octetValueCodec[UtranCivicAddress]("MAP-LCS-DataTypes.UtranCivicAddress", "UtranCivicAddress", nil)
}

// AddGeographicalInformationCodec binds MAP-LCS-DataTypes.Add-GeographicalInformation.
func AddGeographicalInformationCodec() ValueCodec[BERValue[AddGeographicalInformation]] {
	return octetValueCodec[AddGeographicalInformation]("MAP-LCS-DataTypes.Add-GeographicalInformation", "Add-GeographicalInformation", []primitiveRule[AddGeographicalInformation]{{invalid: func(value AddGeographicalInformation) bool { return !(len(value) >= 1 && len(value) <= 91) }, description: "SIZE (1..91)", clause: "51.5", length: func(value AddGeographicalInformation) int { return len(value) }}})
}

// SubscriberLocationReportArgCodec binds MAP-LCS-DataTypes.SubscriberLocationReport-Arg.
func SubscriberLocationReportArgCodec() ValueCodec[SubscriberLocationReportArg] {
	return compositeValueCodec[SubscriberLocationReportArg, *SubscriberLocationReportArg]()
}

// DeferredmtLrDataCodec binds MAP-LCS-DataTypes.Deferredmt-lrData.
func DeferredmtLrDataCodec() ValueCodec[DeferredmtLrData] {
	return compositeValueCodec[DeferredmtLrData, *DeferredmtLrData]()
}

// LCSEventCodec binds MAP-LCS-DataTypes.LCS-Event.
func LCSEventCodec() ValueCodec[BERValue[LCSEvent]] {
	return integerValueCodec[LCSEvent]("MAP-LCS-DataTypes.LCS-Event", "LCS-Event", nil, true)
}

// TerminationCauseCodec binds MAP-LCS-DataTypes.TerminationCause.
func TerminationCauseCodec() ValueCodec[BERValue[TerminationCause]] {
	return integerValueCodec[TerminationCause]("MAP-LCS-DataTypes.TerminationCause", "TerminationCause", nil, true)
}

// SequenceNumberCodec binds MAP-LCS-DataTypes.SequenceNumber.
func SequenceNumberCodec() ValueCodec[BERValue[SequenceNumber]] {
	return integerValueCodec[SequenceNumber]("MAP-LCS-DataTypes.SequenceNumber", "SequenceNumber", []primitiveRule[SequenceNumber]{{invalid: func(value SequenceNumber) bool { return !(int64(value) >= 1 && int64(value) <= 8639999) }, description: "(1..8639999)", clause: "51.4", observed: func(value SequenceNumber) any { return int64(value) }}}, false)
}

// ServingNodeAddressCodec binds MAP-LCS-DataTypes.ServingNodeAddress.
func ServingNodeAddressCodec() ValueCodec[ServingNodeAddress] {
	return compositeValueCodec[ServingNodeAddress, *ServingNodeAddress]()
}

// SubscriberLocationReportResCodec binds MAP-LCS-DataTypes.SubscriberLocationReport-Res.
func SubscriberLocationReportResCodec() ValueCodec[SubscriberLocationReportRes] {
	return compositeValueCodec[SubscriberLocationReportRes, *SubscriberLocationReportRes]()
}

// SSUserDataCodec binds SS-DataTypes.SS-UserData.
func SSUserDataCodec() ValueCodec[BERValue[SSUserData]] {
	return pointerValueCodec(UnmarshalBERSSUserData, MarshalBERSSUserData, MarshalDERSSUserData)
}

// NotifySSArgCodec binds SS-DataTypes.NotifySS-Arg.
func NotifySSArgCodec() ValueCodec[NotifySSArg] {
	return compositeValueCodec[NotifySSArg, *NotifySSArg]()
}

// MulticallIndicatorCodec binds SS-DataTypes.Multicall-Indicator.
func MulticallIndicatorCodec() ValueCodec[BERValue[MulticallIndicator]] {
	return integerValueCodec[MulticallIndicator]("SS-DataTypes.Multicall-Indicator", "Multicall-Indicator", []primitiveRule[MulticallIndicator]{{invalid: func(value MulticallIndicator) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MulticallIndicator) any { return int64(value) }}}, true)
}

// ForwardChargeAdviceArgCodec binds SS-DataTypes.ForwardChargeAdviceArg.
func ForwardChargeAdviceArgCodec() ValueCodec[ForwardChargeAdviceArg] {
	return compositeValueCodec[ForwardChargeAdviceArg, *ForwardChargeAdviceArg]()
}

// SSNotificationCodec binds SS-DataTypes.SS-Notification.
func SSNotificationCodec() ValueCodec[BERValue[SSNotification]] {
	return octetValueCodec[SSNotification]("SS-DataTypes.SS-Notification", "SS-Notification", []primitiveRule[SSNotification]{{invalid: func(value SSNotification) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value SSNotification) int { return len(value) }}})
}

// ChargingInformationCodec binds SS-DataTypes.ChargingInformation.
func ChargingInformationCodec() ValueCodec[ChargingInformation] {
	return compositeValueCodec[ChargingInformation, *ChargingInformation]()
}

// E1Codec binds SS-DataTypes.E1.
func E1Codec() ValueCodec[BERValue[E1]] {
	return integerValueCodec[E1]("SS-DataTypes.E1", "E1", []primitiveRule[E1]{{invalid: func(value E1) bool { return !(int64(value) >= 0 && int64(value) <= 8191) }, description: "(0..8191)", clause: "51.4", observed: func(value E1) any { return int64(value) }}}, false)
}

// E2Codec binds SS-DataTypes.E2.
func E2Codec() ValueCodec[BERValue[E2]] {
	return integerValueCodec[E2]("SS-DataTypes.E2", "E2", []primitiveRule[E2]{{invalid: func(value E2) bool { return !(int64(value) >= 0 && int64(value) <= 8191) }, description: "(0..8191)", clause: "51.4", observed: func(value E2) any { return int64(value) }}}, false)
}

// E3Codec binds SS-DataTypes.E3.
func E3Codec() ValueCodec[BERValue[E3]] {
	return integerValueCodec[E3]("SS-DataTypes.E3", "E3", []primitiveRule[E3]{{invalid: func(value E3) bool { return !(int64(value) >= 0 && int64(value) <= 8191) }, description: "(0..8191)", clause: "51.4", observed: func(value E3) any { return int64(value) }}}, false)
}

// E4Codec binds SS-DataTypes.E4.
func E4Codec() ValueCodec[BERValue[E4]] {
	return integerValueCodec[E4]("SS-DataTypes.E4", "E4", []primitiveRule[E4]{{invalid: func(value E4) bool { return !(int64(value) >= 0 && int64(value) <= 8191) }, description: "(0..8191)", clause: "51.4", observed: func(value E4) any { return int64(value) }}}, false)
}

// E5Codec binds SS-DataTypes.E5.
func E5Codec() ValueCodec[BERValue[E5]] {
	return integerValueCodec[E5]("SS-DataTypes.E5", "E5", []primitiveRule[E5]{{invalid: func(value E5) bool { return !(int64(value) >= 0 && int64(value) <= 8191) }, description: "(0..8191)", clause: "51.4", observed: func(value E5) any { return int64(value) }}}, false)
}

// E6Codec binds SS-DataTypes.E6.
func E6Codec() ValueCodec[BERValue[E6]] {
	return integerValueCodec[E6]("SS-DataTypes.E6", "E6", []primitiveRule[E6]{{invalid: func(value E6) bool { return !(int64(value) >= 0 && int64(value) <= 8191) }, description: "(0..8191)", clause: "51.4", observed: func(value E6) any { return int64(value) }}}, false)
}

// E7Codec binds SS-DataTypes.E7.
func E7Codec() ValueCodec[BERValue[E7]] {
	return integerValueCodec[E7]("SS-DataTypes.E7", "E7", []primitiveRule[E7]{{invalid: func(value E7) bool { return !(int64(value) >= 0 && int64(value) <= 8191) }, description: "(0..8191)", clause: "51.4", observed: func(value E7) any { return int64(value) }}}, false)
}

// CallOnHoldIndicatorCodec binds SS-DataTypes.CallOnHold-Indicator.
func CallOnHoldIndicatorCodec() ValueCodec[BERValue[CallOnHoldIndicator]] {
	return integerValueCodec[CallOnHoldIndicator]("SS-DataTypes.CallOnHold-Indicator", "CallOnHold-Indicator", []primitiveRule[CallOnHoldIndicator]{{invalid: func(value CallOnHoldIndicator) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value CallOnHoldIndicator) any { return int64(value) }}}, true)
}

// ForwardCUGInfoArgCodec binds SS-DataTypes.ForwardCUG-InfoArg.
func ForwardCUGInfoArgCodec() ValueCodec[ForwardCUGInfoArg] {
	return compositeValueCodec[ForwardCUGInfoArg, *ForwardCUGInfoArg]()
}

// ECTIndicatorCodec binds SS-DataTypes.ECT-Indicator.
func ECTIndicatorCodec() ValueCodec[ECTIndicator] {
	return compositeValueCodec[ECTIndicator, *ECTIndicator]()
}

// ECTCallStateCodec binds SS-DataTypes.ECT-CallState.
func ECTCallStateCodec() ValueCodec[BERValue[ECTCallState]] {
	return integerValueCodec[ECTCallState]("SS-DataTypes.ECT-CallState", "ECT-CallState", []primitiveRule[ECTCallState]{{invalid: func(value ECTCallState) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value ECTCallState) any { return int64(value) }}}, true)
}

// NameIndicatorCodec binds SS-DataTypes.NameIndicator.
func NameIndicatorCodec() ValueCodec[NameIndicator] {
	return compositeValueCodec[NameIndicator, *NameIndicator]()
}

// NameCodec binds SS-DataTypes.Name.
func NameCodec() ValueCodec[Name] {
	return compositeValueCodec[Name, *Name]()
}

// NameSetCodec binds SS-DataTypes.NameSet.
func NameSetCodec() ValueCodec[NameSet] {
	return compositeValueCodec[NameSet, *NameSet]()
}

// RDNCodec binds SS-DataTypes.RDN.
func RDNCodec() ValueCodec[RDN] {
	return compositeValueCodec[RDN, *RDN]()
}

// RemotePartyNumberCodec binds SS-DataTypes.RemotePartyNumber.
func RemotePartyNumberCodec() ValueCodec[RemotePartyNumber] {
	return compositeValueCodec[RemotePartyNumber, *RemotePartyNumber]()
}

// AccessRegisterCCEntryArgCodec binds SS-DataTypes.AccessRegisterCCEntryArg.
func AccessRegisterCCEntryArgCodec() ValueCodec[AccessRegisterCCEntryArg] {
	return compositeValueCodec[AccessRegisterCCEntryArg, *AccessRegisterCCEntryArg]()
}

// CallDeflectionArgCodec binds SS-DataTypes.CallDeflectionArg.
func CallDeflectionArgCodec() ValueCodec[CallDeflectionArg] {
	return compositeValueCodec[CallDeflectionArg, *CallDeflectionArg]()
}

// UserUserServiceArgCodec binds SS-DataTypes.UserUserServiceArg.
func UserUserServiceArgCodec() ValueCodec[UserUserServiceArg] {
	return compositeValueCodec[UserUserServiceArg, *UserUserServiceArg]()
}

// UUSServiceCodec binds SS-DataTypes.UUS-Service.
func UUSServiceCodec() ValueCodec[BERValue[UUSService]] {
	return integerValueCodec[UUSService]("SS-DataTypes.UUS-Service", "UUS-Service", nil, true)
}

// LocationNotificationArgCodec binds SS-DataTypes.LocationNotificationArg.
func LocationNotificationArgCodec() ValueCodec[LocationNotificationArg] {
	return compositeValueCodec[LocationNotificationArg, *LocationNotificationArg]()
}

// DeferredLocationExtCodec binds SS-DataTypes.DeferredLocationExt.
func DeferredLocationExtCodec() ValueCodec[BERValue[DeferredLocationExt]] {
	return bitValueCodec("SS-DataTypes.DeferredLocationExt", "DeferredLocationExt", []primitiveRule[DeferredLocationExt]{{invalid: func(value DeferredLocationExt) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value DeferredLocationExt) int { return value.BitLength }, encodedLength: func(value DeferredLocationExt) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// RangingSlExtCodec binds SS-DataTypes.RangingSlExt.
func RangingSlExtCodec() ValueCodec[BERValue[RangingSlExt]] {
	return bitValueCodec("SS-DataTypes.RangingSlExt", "RangingSlExt", []primitiveRule[RangingSlExt]{{invalid: func(value RangingSlExt) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value RangingSlExt) int { return value.BitLength }, encodedLength: func(value RangingSlExt) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// LocationNotificationResCodec binds SS-DataTypes.LocationNotificationRes.
func LocationNotificationResCodec() ValueCodec[LocationNotificationRes] {
	return compositeValueCodec[LocationNotificationRes, *LocationNotificationRes]()
}

// VerificationResponseCodec binds SS-DataTypes.VerificationResponse.
func VerificationResponseCodec() ValueCodec[BERValue[VerificationResponse]] {
	return integerValueCodec[VerificationResponse]("SS-DataTypes.VerificationResponse", "VerificationResponse", nil, true)
}

// LCSMOLRArgCodec binds SS-DataTypes.LCS-MOLRArg.
func LCSMOLRArgCodec() ValueCodec[LCSMOLRArg] {
	return compositeValueCodec[LCSMOLRArg, *LCSMOLRArg]()
}

// MOLRTypeCodec binds SS-DataTypes.MOLR-Type.
func MOLRTypeCodec() ValueCodec[BERValue[MOLRType]] {
	return integerValueCodec[MOLRType]("SS-DataTypes.MOLR-Type", "MOLR-Type", nil, true)
}

// LocationMethodCodec binds SS-DataTypes.LocationMethod.
func LocationMethodCodec() ValueCodec[BERValue[LocationMethod]] {
	return integerValueCodec[LocationMethod]("SS-DataTypes.LocationMethod", "LocationMethod", nil, true)
}

// GPSAssistanceDataCodec binds SS-DataTypes.GPSAssistanceData.
func GPSAssistanceDataCodec() ValueCodec[BERValue[GPSAssistanceData]] {
	return octetValueCodec[GPSAssistanceData]("SS-DataTypes.GPSAssistanceData", "GPSAssistanceData", []primitiveRule[GPSAssistanceData]{{invalid: func(value GPSAssistanceData) bool { return !(len(value) >= 1 && len(value) <= 38) }, description: "SIZE (1..38)", clause: "51.5", length: func(value GPSAssistanceData) int { return len(value) }}})
}

// GANSSAssistanceDataCodec binds SS-DataTypes.GANSSAssistanceData.
func GANSSAssistanceDataCodec() ValueCodec[BERValue[GANSSAssistanceData]] {
	return octetValueCodec[GANSSAssistanceData]("SS-DataTypes.GANSSAssistanceData", "GANSSAssistanceData", []primitiveRule[GANSSAssistanceData]{{invalid: func(value GANSSAssistanceData) bool { return !(len(value) >= 1 && len(value) <= 40) }, description: "SIZE (1..40)", clause: "51.5", length: func(value GANSSAssistanceData) int { return len(value) }}})
}

// DataTypesTerminationCauseCodec binds SS-DataTypes.TerminationCause.
func DataTypesTerminationCauseCodec() ValueCodec[BERValue[DataTypesTerminationCause]] {
	return integerValueCodec[DataTypesTerminationCause]("SS-DataTypes.TerminationCause", "TerminationCause", nil, true)
}

// MultiplePositioningProtocolPDUsCodec binds SS-DataTypes.MultiplePositioningProtocolPDUs.
func MultiplePositioningProtocolPDUsCodec() ValueCodec[MultiplePositioningProtocolPDUs] {
	return pointerValueCodec(UnmarshalBERMultiplePositioningProtocolPDUs, MarshalBERMultiplePositioningProtocolPDUs, MarshalDERMultiplePositioningProtocolPDUs)
}

// PositioningProtocolPDUCodec binds SS-DataTypes.PositioningProtocolPDU.
func PositioningProtocolPDUCodec() ValueCodec[BERValue[PositioningProtocolPDU]] {
	return octetValueCodec[PositioningProtocolPDU]("SS-DataTypes.PositioningProtocolPDU", "PositioningProtocolPDU", nil)
}

// LCSMOLRResCodec binds SS-DataTypes.LCS-MOLRRes.
func LCSMOLRResCodec() ValueCodec[LCSMOLRRes] {
	return compositeValueCodec[LCSMOLRRes, *LCSMOLRRes]()
}

// DecipheringKeysCodec binds SS-DataTypes.DecipheringKeys.
func DecipheringKeysCodec() ValueCodec[BERValue[DecipheringKeys]] {
	return octetValueCodec[DecipheringKeys]("SS-DataTypes.DecipheringKeys", "DecipheringKeys", []primitiveRule[DecipheringKeys]{{invalid: func(value DecipheringKeys) bool { return !(len(value) == 15) }, description: "SIZE (15)", clause: "51.5", length: func(value DecipheringKeys) int { return len(value) }}})
}

// LCSAreaEventRequestArgCodec binds SS-DataTypes.LCS-AreaEventRequestArg.
func LCSAreaEventRequestArgCodec() ValueCodec[LCSAreaEventRequestArg] {
	return compositeValueCodec[LCSAreaEventRequestArg, *LCSAreaEventRequestArg]()
}

// SLMOLRTypeCodec binds SS-DataTypes.SLMOLR-Type.
func SLMOLRTypeCodec() ValueCodec[BERValue[SLMOLRType]] {
	return integerValueCodec[SLMOLRType]("SS-DataTypes.SLMOLR-Type", "SLMOLR-Type", nil, true)
}

// LCSSLMOLRArgCodec binds SS-DataTypes.LCS-SLMOLRArg.
func LCSSLMOLRArgCodec() ValueCodec[LCSSLMOLRArg] {
	return compositeValueCodec[LCSSLMOLRArg, *LCSSLMOLRArg]()
}

// PreferredRangingResultCodec binds SS-DataTypes.PreferredRangingResult.
func PreferredRangingResultCodec() ValueCodec[PreferredRangingResult] {
	return compositeValueCodec[PreferredRangingResult, *PreferredRangingResult]()
}

// RelatedUEInfoCodec binds SS-DataTypes.RelatedUEInfo.
func RelatedUEInfoCodec() ValueCodec[RelatedUEInfo] {
	return pointerValueCodec(UnmarshalBERRelatedUEInfo, MarshalBERRelatedUEInfo, MarshalDERRelatedUEInfo)
}

// RangingUEInfoCodec binds SS-DataTypes.RangingUEInfo.
func RangingUEInfoCodec() ValueCodec[RangingUEInfo] {
	return compositeValueCodec[RangingUEInfo, *RangingUEInfo]()
}

// RangingRoleCodec binds SS-DataTypes.RangingRole.
func RangingRoleCodec() ValueCodec[BERValue[RangingRole]] {
	return integerValueCodec[RangingRole]("SS-DataTypes.RangingRole", "RangingRole", nil, true)
}

// LCSSLMOLRResCodec binds SS-DataTypes.LCS-SLMOLRRes.
func LCSSLMOLRResCodec() ValueCodec[LCSSLMOLRRes] {
	return compositeValueCodec[LCSSLMOLRRes, *LCSSLMOLRRes]()
}

// RelativeResultCodec binds SS-DataTypes.RelativeResult.
func RelativeResultCodec() ValueCodec[RelativeResult] {
	return pointerValueCodec(UnmarshalBERRelativeResult, MarshalBERRelativeResult, MarshalDERRelativeResult)
}

// SingleRelativeResultCodec binds SS-DataTypes.SingleRelativeResult.
func SingleRelativeResultCodec() ValueCodec[SingleRelativeResult] {
	return compositeValueCodec[SingleRelativeResult, *SingleRelativeResult]()
}

// RelativeLocationCoordinatesCodec binds SS-DataTypes.RelativeLocationCoordinates.
func RelativeLocationCoordinatesCodec() ValueCodec[RelativeLocationCoordinates] {
	return compositeValueCodec[RelativeLocationCoordinates, *RelativeLocationCoordinates]()
}

// Relative2DLocationWithUncertaintyEllipseCodec binds SS-DataTypes.Relative2D-LocationWithUncertaintyEllipse.
func Relative2DLocationWithUncertaintyEllipseCodec() ValueCodec[Relative2DLocationWithUncertaintyEllipse] {
	return compositeValueCodec[Relative2DLocationWithUncertaintyEllipse, *Relative2DLocationWithUncertaintyEllipse]()
}

// Relative3DLocationWithUncertaintyEllipsoidCodec binds SS-DataTypes.Relative3D-LocationWithUncertaintyEllipsoid.
func Relative3DLocationWithUncertaintyEllipsoidCodec() ValueCodec[Relative3DLocationWithUncertaintyEllipsoid] {
	return compositeValueCodec[Relative3DLocationWithUncertaintyEllipsoid, *Relative3DLocationWithUncertaintyEllipsoid]()
}

// RangeXYCoordinatesCodec binds SS-DataTypes.RangeXYCoordinates.
func RangeXYCoordinatesCodec() ValueCodec[BERValue[RangeXYCoordinates]] {
	return integerValueCodec[RangeXYCoordinates]("SS-DataTypes.RangeXYCoordinates", "RangeXYCoordinates", []primitiveRule[RangeXYCoordinates]{{invalid: func(value RangeXYCoordinates) bool { return !(int64(value) >= -134217728 && int64(value) <= 134217727) }, description: "(-134217728..134217727)", clause: "51.4", observed: func(value RangeXYCoordinates) any { return int64(value) }}}, false)
}

// RangeZCoordinatesCodec binds SS-DataTypes.RangeZCoordinates.
func RangeZCoordinatesCodec() ValueCodec[BERValue[RangeZCoordinates]] {
	return integerValueCodec[RangeZCoordinates]("SS-DataTypes.RangeZCoordinates", "RangeZCoordinates", []primitiveRule[RangeZCoordinates]{{invalid: func(value RangeZCoordinates) bool { return !(int64(value) >= -16777216 && int64(value) <= 16777215) }, description: "(-16777216..16777215)", clause: "51.4", observed: func(value RangeZCoordinates) any { return int64(value) }}}, false)
}

// UncertaintyCodec binds SS-DataTypes.Uncertainty.
func UncertaintyCodec() ValueCodec[BERValue[Uncertainty]] {
	return integerValueCodec[Uncertainty]("SS-DataTypes.Uncertainty", "Uncertainty", []primitiveRule[Uncertainty]{{invalid: func(value Uncertainty) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "51.4", observed: func(value Uncertainty) any { return int64(value) }}}, false)
}

// OrientationMajorAxisCodec binds SS-DataTypes.OrientationMajorAxis.
func OrientationMajorAxisCodec() ValueCodec[BERValue[OrientationMajorAxis]] {
	return integerValueCodec[OrientationMajorAxis]("SS-DataTypes.OrientationMajorAxis", "OrientationMajorAxis", []primitiveRule[OrientationMajorAxis]{{invalid: func(value OrientationMajorAxis) bool { return !(int64(value) >= 0 && int64(value) <= 179) }, description: "(0..179)", clause: "51.4", observed: func(value OrientationMajorAxis) any { return int64(value) }}}, false)
}

// ConfidenceCodec binds SS-DataTypes.Confidence.
func ConfidenceCodec() ValueCodec[BERValue[Confidence]] {
	return integerValueCodec[Confidence]("SS-DataTypes.Confidence", "Confidence", []primitiveRule[Confidence]{{invalid: func(value Confidence) bool { return !(int64(value) >= 0 && int64(value) <= 100) }, description: "(0..100)", clause: "51.4", observed: func(value Confidence) any { return int64(value) }}}, false)
}

// RangeDirectionCodec binds SS-DataTypes.RangeDirection.
func RangeDirectionCodec() ValueCodec[RangeDirection] {
	return compositeValueCodec[RangeDirection, *RangeDirection]()
}

// RangeCodec binds SS-DataTypes.Range.
func RangeCodec() ValueCodec[Range] {
	return compositeValueCodec[Range, *Range]()
}

// AzimuthCodec binds SS-DataTypes.Azimuth.
func AzimuthCodec() ValueCodec[Azimuth] {
	return compositeValueCodec[Azimuth, *Azimuth]()
}

// ElevationCodec binds SS-DataTypes.Elevation.
func ElevationCodec() ValueCodec[Elevation] {
	return compositeValueCodec[Elevation, *Elevation]()
}

// RangeResultCodec binds SS-DataTypes.RangeResult.
func RangeResultCodec() ValueCodec[BERValue[RangeResult]] {
	return integerValueCodec[RangeResult]("SS-DataTypes.RangeResult", "RangeResult", []primitiveRule[RangeResult]{{invalid: func(value RangeResult) bool { return !(int64(value) >= 0 && int64(value) <= 1048575) }, description: "(0..1048575)", clause: "51.4", observed: func(value RangeResult) any { return int64(value) }}}, false)
}

// AzimuthResultCodec binds SS-DataTypes.AzimuthResult.
func AzimuthResultCodec() ValueCodec[BERValue[AzimuthResult]] {
	return integerValueCodec[AzimuthResult]("SS-DataTypes.AzimuthResult", "AzimuthResult", []primitiveRule[AzimuthResult]{{invalid: func(value AzimuthResult) bool { return !(int64(value) >= 0 && int64(value) <= 3599) }, description: "(0..3599)", clause: "51.4", observed: func(value AzimuthResult) any { return int64(value) }}}, false)
}

// ElevationResultCodec binds SS-DataTypes.ElevationResult.
func ElevationResultCodec() ValueCodec[BERValue[ElevationResult]] {
	return integerValueCodec[ElevationResult]("SS-DataTypes.ElevationResult", "ElevationResult", []primitiveRule[ElevationResult]{{invalid: func(value ElevationResult) bool { return !(int64(value) >= 0 && int64(value) <= 1800) }, description: "(0..1800)", clause: "51.4", observed: func(value ElevationResult) any { return int64(value) }}}, false)
}

// RelVelocityEstimateCodec binds SS-DataTypes.RelVelocityEstimate.
func RelVelocityEstimateCodec() ValueCodec[RelVelocityEstimate] {
	return compositeValueCodec[RelVelocityEstimate, *RelVelocityEstimate]()
}

// RadialVelocityCodec binds SS-DataTypes.RadialVelocity.
func RadialVelocityCodec() ValueCodec[BERValue[RadialVelocity]] {
	return integerValueCodec[RadialVelocity]("SS-DataTypes.RadialVelocity", "RadialVelocity", []primitiveRule[RadialVelocity]{{invalid: func(value RadialVelocity) bool { return !(int64(value) >= -2048 && int64(value) <= 2047) }, description: "(-2048..2047)", clause: "51.4", observed: func(value RadialVelocity) any { return int64(value) }}}, false)
}

// AngularVelocityCodec binds SS-DataTypes.AngularVelocity.
func AngularVelocityCodec() ValueCodec[BERValue[AngularVelocity]] {
	return integerValueCodec[AngularVelocity]("SS-DataTypes.AngularVelocity", "AngularVelocity", []primitiveRule[AngularVelocity]{{invalid: func(value AngularVelocity) bool { return !(int64(value) >= -1024 && int64(value) <= 1023) }, description: "(-1024..1023)", clause: "51.4", observed: func(value AngularVelocity) any { return int64(value) }}}, false)
}

// AngularVelocityUncertaintyCodec binds SS-DataTypes.AngularVelocityUncertainty.
func AngularVelocityUncertaintyCodec() ValueCodec[BERValue[AngularVelocityUncertainty]] {
	return integerValueCodec[AngularVelocityUncertainty]("SS-DataTypes.AngularVelocityUncertainty", "AngularVelocityUncertainty", []primitiveRule[AngularVelocityUncertainty]{{invalid: func(value AngularVelocityUncertainty) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "51.4", observed: func(value AngularVelocityUncertainty) any { return int64(value) }}}, false)
}

// UnitsLinearVelocityCodec binds SS-DataTypes.UnitsLinearVelocity.
func UnitsLinearVelocityCodec() ValueCodec[BERValue[UnitsLinearVelocity]] {
	return integerValueCodec[UnitsLinearVelocity]("SS-DataTypes.UnitsLinearVelocity", "UnitsLinearVelocity", nil, true)
}

// UnitsAngularVelocityCodec binds SS-DataTypes.UnitsAngularVelocity.
func UnitsAngularVelocityCodec() ValueCodec[BERValue[UnitsAngularVelocity]] {
	return integerValueCodec[UnitsAngularVelocity]("SS-DataTypes.UnitsAngularVelocity", "UnitsAngularVelocity", nil, true)
}

// LCSAreaEventReportArgCodec binds SS-DataTypes.LCS-AreaEventReportArg.
func LCSAreaEventReportArgCodec() ValueCodec[LCSAreaEventReportArg] {
	return compositeValueCodec[LCSAreaEventReportArg, *LCSAreaEventReportArg]()
}

// LCSAreaEventCancellationArgCodec binds SS-DataTypes.LCS-AreaEventCancellationArg.
func LCSAreaEventCancellationArgCodec() ValueCodec[LCSAreaEventCancellationArg] {
	return compositeValueCodec[LCSAreaEventCancellationArg, *LCSAreaEventCancellationArg]()
}

// LCSPeriodicLocationRequestArgCodec binds SS-DataTypes.LCS-PeriodicLocationRequestArg.
func LCSPeriodicLocationRequestArgCodec() ValueCodec[LCSPeriodicLocationRequestArg] {
	return compositeValueCodec[LCSPeriodicLocationRequestArg, *LCSPeriodicLocationRequestArg]()
}

// LCSPeriodicLocationRequestResCodec binds SS-DataTypes.LCS-PeriodicLocationRequestRes.
func LCSPeriodicLocationRequestResCodec() ValueCodec[LCSPeriodicLocationRequestRes] {
	return compositeValueCodec[LCSPeriodicLocationRequestRes, *LCSPeriodicLocationRequestRes]()
}

// LCSLocationUpdateArgCodec binds SS-DataTypes.LCS-LocationUpdateArg.
func LCSLocationUpdateArgCodec() ValueCodec[LCSLocationUpdateArg] {
	return compositeValueCodec[LCSLocationUpdateArg, *LCSLocationUpdateArg]()
}

// LCSLocationUpdateResCodec binds SS-DataTypes.LCS-LocationUpdateRes.
func LCSLocationUpdateResCodec() ValueCodec[LCSLocationUpdateRes] {
	return compositeValueCodec[LCSLocationUpdateRes, *LCSLocationUpdateRes]()
}

// LCSPeriodicLocationCancellationArgCodec binds SS-DataTypes.LCS-PeriodicLocationCancellationArg.
func LCSPeriodicLocationCancellationArgCodec() ValueCodec[LCSPeriodicLocationCancellationArg] {
	return compositeValueCodec[LCSPeriodicLocationCancellationArg, *LCSPeriodicLocationCancellationArg]()
}

// LCSPeriodicTriggeredInvokeArgCodec binds SS-DataTypes.LCS-PeriodicTriggeredInvokeArg.
func LCSPeriodicTriggeredInvokeArgCodec() ValueCodec[LCSPeriodicTriggeredInvokeArg] {
	return compositeValueCodec[LCSPeriodicTriggeredInvokeArg, *LCSPeriodicTriggeredInvokeArg]()
}

// PeriodicLocationCodec binds SS-DataTypes.PeriodicLocation.
func PeriodicLocationCodec() ValueCodec[PeriodicLocation] {
	return compositeValueCodec[PeriodicLocation, *PeriodicLocation]()
}

// AreaEventReportingCodec binds SS-DataTypes.AreaEventReporting.
func AreaEventReportingCodec() ValueCodec[AreaEventReporting] {
	return compositeValueCodec[AreaEventReporting, *AreaEventReporting]()
}

// DataTypesAreaListCodec binds SS-DataTypes.AreaList.
func DataTypesAreaListCodec() ValueCodec[DataTypesAreaList] {
	return pointerValueCodec(UnmarshalBERDataTypesAreaList, MarshalBERDataTypesAreaList, MarshalDERDataTypesAreaList)
}

// DataTypesAreaCodec binds SS-DataTypes.Area.
func DataTypesAreaCodec() ValueCodec[DataTypesArea] {
	return compositeValueCodec[DataTypesArea, *DataTypesArea]()
}

// DataTypesAreaTypeCodec binds SS-DataTypes.AreaType.
func DataTypesAreaTypeCodec() ValueCodec[BERValue[DataTypesAreaType]] {
	return integerValueCodec[DataTypesAreaType]("SS-DataTypes.AreaType", "AreaType", nil, true)
}

// DataTypesAreaIdentificationCodec binds SS-DataTypes.AreaIdentification.
func DataTypesAreaIdentificationCodec() ValueCodec[BERValue[DataTypesAreaIdentification]] {
	return octetValueCodec[DataTypesAreaIdentification]("SS-DataTypes.AreaIdentification", "AreaIdentification", []primitiveRule[DataTypesAreaIdentification]{{invalid: func(value DataTypesAreaIdentification) bool { return !(len(value) >= 5 && len(value) <= 7) }, description: "SIZE (5..7)", clause: "51.5", length: func(value DataTypesAreaIdentification) int { return len(value) }}})
}

// AreaIdentificationExtCodec binds SS-DataTypes.AreaIdentificationExt.
func AreaIdentificationExtCodec() ValueCodec[BERValue[AreaIdentificationExt]] {
	return octetValueCodec[AreaIdentificationExt]("SS-DataTypes.AreaIdentificationExt", "AreaIdentificationExt", []primitiveRule[AreaIdentificationExt]{{invalid: func(value AreaIdentificationExt) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value AreaIdentificationExt) int { return len(value) }}})
}

// DataTypesOccurrenceInfoCodec binds SS-DataTypes.OccurrenceInfo.
func DataTypesOccurrenceInfoCodec() ValueCodec[BERValue[DataTypesOccurrenceInfo]] {
	return integerValueCodec[DataTypesOccurrenceInfo]("SS-DataTypes.OccurrenceInfo", "OccurrenceInfo", nil, true)
}

// MaximumIntervalCodec binds SS-DataTypes.MaximumInterval.
func MaximumIntervalCodec() ValueCodec[BERValue[MaximumInterval]] {
	return integerValueCodec[MaximumInterval]("SS-DataTypes.MaximumInterval", "MaximumInterval", []primitiveRule[MaximumInterval]{{invalid: func(value MaximumInterval) bool { return !(int64(value) >= 1 && int64(value) <= 86400) }, description: "(1..86400)", clause: "51.4", observed: func(value MaximumInterval) any { return int64(value) }}}, false)
}

// SamplingIntervalCodec binds SS-DataTypes.SamplingInterval.
func SamplingIntervalCodec() ValueCodec[BERValue[SamplingInterval]] {
	return integerValueCodec[SamplingInterval]("SS-DataTypes.SamplingInterval", "SamplingInterval", []primitiveRule[SamplingInterval]{{invalid: func(value SamplingInterval) bool { return !(int64(value) >= 1 && int64(value) <= 3600) }, description: "(1..3600)", clause: "51.4", observed: func(value SamplingInterval) any { return int64(value) }}}, false)
}

// DurationCodec binds SS-DataTypes.Duration.
func DurationCodec() ValueCodec[BERValue[Duration]] {
	return integerValueCodec[Duration]("SS-DataTypes.Duration", "Duration", []primitiveRule[Duration]{{invalid: func(value Duration) bool { return !(int64(value) >= 1 && int64(value) <= 8640000) }, description: "(1..8640000)", clause: "51.4", observed: func(value Duration) any { return int64(value) }}}, false)
}

// LocationInfoCodec binds SS-DataTypes.LocationInfo.
func LocationInfoCodec() ValueCodec[BERValue[LocationInfo]] {
	return bitValueCodec("SS-DataTypes.LocationInfo", "LocationInfo", []primitiveRule[LocationInfo]{{invalid: func(value LocationInfo) bool { return !(value.BitLength >= 1 && value.BitLength <= 32) }, description: "SIZE (1..32)", clause: "51.5", length: func(value LocationInfo) int { return value.BitLength }, encodedLength: func(value LocationInfo) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 32}}})
}

// MotionEventReportingCodec binds SS-DataTypes.MotionEventReporting.
func MotionEventReportingCodec() ValueCodec[MotionEventReporting] {
	return compositeValueCodec[MotionEventReporting, *MotionEventReporting]()
}

// LinearDistanceCodec binds SS-DataTypes.LinearDistance.
func LinearDistanceCodec() ValueCodec[BERValue[LinearDistance]] {
	return integerValueCodec[LinearDistance]("SS-DataTypes.LinearDistance", "LinearDistance", []primitiveRule[LinearDistance]{{invalid: func(value LinearDistance) bool { return !(int64(value) >= 1 && int64(value) <= 10000) }, description: "(1..10000)", clause: "51.4", observed: func(value LinearDistance) any { return int64(value) }}}, false)
}

// LCSReferenceNumberExtCodec binds SS-DataTypes.LCS-ReferenceNumberExt.
func LCSReferenceNumberExtCodec() ValueCodec[BERValue[LCSReferenceNumberExt]] {
	return octetValueCodec[LCSReferenceNumberExt]("SS-DataTypes.LCS-ReferenceNumberExt", "LCS-ReferenceNumberExt", []primitiveRule[LCSReferenceNumberExt]{{invalid: func(value LCSReferenceNumberExt) bool { return !(len(value) >= 1 && len(value) <= 255) }, description: "SIZE (1..255)", clause: "51.5", length: func(value LCSReferenceNumberExt) int { return len(value) }}})
}

// ReportingAccessTypesCodec binds SS-DataTypes.ReportingAccessTypes.
func ReportingAccessTypesCodec() ValueCodec[BERValue[ReportingAccessTypes]] {
	return bitValueCodec("SS-DataTypes.ReportingAccessTypes", "ReportingAccessTypes", []primitiveRule[ReportingAccessTypes]{{invalid: func(value ReportingAccessTypes) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value ReportingAccessTypes) int { return value.BitLength }, encodedLength: func(value ReportingAccessTypes) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// ReportingIndCodec binds SS-DataTypes.ReportingInd.
func ReportingIndCodec() ValueCodec[BERValue[ReportingInd]] {
	return integerValueCodec[ReportingInd]("SS-DataTypes.ReportingInd", "ReportingInd", nil, true)
}

// LCSPeriodicTriggeredInvokeResCodec binds SS-DataTypes.LCS-PeriodicTriggeredInvokeRes.
func LCSPeriodicTriggeredInvokeResCodec() ValueCodec[LCSPeriodicTriggeredInvokeRes] {
	return compositeValueCodec[LCSPeriodicTriggeredInvokeRes, *LCSPeriodicTriggeredInvokeRes]()
}

// LCSEventReportArgCodec binds SS-DataTypes.LCS-EventReportArg.
func LCSEventReportArgCodec() ValueCodec[LCSEventReportArg] {
	return compositeValueCodec[LCSEventReportArg, *LCSEventReportArg]()
}

// EventTypeCodec binds SS-DataTypes.EventType.
func EventTypeCodec() ValueCodec[BERValue[EventType]] {
	return integerValueCodec[EventType]("SS-DataTypes.EventType", "EventType", nil, true)
}

// ControlPlaneCIoT5GSOptimisationCodec binds SS-DataTypes.ControlPlane-CIoT-5GS-Optimisation.
func ControlPlaneCIoT5GSOptimisationCodec() ValueCodec[ControlPlaneCIoT5GSOptimisation] {
	return compositeValueCodec[ControlPlaneCIoT5GSOptimisation, *ControlPlaneCIoT5GSOptimisation]()
}

// MaximumDurationCodec binds SS-DataTypes.MaximumDuration.
func MaximumDurationCodec() ValueCodec[BERValue[MaximumDuration]] {
	return integerValueCodec[MaximumDuration]("SS-DataTypes.MaximumDuration", "MaximumDuration", []primitiveRule[MaximumDuration]{{invalid: func(value MaximumDuration) bool { return !(int64(value) >= 1 && int64(value) <= 10080) }, description: "(1..10080)", clause: "51.4", observed: func(value MaximumDuration) any { return int64(value) }}}, false)
}

// MaximumConsecutiveEventReportsCodec binds SS-DataTypes.MaximumConsecutiveEventReports.
func MaximumConsecutiveEventReportsCodec() ValueCodec[BERValue[MaximumConsecutiveEventReports]] {
	return integerValueCodec[MaximumConsecutiveEventReports]("SS-DataTypes.MaximumConsecutiveEventReports", "MaximumConsecutiveEventReports", []primitiveRule[MaximumConsecutiveEventReports]{{invalid: func(value MaximumConsecutiveEventReports) bool { return !(int64(value) >= 1 && int64(value) <= 1023) }, description: "(1..1023)", clause: "51.4", observed: func(value MaximumConsecutiveEventReports) any { return int64(value) }}}, false)
}

// LCSUserPlaneEventReportStatCodec binds SS-DataTypes.LCS-UserPlaneEventReportStat.
func LCSUserPlaneEventReportStatCodec() ValueCodec[BERValue[LCSUserPlaneEventReportStat]] {
	return integerValueCodec[LCSUserPlaneEventReportStat]("SS-DataTypes.LCS-UserPlaneEventReportStat", "LCS-UserPlaneEventReportStat", []primitiveRule[LCSUserPlaneEventReportStat]{{invalid: func(value LCSUserPlaneEventReportStat) bool { return !(int64(value) >= 1 && int64(value) <= 8639999) }, description: "(1..8639999)", clause: "51.4", observed: func(value LCSUserPlaneEventReportStat) any { return int64(value) }}}, false)
}

// LCSUserPlaneReportAFAddrCodec binds SS-DataTypes.LCS-UserPlaneReportAFAddr.
func LCSUserPlaneReportAFAddrCodec() ValueCodec[LCSUserPlaneReportAFAddr] {
	return compositeValueCodec[LCSUserPlaneReportAFAddr, *LCSUserPlaneReportAFAddr]()
}

// Ipv4AddrsCodec binds SS-DataTypes.Ipv4Addrs.
func Ipv4AddrsCodec() ValueCodec[Ipv4Addrs] {
	return pointerValueCodec(UnmarshalBERIpv4Addrs, MarshalBERIpv4Addrs, MarshalDERIpv4Addrs)
}

// Ipv6AddrsCodec binds SS-DataTypes.Ipv6Addrs.
func Ipv6AddrsCodec() ValueCodec[Ipv6Addrs] {
	return pointerValueCodec(UnmarshalBERIpv6Addrs, MarshalBERIpv6Addrs, MarshalDERIpv6Addrs)
}

// Ipv4AddrCodec binds SS-DataTypes.Ipv4Addr.
func Ipv4AddrCodec() ValueCodec[BERValue[Ipv4Addr]] {
	return octetValueCodec[Ipv4Addr]("SS-DataTypes.Ipv4Addr", "Ipv4Addr", []primitiveRule[Ipv4Addr]{{invalid: func(value Ipv4Addr) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value Ipv4Addr) int { return len(value) }}})
}

// Ipv6AddrCodec binds SS-DataTypes.Ipv6Addr.
func Ipv6AddrCodec() ValueCodec[BERValue[Ipv6Addr]] {
	return octetValueCodec[Ipv6Addr]("SS-DataTypes.Ipv6Addr", "Ipv6Addr", []primitiveRule[Ipv6Addr]{{invalid: func(value Ipv6Addr) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value Ipv6Addr) int { return len(value) }}})
}

// LCSCumulativeReportCriteriaCodec binds SS-DataTypes.LCS-CumulativeReportCriteria.
func LCSCumulativeReportCriteriaCodec() ValueCodec[LCSCumulativeReportCriteria] {
	return compositeValueCodec[LCSCumulativeReportCriteria, *LCSCumulativeReportCriteria]()
}

// LCSCumulativeReportTimerCriteriaCodec binds SS-DataTypes.LCS-CumulativeReportTimerCriteria.
func LCSCumulativeReportTimerCriteriaCodec() ValueCodec[BERValue[LCSCumulativeReportTimerCriteria]] {
	return integerValueCodec[LCSCumulativeReportTimerCriteria]("SS-DataTypes.LCS-CumulativeReportTimerCriteria", "LCS-CumulativeReportTimerCriteria", []primitiveRule[LCSCumulativeReportTimerCriteria]{{invalid: func(value LCSCumulativeReportTimerCriteria) bool {
		return !(int64(value) >= 1 && int64(value) <= 8639999)
	}, description: "(1..8639999)", clause: "51.4", observed: func(value LCSCumulativeReportTimerCriteria) any { return int64(value) }}}, false)
}

// LCSCumulativeReportCounterCriteriaCodec binds SS-DataTypes.LCS-CumulativeReportCounterCriteria.
func LCSCumulativeReportCounterCriteriaCodec() ValueCodec[BERValue[LCSCumulativeReportCounterCriteria]] {
	return integerValueCodec[LCSCumulativeReportCounterCriteria]("SS-DataTypes.LCS-CumulativeReportCounterCriteria", "LCS-CumulativeReportCounterCriteria", []primitiveRule[LCSCumulativeReportCounterCriteria]{{invalid: func(value LCSCumulativeReportCounterCriteria) bool {
		return !(int64(value) >= 1 && int64(value) <= 8639999)
	}, description: "(1..8639999)", clause: "51.4", observed: func(value LCSCumulativeReportCounterCriteria) any { return int64(value) }}}, false)
}

// DataTypesFQDNCodec binds SS-DataTypes.FQDN.
func DataTypesFQDNCodec() ValueCodec[BERValue[DataTypesFQDN]] {
	return octetValueCodec[DataTypesFQDN]("SS-DataTypes.FQDN", "FQDN", []primitiveRule[DataTypesFQDN]{{invalid: func(value DataTypesFQDN) bool { return !(len(value) >= 4 && len(value) <= 253) }, description: "SIZE (4..253)", clause: "51.5", length: func(value DataTypesFQDN) int { return len(value) }}})
}

// LCSEventReportResCodec binds SS-DataTypes.LCS-EventReportRes.
func LCSEventReportResCodec() ValueCodec[LCSEventReportRes] {
	return compositeValueCodec[LCSEventReportRes, *LCSEventReportRes]()
}

// LCSCancelDeferredLocationArgCodec binds SS-DataTypes.LCS-CancelDeferredLocationArg.
func LCSCancelDeferredLocationArgCodec() ValueCodec[LCSCancelDeferredLocationArg] {
	return compositeValueCodec[LCSCancelDeferredLocationArg, *LCSCancelDeferredLocationArg]()
}

// LCSLocationPrivacySettingArgCodec binds SS-DataTypes.LCS-LocationPrivacySettingArg.
func LCSLocationPrivacySettingArgCodec() ValueCodec[LCSLocationPrivacySettingArg] {
	return compositeValueCodec[LCSLocationPrivacySettingArg, *LCSLocationPrivacySettingArg]()
}

// LCSLocationPrivacyIndicationCodec binds SS-DataTypes.LCS-LocationPrivacyIndication.
func LCSLocationPrivacyIndicationCodec() ValueCodec[BERValue[LCSLocationPrivacyIndication]] {
	return integerValueCodec[LCSLocationPrivacyIndication]("SS-DataTypes.LCS-LocationPrivacyIndication", "LCS-LocationPrivacyIndication", nil, true)
}

// LCSValidTimePeriodCodec binds SS-DataTypes.LCS-ValidTimePeriod.
func LCSValidTimePeriodCodec() ValueCodec[LCSValidTimePeriod] {
	return compositeValueCodec[LCSValidTimePeriod, *LCSValidTimePeriod]()
}

// DateTimeCodec binds SS-DataTypes.DateTime.
func DateTimeCodec() ValueCodec[BERValue[DateTime]] {
	return octetValueCodec[DateTime]("SS-DataTypes.DateTime", "DateTime", []primitiveRule[DateTime]{{invalid: func(value DateTime) bool { return !(len(value) == 30) }, description: "SIZE (30)", clause: "51.5", length: func(value DateTime) int { return len(value) }}})
}

// LCSPruAssociationArgCodec binds SS-DataTypes.LCS-PruAssociationArg.
func LCSPruAssociationArgCodec() ValueCodec[LCSPruAssociationArg] {
	return compositeValueCodec[LCSPruAssociationArg, *LCSPruAssociationArg]()
}

// LCSAssociationTypeCodec binds SS-DataTypes.LCS-AssociationType.
func LCSAssociationTypeCodec() ValueCodec[BERValue[LCSAssociationType]] {
	return integerValueCodec[LCSAssociationType]("SS-DataTypes.LCS-AssociationType", "LCS-AssociationType", nil, true)
}

// LCSStateOfPruCodec binds SS-DataTypes.LCS-StateOfPru.
func LCSStateOfPruCodec() ValueCodec[BERValue[LCSStateOfPru]] {
	return integerValueCodec[LCSStateOfPru]("SS-DataTypes.LCS-StateOfPru", "LCS-StateOfPru", nil, true)
}

// LCSPruAssociationResCodec binds SS-DataTypes.LCS-PruAssociationRes.
func LCSPruAssociationResCodec() ValueCodec[LCSPruAssociationRes] {
	return compositeValueCodec[LCSPruAssociationRes, *LCSPruAssociationRes]()
}

// LCSPeriodicUpdateTimerCodec binds SS-DataTypes.LCS-PeriodicUpdateTimer.
func LCSPeriodicUpdateTimerCodec() ValueCodec[BERValue[LCSPeriodicUpdateTimer]] {
	return integerValueCodec[LCSPeriodicUpdateTimer]("SS-DataTypes.LCS-PeriodicUpdateTimer", "LCS-PeriodicUpdateTimer", []primitiveRule[LCSPeriodicUpdateTimer]{{invalid: func(value LCSPeriodicUpdateTimer) bool { return !(int64(value) >= 1 && int64(value) <= 4294967295) }, description: "(1..4294967295)", clause: "51.4", observed: func(value LCSPeriodicUpdateTimer) any { return int64(value) }}}, false)
}

// LCSPruUpdateTriggerCodec binds SS-DataTypes.LCS-PruUpdateTrigger.
func LCSPruUpdateTriggerCodec() ValueCodec[BERValue[LCSPruUpdateTrigger]] {
	return bitValueCodec("SS-DataTypes.LCS-PruUpdateTrigger", "LCS-PruUpdateTrigger", []primitiveRule[LCSPruUpdateTrigger]{{invalid: func(value LCSPruUpdateTrigger) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value LCSPruUpdateTrigger) int { return value.BitLength }, encodedLength: func(value LCSPruUpdateTrigger) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// LCSPruDisassociationArgCodec binds SS-DataTypes.LCS-PruDisassociationArg.
func LCSPruDisassociationArgCodec() ValueCodec[LCSPruDisassociationArg] {
	return compositeValueCodec[LCSPruDisassociationArg, *LCSPruDisassociationArg]()
}

// SLMTLRTypeCodec binds SS-DataTypes.SLMTLR-Type.
func SLMTLRTypeCodec() ValueCodec[BERValue[SLMTLRType]] {
	return integerValueCodec[SLMTLRType]("SS-DataTypes.SLMTLR-Type", "SLMTLR-Type", nil, true)
}

// LCSSLMTLRArgCodec binds SS-DataTypes.LCS-SLMTLRArg.
func LCSSLMTLRArgCodec() ValueCodec[LCSSLMTLRArg] {
	return compositeValueCodec[LCSSLMTLRArg, *LCSSLMTLRArg]()
}

// LocatedUEselectCodec binds SS-DataTypes.LocatedUEselect.
func LocatedUEselectCodec() ValueCodec[BERValue[LocatedUEselect]] {
	return integerValueCodec[LocatedUEselect]("SS-DataTypes.LocatedUEselect", "LocatedUEselect", nil, true)
}

// CoordinateIDCodec binds SS-DataTypes.CoordinateID.
func CoordinateIDCodec() ValueCodec[BERValue[CoordinateID]] {
	return integerValueCodec[CoordinateID]("SS-DataTypes.CoordinateID", "CoordinateID", []primitiveRule[CoordinateID]{{invalid: func(value CoordinateID) bool { return !(int64(value) >= 0 && int64(value) <= 511) }, description: "(0..511)", clause: "51.4", observed: func(value CoordinateID) any { return int64(value) }}}, false)
}

// LCSSLMTLRResCodec binds SS-DataTypes.LCS-SLMTLRRes.
func LCSSLMTLRResCodec() ValueCodec[LCSSLMTLRRes] {
	return compositeValueCodec[LCSSLMTLRRes, *LCSSLMTLRRes]()
}

// RangingSLPPListCodec binds SS-DataTypes.RangingSLPPList.
func RangingSLPPListCodec() ValueCodec[RangingSLPPList] {
	return pointerValueCodec(UnmarshalBERRangingSLPPList, MarshalBERRangingSLPPList, MarshalDERRangingSLPPList)
}

// RangingSLPPInfoCodec binds SS-DataTypes.RangingSLPPInfo.
func RangingSLPPInfoCodec() ValueCodec[RangingSLPPInfo] {
	return compositeValueCodec[RangingSLPPInfo, *RangingSLPPInfo]()
}

// SlPosProtocolPDUCodec binds SS-DataTypes.SlPosProtocolPDU.
func SlPosProtocolPDUCodec() ValueCodec[BERValue[SlPosProtocolPDU]] {
	return octetValueCodec[SlPosProtocolPDU]("SS-DataTypes.SlPosProtocolPDU", "SlPosProtocolPDU", nil)
}

// UEBasedCodec binds SS-DataTypes.UEBased.
func UEBasedCodec() ValueCodec[BERValue[UEBased]] {
	return integerValueCodec[UEBased]("SS-DataTypes.UEBased", "UEBased", nil, true)
}

// LCSDLRSPPTransportArgCodec binds SS-DataTypes.LCS-DLRSPPTransportArg.
func LCSDLRSPPTransportArgCodec() ValueCodec[LCSDLRSPPTransportArg] {
	return compositeValueCodec[LCSDLRSPPTransportArg, *LCSDLRSPPTransportArg]()
}

// LCSDLRSPPTransportResCodec binds SS-DataTypes.LCS-DLRSPPTransportRes.
func LCSDLRSPPTransportResCodec() ValueCodec[LCSDLRSPPTransportRes] {
	return compositeValueCodec[LCSDLRSPPTransportRes, *LCSDLRSPPTransportRes]()
}

// LCSULRSPPTransportArgCodec binds SS-DataTypes.LCS-ULRSPPTransportArg.
func LCSULRSPPTransportArgCodec() ValueCodec[LCSULRSPPTransportArg] {
	return compositeValueCodec[LCSULRSPPTransportArg, *LCSULRSPPTransportArg]()
}

// LCSULRSPPTransportResCodec binds SS-DataTypes.LCS-ULRSPPTransportRes.
func LCSULRSPPTransportResCodec() ValueCodec[LCSULRSPPTransportRes] {
	return compositeValueCodec[LCSULRSPPTransportRes, *LCSULRSPPTransportRes]()
}

// PruAssociationRejParamCodec binds SS-Errors.PruAssociationRejParam.
func PruAssociationRejParamCodec() ValueCodec[PruAssociationRejParam] {
	return compositeValueCodec[PruAssociationRejParam, *PruAssociationRejParam]()
}
