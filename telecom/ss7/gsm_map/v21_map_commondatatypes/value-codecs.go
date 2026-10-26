// Code generated from ASN.1. DO NOT EDIT.

package v21_map_commondatatypes

import (
	"fmt"
	"math/big"
	"reflect"
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

// DecodeBER delegates one complete BER value to the bound decoder with opts.
// Generated factories validate strictly by default; ber.WithTolerance records
// representable validation violations in its log. Malformed
// structure and exhausted limits remain errors. ber.WithDecodeLimits and
// ber.WithDiagnosticLimits control budgets; ber.WithoutReplayCapture omits capture.
// Otherwise retained forms permit later
// byte-exact BER replay of unchanged values. Trailing bytes and invalid options
// produce errors matching ber.ErrExtraData and ber.ErrInvalidValue, respectively;
// exhausted limits match ber.ErrResourceLimit. MAP source roots apply TS 29.002
// V19.1.0 §17.1.1; other roots use X.690 (02/2021) §8.
// Decoder errors are returned unchanged. Every error returns the zero T,
// without retaining a partial value or received form.
// An invalid codec, including the zero value, returns the zero T and
// ber.ErrInvalidCodec without calling a decoder.
func (c ValueCodec[T]) DecodeBER(data []byte, opts ...ber.DecodeOption) (T, error) {
	if !c.valid() {
		var zero T
		return zero, ber.ErrInvalidCodec
	}
	value, err := c.decode(data, opts...)
	if err != nil {
		var zero T
		return zero, err
	}
	return value, nil
}

// EncodeBER delegates value to the bound BER encoder with opts.
// Generated factories validate strictly by default; ber.WithTolerance records
// representable violations in its log. Unchanged received forms replay byte
// exactly when the selected policy accepts them; ber.WithoutBERReplay rebuilds
// typed values recursively. Strict MAP replay rejects retained profile
// violations; edited values repair affected typed parts while preserving clean
// parts. Fresh MAP forms follow TS 29.002 V19.1.0 §17.1.1; generic BER follows
// X.690 (02/2021) §8. Invalid options and unrepresentable values remain errors.
// Encoder errors are returned unchanged. An invalid codec, including the zero
// value, returns nil and ber.ErrInvalidCodec without calling an encoder.
func (c ValueCodec[T]) EncodeBER(value T, opts ...ber.EncodeOption) ([]byte, error) {
	if !c.valid() {
		return nil, ber.ErrInvalidCodec
	}
	return c.encode(value, opts...)
}

// EncodeDER delegates value to the bound DER encoder without BER options.
// Generated factories validate strictly and rebuild the canonical encoding
// instead of replaying received BER forms (X.690 (02/2021) §§10–11).
// Encoder errors are returned unchanged. An invalid codec, including the zero
// value, returns nil and ber.ErrInvalidCodec without calling an encoder.
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
		defer func() {
			returnErr = ber.LocateDecodeError(returnErr, opts)
			if returnErr != nil {
				result = BERValue[T]{}
			}
		}()
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

// P is supplied as *T by generated entries, sharing the pointer shape.
func marshalFramedValue[P any](value P, node *ber.ReplayNode, opts []ber.EncodeOption, recursive, fresh func(P, ...ber.EncodeOption) ([]byte, error), flags byte, decoders ...func([]byte, ...ber.DecodeOption) (P, error)) (encoded []byte, returnErr error) {
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
				decoder, ok := reflect.New(reflect.TypeOf(value).Elem()).Interface().(interface {
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

// CommonDataTypesTBCDSTRINGCodec binds MAP-CommonDataTypes.TBCD-STRING.
func CommonDataTypesTBCDSTRINGCodec() ValueCodec[BERValue[CommonDataTypesTBCDSTRING]] {
	return octetValueCodec[CommonDataTypesTBCDSTRING]("MAP-CommonDataTypes.TBCD-STRING", "TBCD-STRING", nil)
}

// CommonDataTypesDiameterIdentityCodec binds MAP-CommonDataTypes.DiameterIdentity.
func CommonDataTypesDiameterIdentityCodec() ValueCodec[BERValue[CommonDataTypesDiameterIdentity]] {
	return octetValueCodec[CommonDataTypesDiameterIdentity]("MAP-CommonDataTypes.DiameterIdentity", "DiameterIdentity", []primitiveRule[CommonDataTypesDiameterIdentity]{{invalid: func(value CommonDataTypesDiameterIdentity) bool { return !(len(value) >= 9 && len(value) <= 255) }, description: "SIZE (9..255)", clause: "51.5", length: func(value CommonDataTypesDiameterIdentity) int { return len(value) }}})
}

// CommonDataTypesAddressStringCodec binds MAP-CommonDataTypes.AddressString.
func CommonDataTypesAddressStringCodec() ValueCodec[BERValue[CommonDataTypesAddressString]] {
	return octetValueCodec[CommonDataTypesAddressString]("MAP-CommonDataTypes.AddressString", "AddressString", []primitiveRule[CommonDataTypesAddressString]{{invalid: func(value CommonDataTypesAddressString) bool { return !(len(value) >= 1 && len(value) <= 20) }, description: "SIZE (1..20)", clause: "51.5", length: func(value CommonDataTypesAddressString) int { return len(value) }}})
}

// CommonDataTypesISDNAddressStringCodec binds MAP-CommonDataTypes.ISDN-AddressString.
func CommonDataTypesISDNAddressStringCodec() ValueCodec[BERValue[CommonDataTypesISDNAddressString]] {
	return pointerValueCodec(UnmarshalBERCommonDataTypesISDNAddressString, MarshalBERCommonDataTypesISDNAddressString, MarshalDERCommonDataTypesISDNAddressString)
}

// CommonDataTypesFTNAddressStringCodec binds MAP-CommonDataTypes.FTN-AddressString.
func CommonDataTypesFTNAddressStringCodec() ValueCodec[BERValue[CommonDataTypesFTNAddressString]] {
	return pointerValueCodec(UnmarshalBERCommonDataTypesFTNAddressString, MarshalBERCommonDataTypesFTNAddressString, MarshalDERCommonDataTypesFTNAddressString)
}

// CommonDataTypesISDNSubaddressStringCodec binds MAP-CommonDataTypes.ISDN-SubaddressString.
func CommonDataTypesISDNSubaddressStringCodec() ValueCodec[BERValue[CommonDataTypesISDNSubaddressString]] {
	return octetValueCodec[CommonDataTypesISDNSubaddressString]("MAP-CommonDataTypes.ISDN-SubaddressString", "ISDN-SubaddressString", []primitiveRule[CommonDataTypesISDNSubaddressString]{{invalid: func(value CommonDataTypesISDNSubaddressString) bool { return !(len(value) >= 1 && len(value) <= 21) }, description: "SIZE (1..21)", clause: "51.5", length: func(value CommonDataTypesISDNSubaddressString) int { return len(value) }}})
}

// CommonDataTypesExternalSignalInfoCodec binds MAP-CommonDataTypes.ExternalSignalInfo.
func CommonDataTypesExternalSignalInfoCodec() ValueCodec[CommonDataTypesExternalSignalInfo] {
	return compositeValueCodec[CommonDataTypesExternalSignalInfo, *CommonDataTypesExternalSignalInfo]()
}

// CommonDataTypesSignalInfoCodec binds MAP-CommonDataTypes.SignalInfo.
func CommonDataTypesSignalInfoCodec() ValueCodec[BERValue[CommonDataTypesSignalInfo]] {
	return octetValueCodec[CommonDataTypesSignalInfo]("MAP-CommonDataTypes.SignalInfo", "SignalInfo", []primitiveRule[CommonDataTypesSignalInfo]{{invalid: func(value CommonDataTypesSignalInfo) bool { return !(len(value) >= 1 && len(value) <= 200) }, description: "SIZE (1..200)", clause: "51.5", length: func(value CommonDataTypesSignalInfo) int { return len(value) }}})
}

// CommonDataTypesProtocolIdCodec binds MAP-CommonDataTypes.ProtocolId.
func CommonDataTypesProtocolIdCodec() ValueCodec[BERValue[CommonDataTypesProtocolId]] {
	return integerValueCodec[CommonDataTypesProtocolId]("MAP-CommonDataTypes.ProtocolId", "ProtocolId", []primitiveRule[CommonDataTypesProtocolId]{{invalid: func(value CommonDataTypesProtocolId) bool {
		return (int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4)
	}, description: "ENUMERATED {1, 2, 3, 4}", clause: "20", observed: func(value CommonDataTypesProtocolId) any { return int64(value) }}}, true)
}

// CommonDataTypesExtExternalSignalInfoCodec binds MAP-CommonDataTypes.Ext-ExternalSignalInfo.
func CommonDataTypesExtExternalSignalInfoCodec() ValueCodec[CommonDataTypesExtExternalSignalInfo] {
	return compositeValueCodec[CommonDataTypesExtExternalSignalInfo, *CommonDataTypesExtExternalSignalInfo]()
}

// CommonDataTypesExtProtocolIdCodec binds MAP-CommonDataTypes.Ext-ProtocolId.
func CommonDataTypesExtProtocolIdCodec() ValueCodec[BERValue[CommonDataTypesExtProtocolId]] {
	return integerValueCodec[CommonDataTypesExtProtocolId]("MAP-CommonDataTypes.Ext-ProtocolId", "Ext-ProtocolId", nil, true)
}

// CommonDataTypesAccessNetworkSignalInfoCodec binds MAP-CommonDataTypes.AccessNetworkSignalInfo.
func CommonDataTypesAccessNetworkSignalInfoCodec() ValueCodec[CommonDataTypesAccessNetworkSignalInfo] {
	return compositeValueCodec[CommonDataTypesAccessNetworkSignalInfo, *CommonDataTypesAccessNetworkSignalInfo]()
}

// CommonDataTypesLongSignalInfoCodec binds MAP-CommonDataTypes.LongSignalInfo.
func CommonDataTypesLongSignalInfoCodec() ValueCodec[BERValue[CommonDataTypesLongSignalInfo]] {
	return octetValueCodec[CommonDataTypesLongSignalInfo]("MAP-CommonDataTypes.LongSignalInfo", "LongSignalInfo", []primitiveRule[CommonDataTypesLongSignalInfo]{{invalid: func(value CommonDataTypesLongSignalInfo) bool { return !(len(value) >= 1 && len(value) <= 2560) }, description: "SIZE (1..2560)", clause: "51.5", length: func(value CommonDataTypesLongSignalInfo) int { return len(value) }}})
}

// CommonDataTypesAccessNetworkProtocolIdCodec binds MAP-CommonDataTypes.AccessNetworkProtocolId.
func CommonDataTypesAccessNetworkProtocolIdCodec() ValueCodec[BERValue[CommonDataTypesAccessNetworkProtocolId]] {
	return integerValueCodec[CommonDataTypesAccessNetworkProtocolId]("MAP-CommonDataTypes.AccessNetworkProtocolId", "AccessNetworkProtocolId", nil, true)
}

// CommonDataTypesAlertingPatternCodec binds MAP-CommonDataTypes.AlertingPattern.
func CommonDataTypesAlertingPatternCodec() ValueCodec[BERValue[CommonDataTypesAlertingPattern]] {
	return octetValueCodec[CommonDataTypesAlertingPattern]("MAP-CommonDataTypes.AlertingPattern", "AlertingPattern", []primitiveRule[CommonDataTypesAlertingPattern]{{invalid: func(value CommonDataTypesAlertingPattern) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value CommonDataTypesAlertingPattern) int { return len(value) }}})
}

// CommonDataTypesGSNAddressCodec binds MAP-CommonDataTypes.GSN-Address.
func CommonDataTypesGSNAddressCodec() ValueCodec[BERValue[CommonDataTypesGSNAddress]] {
	return octetValueCodec[CommonDataTypesGSNAddress]("MAP-CommonDataTypes.GSN-Address", "GSN-Address", []primitiveRule[CommonDataTypesGSNAddress]{{invalid: func(value CommonDataTypesGSNAddress) bool { return !(len(value) >= 5 && len(value) <= 17) }, description: "SIZE (5..17)", clause: "51.5", length: func(value CommonDataTypesGSNAddress) int { return len(value) }}})
}

// CommonDataTypesTimeCodec binds MAP-CommonDataTypes.Time.
func CommonDataTypesTimeCodec() ValueCodec[BERValue[CommonDataTypesTime]] {
	return octetValueCodec[CommonDataTypesTime]("MAP-CommonDataTypes.Time", "Time", []primitiveRule[CommonDataTypesTime]{{invalid: func(value CommonDataTypesTime) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value CommonDataTypesTime) int { return len(value) }}})
}

// CommonDataTypesIMSICodec binds MAP-CommonDataTypes.IMSI.
func CommonDataTypesIMSICodec() ValueCodec[BERValue[CommonDataTypesIMSI]] {
	return pointerValueCodec(UnmarshalBERCommonDataTypesIMSI, MarshalBERCommonDataTypesIMSI, MarshalDERCommonDataTypesIMSI)
}

// CommonDataTypesIdentityCodec binds MAP-CommonDataTypes.Identity.
func CommonDataTypesIdentityCodec() ValueCodec[CommonDataTypesIdentity] {
	return compositeValueCodec[CommonDataTypesIdentity, *CommonDataTypesIdentity]()
}

// CommonDataTypesIMSIWithLMSICodec binds MAP-CommonDataTypes.IMSI-WithLMSI.
func CommonDataTypesIMSIWithLMSICodec() ValueCodec[CommonDataTypesIMSIWithLMSI] {
	return compositeValueCodec[CommonDataTypesIMSIWithLMSI, *CommonDataTypesIMSIWithLMSI]()
}

// CommonDataTypesASCICallReferenceCodec binds MAP-CommonDataTypes.ASCI-CallReference.
func CommonDataTypesASCICallReferenceCodec() ValueCodec[BERValue[CommonDataTypesASCICallReference]] {
	return pointerValueCodec(UnmarshalBERCommonDataTypesASCICallReference, MarshalBERCommonDataTypesASCICallReference, MarshalDERCommonDataTypesASCICallReference)
}

// CommonDataTypesTMSICodec binds MAP-CommonDataTypes.TMSI.
func CommonDataTypesTMSICodec() ValueCodec[BERValue[CommonDataTypesTMSI]] {
	return octetValueCodec[CommonDataTypesTMSI]("MAP-CommonDataTypes.TMSI", "TMSI", []primitiveRule[CommonDataTypesTMSI]{{invalid: func(value CommonDataTypesTMSI) bool { return !(len(value) >= 1 && len(value) <= 4) }, description: "SIZE (1..4)", clause: "51.5", length: func(value CommonDataTypesTMSI) int { return len(value) }}})
}

// CommonDataTypesSubscriberIdCodec binds MAP-CommonDataTypes.SubscriberId.
func CommonDataTypesSubscriberIdCodec() ValueCodec[CommonDataTypesSubscriberId] {
	return compositeValueCodec[CommonDataTypesSubscriberId, *CommonDataTypesSubscriberId]()
}

// CommonDataTypesIMEICodec binds MAP-CommonDataTypes.IMEI.
func CommonDataTypesIMEICodec() ValueCodec[BERValue[CommonDataTypesIMEI]] {
	return pointerValueCodec(UnmarshalBERCommonDataTypesIMEI, MarshalBERCommonDataTypesIMEI, MarshalDERCommonDataTypesIMEI)
}

// CommonDataTypesHLRIdCodec binds MAP-CommonDataTypes.HLR-Id.
func CommonDataTypesHLRIdCodec() ValueCodec[BERValue[CommonDataTypesHLRId]] {
	return pointerValueCodec(UnmarshalBERCommonDataTypesHLRId, MarshalBERCommonDataTypesHLRId, MarshalDERCommonDataTypesHLRId)
}

// CommonDataTypesHLRListCodec binds MAP-CommonDataTypes.HLR-List.
func CommonDataTypesHLRListCodec() ValueCodec[CommonDataTypesHLRList] {
	return pointerValueCodec(UnmarshalBERCommonDataTypesHLRList, MarshalBERCommonDataTypesHLRList, MarshalDERCommonDataTypesHLRList)
}

// CommonDataTypesLMSICodec binds MAP-CommonDataTypes.LMSI.
func CommonDataTypesLMSICodec() ValueCodec[BERValue[CommonDataTypesLMSI]] {
	return octetValueCodec[CommonDataTypesLMSI]("MAP-CommonDataTypes.LMSI", "LMSI", []primitiveRule[CommonDataTypesLMSI]{{invalid: func(value CommonDataTypesLMSI) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value CommonDataTypesLMSI) int { return len(value) }}})
}

// CommonDataTypesGlobalCellIdCodec binds MAP-CommonDataTypes.GlobalCellId.
func CommonDataTypesGlobalCellIdCodec() ValueCodec[BERValue[CommonDataTypesGlobalCellId]] {
	return octetValueCodec[CommonDataTypesGlobalCellId]("MAP-CommonDataTypes.GlobalCellId", "GlobalCellId", []primitiveRule[CommonDataTypesGlobalCellId]{{invalid: func(value CommonDataTypesGlobalCellId) bool { return !(len(value) >= 5 && len(value) <= 7) }, description: "SIZE (5..7)", clause: "51.5", length: func(value CommonDataTypesGlobalCellId) int { return len(value) }}})
}

// CommonDataTypesNetworkResourceCodec binds MAP-CommonDataTypes.NetworkResource.
func CommonDataTypesNetworkResourceCodec() ValueCodec[BERValue[CommonDataTypesNetworkResource]] {
	return integerValueCodec[CommonDataTypesNetworkResource]("MAP-CommonDataTypes.NetworkResource", "NetworkResource", []primitiveRule[CommonDataTypesNetworkResource]{{invalid: func(value CommonDataTypesNetworkResource) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", clause: "20", observed: func(value CommonDataTypesNetworkResource) any { return int64(value) }}}, true)
}

// CommonDataTypesAdditionalNetworkResourceCodec binds MAP-CommonDataTypes.AdditionalNetworkResource.
func CommonDataTypesAdditionalNetworkResourceCodec() ValueCodec[BERValue[CommonDataTypesAdditionalNetworkResource]] {
	return integerValueCodec[CommonDataTypesAdditionalNetworkResource]("MAP-CommonDataTypes.AdditionalNetworkResource", "AdditionalNetworkResource", nil, true)
}

// CommonDataTypesNAEAPreferredCICodec binds MAP-CommonDataTypes.NAEA-PreferredCI.
func CommonDataTypesNAEAPreferredCICodec() ValueCodec[CommonDataTypesNAEAPreferredCI] {
	return compositeValueCodec[CommonDataTypesNAEAPreferredCI, *CommonDataTypesNAEAPreferredCI]()
}

// CommonDataTypesNAEACICCodec binds MAP-CommonDataTypes.NAEA-CIC.
func CommonDataTypesNAEACICCodec() ValueCodec[BERValue[CommonDataTypesNAEACIC]] {
	return octetValueCodec[CommonDataTypesNAEACIC]("MAP-CommonDataTypes.NAEA-CIC", "NAEA-CIC", []primitiveRule[CommonDataTypesNAEACIC]{{invalid: func(value CommonDataTypesNAEACIC) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value CommonDataTypesNAEACIC) int { return len(value) }}})
}

// CommonDataTypesSubscriberIdentityCodec binds MAP-CommonDataTypes.SubscriberIdentity.
func CommonDataTypesSubscriberIdentityCodec() ValueCodec[CommonDataTypesSubscriberIdentity] {
	return compositeValueCodec[CommonDataTypesSubscriberIdentity, *CommonDataTypesSubscriberIdentity]()
}

// CommonDataTypesLCSClientExternalIDCodec binds MAP-CommonDataTypes.LCSClientExternalID.
func CommonDataTypesLCSClientExternalIDCodec() ValueCodec[CommonDataTypesLCSClientExternalID] {
	return compositeValueCodec[CommonDataTypesLCSClientExternalID, *CommonDataTypesLCSClientExternalID]()
}

// CommonDataTypesLCSClientInternalIDCodec binds MAP-CommonDataTypes.LCSClientInternalID.
func CommonDataTypesLCSClientInternalIDCodec() ValueCodec[BERValue[CommonDataTypesLCSClientInternalID]] {
	return integerValueCodec[CommonDataTypesLCSClientInternalID]("MAP-CommonDataTypes.LCSClientInternalID", "LCSClientInternalID", nil, true)
}

// CommonDataTypesLCSServiceTypeIDCodec binds MAP-CommonDataTypes.LCSServiceTypeID.
func CommonDataTypesLCSServiceTypeIDCodec() ValueCodec[BERValue[CommonDataTypesLCSServiceTypeID]] {
	return integerValueCodec[CommonDataTypesLCSServiceTypeID]("MAP-CommonDataTypes.LCSServiceTypeID", "LCSServiceTypeID", []primitiveRule[CommonDataTypesLCSServiceTypeID]{{invalid: func(value CommonDataTypesLCSServiceTypeID) bool { return !(int64(value) >= 0 && int64(value) <= 127) }, description: "(0..127)", clause: "51.4", observed: func(value CommonDataTypesLCSServiceTypeID) any { return int64(value) }}}, false)
}

// CommonDataTypesPLMNIdCodec binds MAP-CommonDataTypes.PLMN-Id.
func CommonDataTypesPLMNIdCodec() ValueCodec[BERValue[CommonDataTypesPLMNId]] {
	return octetValueCodec[CommonDataTypesPLMNId]("MAP-CommonDataTypes.PLMN-Id", "PLMN-Id", []primitiveRule[CommonDataTypesPLMNId]{{invalid: func(value CommonDataTypesPLMNId) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value CommonDataTypesPLMNId) int { return len(value) }}})
}

// CommonDataTypesEUTRANCGICodec binds MAP-CommonDataTypes.E-UTRAN-CGI.
func CommonDataTypesEUTRANCGICodec() ValueCodec[BERValue[CommonDataTypesEUTRANCGI]] {
	return octetValueCodec[CommonDataTypesEUTRANCGI]("MAP-CommonDataTypes.E-UTRAN-CGI", "E-UTRAN-CGI", []primitiveRule[CommonDataTypesEUTRANCGI]{{invalid: func(value CommonDataTypesEUTRANCGI) bool { return !(len(value) == 7) }, description: "SIZE (7)", clause: "51.5", length: func(value CommonDataTypesEUTRANCGI) int { return len(value) }}})
}

// CommonDataTypesNRCGICodec binds MAP-CommonDataTypes.NR-CGI.
func CommonDataTypesNRCGICodec() ValueCodec[BERValue[CommonDataTypesNRCGI]] {
	return octetValueCodec[CommonDataTypesNRCGI]("MAP-CommonDataTypes.NR-CGI", "NR-CGI", []primitiveRule[CommonDataTypesNRCGI]{{invalid: func(value CommonDataTypesNRCGI) bool { return !(len(value) == 8) }, description: "SIZE (8)", clause: "51.5", length: func(value CommonDataTypesNRCGI) int { return len(value) }}})
}

// CommonDataTypesTAIdCodec binds MAP-CommonDataTypes.TA-Id.
func CommonDataTypesTAIdCodec() ValueCodec[BERValue[CommonDataTypesTAId]] {
	return octetValueCodec[CommonDataTypesTAId]("MAP-CommonDataTypes.TA-Id", "TA-Id", []primitiveRule[CommonDataTypesTAId]{{invalid: func(value CommonDataTypesTAId) bool { return !(len(value) == 5) }, description: "SIZE (5)", clause: "51.5", length: func(value CommonDataTypesTAId) int { return len(value) }}})
}

// CommonDataTypesNRTAIdCodec binds MAP-CommonDataTypes.NR-TA-Id.
func CommonDataTypesNRTAIdCodec() ValueCodec[BERValue[CommonDataTypesNRTAId]] {
	return octetValueCodec[CommonDataTypesNRTAId]("MAP-CommonDataTypes.NR-TA-Id", "NR-TA-Id", []primitiveRule[CommonDataTypesNRTAId]{{invalid: func(value CommonDataTypesNRTAId) bool { return !(len(value) == 6) }, description: "SIZE (6)", clause: "51.5", length: func(value CommonDataTypesNRTAId) int { return len(value) }}})
}

// CommonDataTypesRAIdentityCodec binds MAP-CommonDataTypes.RAIdentity.
func CommonDataTypesRAIdentityCodec() ValueCodec[BERValue[CommonDataTypesRAIdentity]] {
	return octetValueCodec[CommonDataTypesRAIdentity]("MAP-CommonDataTypes.RAIdentity", "RAIdentity", []primitiveRule[CommonDataTypesRAIdentity]{{invalid: func(value CommonDataTypesRAIdentity) bool { return !(len(value) == 6) }, description: "SIZE (6)", clause: "51.5", length: func(value CommonDataTypesRAIdentity) int { return len(value) }}})
}

// CommonDataTypesNetworkNodeDiameterAddressCodec binds MAP-CommonDataTypes.NetworkNodeDiameterAddress.
func CommonDataTypesNetworkNodeDiameterAddressCodec() ValueCodec[CommonDataTypesNetworkNodeDiameterAddress] {
	return compositeValueCodec[CommonDataTypesNetworkNodeDiameterAddress, *CommonDataTypesNetworkNodeDiameterAddress]()
}

// CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAICodec binds MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdOrLAI.
func CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAICodec() ValueCodec[CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI] {
	return compositeValueCodec[CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI, *CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI]()
}

// CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLengthCodec binds MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdFixedLength.
func CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLengthCodec() ValueCodec[BERValue[CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength]] {
	return octetValueCodec[CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength]("MAP-CommonDataTypes.CellGlobalIdOrServiceAreaIdFixedLength", "CellGlobalIdOrServiceAreaIdFixedLength", []primitiveRule[CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength]{{invalid: func(value CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength) bool { return !(len(value) == 7) }, description: "SIZE (7)", clause: "51.5", length: func(value CommonDataTypesCellGlobalIdOrServiceAreaIdFixedLength) int { return len(value) }}})
}

// CommonDataTypesLAIFixedLengthCodec binds MAP-CommonDataTypes.LAIFixedLength.
func CommonDataTypesLAIFixedLengthCodec() ValueCodec[BERValue[CommonDataTypesLAIFixedLength]] {
	return octetValueCodec[CommonDataTypesLAIFixedLength]("MAP-CommonDataTypes.LAIFixedLength", "LAIFixedLength", []primitiveRule[CommonDataTypesLAIFixedLength]{{invalid: func(value CommonDataTypesLAIFixedLength) bool { return !(len(value) == 5) }, description: "SIZE (5)", clause: "51.5", length: func(value CommonDataTypesLAIFixedLength) int { return len(value) }}})
}

// CommonDataTypesBasicServiceCodeCodec binds MAP-CommonDataTypes.BasicServiceCode.
func CommonDataTypesBasicServiceCodeCodec() ValueCodec[CommonDataTypesBasicServiceCode] {
	return compositeValueCodec[CommonDataTypesBasicServiceCode, *CommonDataTypesBasicServiceCode]()
}

// CommonDataTypesExtBasicServiceCodeCodec binds MAP-CommonDataTypes.Ext-BasicServiceCode.
func CommonDataTypesExtBasicServiceCodeCodec() ValueCodec[CommonDataTypesExtBasicServiceCode] {
	return compositeValueCodec[CommonDataTypesExtBasicServiceCode, *CommonDataTypesExtBasicServiceCode]()
}

// CommonDataTypesEMLPPInfoCodec binds MAP-CommonDataTypes.EMLPP-Info.
func CommonDataTypesEMLPPInfoCodec() ValueCodec[CommonDataTypesEMLPPInfo] {
	return compositeValueCodec[CommonDataTypesEMLPPInfo, *CommonDataTypesEMLPPInfo]()
}

// CommonDataTypesEMLPPPriorityCodec binds MAP-CommonDataTypes.EMLPP-Priority.
func CommonDataTypesEMLPPPriorityCodec() ValueCodec[BERValue[CommonDataTypesEMLPPPriority]] {
	return integerValueCodec[CommonDataTypesEMLPPPriority]("MAP-CommonDataTypes.EMLPP-Priority", "EMLPP-Priority", []primitiveRule[CommonDataTypesEMLPPPriority]{{invalid: func(value CommonDataTypesEMLPPPriority) bool { return !(int64(value) >= 0 && int64(value) <= 15) }, description: "(0..15)", clause: "51.4", observed: func(value CommonDataTypesEMLPPPriority) any { return int64(value) }}}, false)
}

// CommonDataTypesMCSSInfoCodec binds MAP-CommonDataTypes.MC-SS-Info.
func CommonDataTypesMCSSInfoCodec() ValueCodec[CommonDataTypesMCSSInfo] {
	return compositeValueCodec[CommonDataTypesMCSSInfo, *CommonDataTypesMCSSInfo]()
}

// CommonDataTypesMaxMCBearersCodec binds MAP-CommonDataTypes.MaxMC-Bearers.
func CommonDataTypesMaxMCBearersCodec() ValueCodec[BERValue[CommonDataTypesMaxMCBearers]] {
	return integerValueCodec[CommonDataTypesMaxMCBearers]("MAP-CommonDataTypes.MaxMC-Bearers", "MaxMC-Bearers", []primitiveRule[CommonDataTypesMaxMCBearers]{{invalid: func(value CommonDataTypesMaxMCBearers) bool { return !(int64(value) >= 2 && int64(value) <= 7) }, description: "(2..7)", clause: "51.4", observed: func(value CommonDataTypesMaxMCBearers) any { return int64(value) }}}, false)
}

// CommonDataTypesMCBearersCodec binds MAP-CommonDataTypes.MC-Bearers.
func CommonDataTypesMCBearersCodec() ValueCodec[BERValue[CommonDataTypesMCBearers]] {
	return integerValueCodec[CommonDataTypesMCBearers]("MAP-CommonDataTypes.MC-Bearers", "MC-Bearers", []primitiveRule[CommonDataTypesMCBearers]{{invalid: func(value CommonDataTypesMCBearers) bool { return !(int64(value) >= 1 && int64(value) <= 7) }, description: "(1..7)", clause: "51.4", observed: func(value CommonDataTypesMCBearers) any { return int64(value) }}}, false)
}

// CommonDataTypesExtSSStatusCodec binds MAP-CommonDataTypes.Ext-SS-Status.
func CommonDataTypesExtSSStatusCodec() ValueCodec[BERValue[CommonDataTypesExtSSStatus]] {
	return octetValueCodec[CommonDataTypesExtSSStatus]("MAP-CommonDataTypes.Ext-SS-Status", "Ext-SS-Status", []primitiveRule[CommonDataTypesExtSSStatus]{{invalid: func(value CommonDataTypesExtSSStatus) bool { return !(len(value) >= 1 && len(value) <= 5) }, description: "SIZE (1..5)", clause: "51.5", length: func(value CommonDataTypesExtSSStatus) int { return len(value) }}})
}

// CommonDataTypesAgeOfLocationInformationCodec binds MAP-CommonDataTypes.AgeOfLocationInformation.
func CommonDataTypesAgeOfLocationInformationCodec() ValueCodec[BERValue[CommonDataTypesAgeOfLocationInformation]] {
	return integerValueCodec[CommonDataTypesAgeOfLocationInformation]("MAP-CommonDataTypes.AgeOfLocationInformation", "AgeOfLocationInformation", []primitiveRule[CommonDataTypesAgeOfLocationInformation]{{invalid: func(value CommonDataTypesAgeOfLocationInformation) bool {
		return !(int64(value) >= 0 && int64(value) <= 32767)
	}, description: "(0..32767)", clause: "51.4", observed: func(value CommonDataTypesAgeOfLocationInformation) any { return int64(value) }}}, false)
}
