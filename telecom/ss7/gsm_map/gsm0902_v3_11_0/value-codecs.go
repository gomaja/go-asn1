// Code generated from ASN.1. DO NOT EDIT.

package gsm0902_v3_11_0

import (
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
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
// exhausted limits match ber.ErrResourceLimit. MAP source roots apply GSM 09.02
// V3.11.0 §6.1; other roots use X.209 (11/1988) §§6–24.
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
// parts. Fresh MAP forms follow GSM 09.02 V3.11.0 §6.1; generic BER follows
// X.209 (11/1988) §§6–24. Invalid options and unrepresentable values remain errors.
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
// instead of replaying received BER forms. Historical BER is defined by X.209 (11/1988).
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
		return ber.TrackGSM0902Phase1Form(opts)
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
		ref := sourceASN1Rule(rule.clause)
		if _, bits := any(value).(runtime.BitString); bits {
			ref = ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}
		}
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
		opts = trackMAPSource(opts, source)
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
	// X.209 (11/1988) §§11.2–11.3: reject malformed storage before SIZE.
	normalize := func(v runtime.BitString, encoding bool, _ []ber.DecodeOption, _ []ber.EncodeOption) (runtime.BitString, error) {
		if encoding {
			return v, ber.ValidateBitStringLength(v.Bytes, v.BitLength)
		}
		return v, nil
	}
	if named {
		normalize = func(v runtime.BitString, encoding bool, opts []ber.DecodeOption, encodeOpts []ber.EncodeOption) (runtime.BitString, error) {
			if encoding {
				return validateEditionBitLength(v, sets, encodeOpts...)
			}
			return keepEditionBitLength(v, sets, opts...), nil
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
			return encodeEditionBitString(v.Bytes, v.BitLength)
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
	return ber.RuleRef{Document: "CCITT X.208", Edition: "11/1988", Clause: clause}
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

// The extension loop owns one lazy base count. X.209 (11/1988) §14:
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

// Historical diagnostics use the exact supplied or received bit count.
// X.208 (11/1988) §§17.10, 37.4.3–37.4.4; X.209 (11/1988) §11.2.
func namedBitObservedLength(value runtime.BitString) int {
	normalized, err := validateEditionBitLength(value, nil)
	if err != nil {
		return value.BitLength
	}
	return normalized.BitLength
}

// Source and path are applied only when normalization refuses a SIZE.
func normalizeNamedBits(value runtime.BitString, sets []ber.NamedBitSizeSet, opts []ber.EncodeOption, component, source string) (runtime.BitString, error) {
	normalized, err := validateEditionBitLength(value, sets, opts...)
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

// X.209 (11/1988) §23.5.3 and Table 2 forbid explicit IA5 escape sequences.
func checkIA5Controls(value string, opts []ber.EncodeOption, component, source string) error {
	if !strings.ContainsRune(value, 0x1b) {
		return nil
	}
	if _, err := ber.EncodeIA5String(value); err == nil {
		return nil
	}
	rule := ber.RuleRef{Document: "CCITT X.209", Edition: "11/1988", Clause: "23.5.3"}
	return ber.CheckEncodedValue(ber.EncodeRule(opts, source, rule), component, "IA5String escape sequences", value)
}

// MAPAbortInformationCodec binds MAP-AbortInformation.MAPAbortInformation.
func MAPAbortInformationCodec() ValueCodec[MAPAbortInformation] {
	return compositeValueCodec[MAPAbortInformation, *MAPAbortInformation]()
}

// TBCDSTRINGCodec binds MAP-DataTypes.TBCD-STRING.
func TBCDSTRINGCodec() ValueCodec[BERValue[TBCDSTRING]] {
	return octetValueCodec[TBCDSTRING]("MAP-DataTypes.TBCD-STRING", "TBCD-STRING", nil)
}

// AddressStringCodec binds MAP-DataTypes.AddressString.
func AddressStringCodec() ValueCodec[BERValue[AddressString]] {
	return octetValueCodec[AddressString]("MAP-DataTypes.AddressString", "AddressString", []primitiveRule[AddressString]{{invalid: func(value AddressString) bool { return !(len(value) >= 1 && len(value) <= 20) }, description: "SIZE (1..20)", clause: "37.4", length: func(value AddressString) int { return len(value) }}})
}

// IsdnAddressStringCodec binds MAP-DataTypes.IsdnAddressString.
func IsdnAddressStringCodec() ValueCodec[BERValue[IsdnAddressString]] {
	return pointerValueCodec(UnmarshalBERIsdnAddressString, MarshalBERIsdnAddressString, MarshalDERIsdnAddressString)
}

// ExternalSignalInfoCodec binds MAP-DataTypes.ExternalSignalInfo.
func ExternalSignalInfoCodec() ValueCodec[ExternalSignalInfo] {
	return compositeValueCodec[ExternalSignalInfo, *ExternalSignalInfo]()
}

// SignalInfoCodec binds MAP-DataTypes.SignalInfo.
func SignalInfoCodec() ValueCodec[BERValue[SignalInfo]] {
	return octetValueCodec[SignalInfo]("MAP-DataTypes.SignalInfo", "SignalInfo", []primitiveRule[SignalInfo]{{invalid: func(value SignalInfo) bool { return !(len(value) >= 1 && len(value) <= 200) }, description: "SIZE (1..200)", clause: "37.4", length: func(value SignalInfo) int { return len(value) }}})
}

// ProtocolIdCodec binds MAP-DataTypes.ProtocolId.
func ProtocolIdCodec() ValueCodec[BERValue[ProtocolId]] {
	return integerValueCodec[ProtocolId]("MAP-DataTypes.ProtocolId", "ProtocolId", []primitiveRule[ProtocolId]{{invalid: func(value ProtocolId) bool {
		return (int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4)
	}, description: "ENUMERATED {1, 2, 3, 4}", clause: "15", observed: func(value ProtocolId) any { return int64(value) }}}, true)
}

// IMSICodec binds MAP-DataTypes.IMSI.
func IMSICodec() ValueCodec[BERValue[IMSI]] {
	return pointerValueCodec(UnmarshalBERIMSI, MarshalBERIMSI, MarshalDERIMSI)
}

// TMSICodec binds MAP-DataTypes.TMSI.
func TMSICodec() ValueCodec[BERValue[TMSI]] {
	return octetValueCodec[TMSI]("MAP-DataTypes.TMSI", "TMSI", []primitiveRule[TMSI]{{invalid: func(value TMSI) bool { return !(len(value) >= 1 && len(value) <= 4) }, description: "SIZE (1..4)", clause: "37.4", length: func(value TMSI) int { return len(value) }}})
}

// SubscriberIdCodec binds MAP-DataTypes.SubscriberId.
func SubscriberIdCodec() ValueCodec[SubscriberId] {
	return compositeValueCodec[SubscriberId, *SubscriberId]()
}

// IMEICodec binds MAP-DataTypes.IMEI.
func IMEICodec() ValueCodec[BERValue[IMEI]] {
	return pointerValueCodec(UnmarshalBERIMEI, MarshalBERIMEI, MarshalDERIMEI)
}

// LocAreaIdCodec binds MAP-DataTypes.LocAreaId.
func LocAreaIdCodec() ValueCodec[BERValue[LocAreaId]] {
	return octetValueCodec[LocAreaId]("MAP-DataTypes.LocAreaId", "LocAreaId", []primitiveRule[LocAreaId]{{invalid: func(value LocAreaId) bool { return !(len(value) >= 2 && len(value) <= 5) }, description: "SIZE (2..5)", clause: "37.4", length: func(value LocAreaId) int { return len(value) }}})
}

// LocationInfoCodec binds MAP-DataTypes.LocationInfo.
func LocationInfoCodec() ValueCodec[LocationInfo] {
	return compositeValueCodec[LocationInfo, *LocationInfo]()
}

// HlrIdCodec binds MAP-DataTypes.HlrId.
func HlrIdCodec() ValueCodec[BERValue[HlrId]] {
	return pointerValueCodec(UnmarshalBERHlrId, MarshalBERHlrId, MarshalDERHlrId)
}

// HlrListCodec binds MAP-DataTypes.HlrList.
func HlrListCodec() ValueCodec[HlrList] {
	return pointerValueCodec(UnmarshalBERHlrList, MarshalBERHlrList, MarshalDERHlrList)
}

// LMsIdCodec binds MAP-DataTypes.LMsId.
func LMsIdCodec() ValueCodec[BERValue[LMsId]] {
	return octetValueCodec[LMsId]("MAP-DataTypes.LMsId", "LMsId", []primitiveRule[LMsId]{{invalid: func(value LMsId) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "37.4", length: func(value LMsId) int { return len(value) }}})
}

// GlobalCellIdCodec binds MAP-DataTypes.GlobalCellId.
func GlobalCellIdCodec() ValueCodec[BERValue[GlobalCellId]] {
	return octetValueCodec[GlobalCellId]("MAP-DataTypes.GlobalCellId", "GlobalCellId", []primitiveRule[GlobalCellId]{{invalid: func(value GlobalCellId) bool { return !(len(value) >= 5 && len(value) <= 7) }, description: "SIZE (5..7)", clause: "37.4", length: func(value GlobalCellId) int { return len(value) }}})
}

// CategoryCodec binds MAP-DataTypes.Category.
func CategoryCodec() ValueCodec[BERValue[Category]] {
	return octetValueCodec[Category]("MAP-DataTypes.Category", "Category", []primitiveRule[Category]{{invalid: func(value Category) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value Category) int { return len(value) }}})
}

// EquipStatusCodec binds MAP-DataTypes.EquipStatus.
func EquipStatusCodec() ValueCodec[BERValue[EquipStatus]] {
	return integerValueCodec[EquipStatus]("MAP-DataTypes.EquipStatus", "EquipStatus", []primitiveRule[EquipStatus]{{invalid: func(value EquipStatus) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "15", observed: func(value EquipStatus) any { return int64(value) }}}, true)
}

// BearerServiceCodeCodec binds MAP-DataTypes.BearerServiceCode.
func BearerServiceCodeCodec() ValueCodec[BERValue[BearerServiceCode]] {
	return octetValueCodec[BearerServiceCode]("MAP-DataTypes.BearerServiceCode", "BearerServiceCode", []primitiveRule[BearerServiceCode]{{invalid: func(value BearerServiceCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value BearerServiceCode) int { return len(value) }}})
}

// BearerServiceListCodec binds MAP-DataTypes.BearerServiceList.
func BearerServiceListCodec() ValueCodec[BearerServiceList] {
	return pointerValueCodec(UnmarshalBERBearerServiceList, MarshalBERBearerServiceList, MarshalDERBearerServiceList)
}

// TeleserviceCodeCodec binds MAP-DataTypes.TeleserviceCode.
func TeleserviceCodeCodec() ValueCodec[BERValue[TeleserviceCode]] {
	return octetValueCodec[TeleserviceCode]("MAP-DataTypes.TeleserviceCode", "TeleserviceCode", []primitiveRule[TeleserviceCode]{{invalid: func(value TeleserviceCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value TeleserviceCode) int { return len(value) }}})
}

// TeleserviceListCodec binds MAP-DataTypes.TeleserviceList.
func TeleserviceListCodec() ValueCodec[TeleserviceList] {
	return pointerValueCodec(UnmarshalBERTeleserviceList, MarshalBERTeleserviceList, MarshalDERTeleserviceList)
}

// BasicServiceCodeCodec binds MAP-DataTypes.BasicServiceCode.
func BasicServiceCodeCodec() ValueCodec[BasicServiceCode] {
	return compositeValueCodec[BasicServiceCode, *BasicServiceCode]()
}

// BasicServiceListCodec binds MAP-DataTypes.BasicServiceList.
func BasicServiceListCodec() ValueCodec[BasicServiceList] {
	return pointerValueCodec(UnmarshalBERBasicServiceList, MarshalBERBasicServiceList, MarshalDERBasicServiceList)
}

// SubscriberStatusCodec binds MAP-DataTypes.SubscriberStatus.
func SubscriberStatusCodec() ValueCodec[BERValue[SubscriberStatus]] {
	return integerValueCodec[SubscriberStatus]("MAP-DataTypes.SubscriberStatus", "SubscriberStatus", []primitiveRule[SubscriberStatus]{{invalid: func(value SubscriberStatus) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "15", observed: func(value SubscriberStatus) any { return int64(value) }}}, true)
}

// SSCodeCodec binds MAP-DataTypes.SS-Code.
func SSCodeCodec() ValueCodec[BERValue[SSCode]] {
	return octetValueCodec[SSCode]("MAP-DataTypes.SS-Code", "SS-Code", []primitiveRule[SSCode]{{invalid: func(value SSCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value SSCode) int { return len(value) }}})
}

// SSCodeListCodec binds MAP-DataTypes.SS-CodeList.
func SSCodeListCodec() ValueCodec[SSCodeList] {
	return pointerValueCodec(UnmarshalBERSSCodeList, MarshalBERSSCodeList, MarshalDERSSCodeList)
}

// SSStatusCodec binds MAP-DataTypes.SS-Status.
func SSStatusCodec() ValueCodec[BERValue[SSStatus]] {
	return octetValueCodec[SSStatus]("MAP-DataTypes.SS-Status", "SS-Status", []primitiveRule[SSStatus]{{invalid: func(value SSStatus) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value SSStatus) int { return len(value) }}})
}

// SSInformationCodec binds MAP-DataTypes.SS-Information.
func SSInformationCodec() ValueCodec[SSInformation] {
	return compositeValueCodec[SSInformation, *SSInformation]()
}

// SSInfoListCodec binds MAP-DataTypes.SS-InfoList.
func SSInfoListCodec() ValueCodec[SSInfoList] {
	return pointerValueCodec(UnmarshalBERSSInfoList, MarshalBERSSInfoList, MarshalDERSSInfoList)
}

// SSDataCodec binds MAP-DataTypes.SS-Data.
func SSDataCodec() ValueCodec[SSData] {
	return compositeValueCodec[SSData, *SSData]()
}

// SSDataListCodec binds MAP-DataTypes.SS-DataList.
func SSDataListCodec() ValueCodec[SSDataList] {
	return pointerValueCodec(UnmarshalBERSSDataList, MarshalBERSSDataList, MarshalDERSSDataList)
}

// SSRequestCodec binds MAP-DataTypes.SS-Request.
func SSRequestCodec() ValueCodec[BERValue[SSRequest]] {
	return integerValueCodec[SSRequest]("MAP-DataTypes.SS-Request", "SS-Request", []primitiveRule[SSRequest]{{invalid: func(value SSRequest) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5}", clause: "15", observed: func(value SSRequest) any { return int64(value) }}}, true)
}

// SSSubscriptionOptionCodec binds MAP-DataTypes.SS-SubscriptionOption.
func SSSubscriptionOptionCodec() ValueCodec[SSSubscriptionOption] {
	return compositeValueCodec[SSSubscriptionOption, *SSSubscriptionOption]()
}

// ForwardingOptionsCodec binds MAP-DataTypes.ForwardingOptions.
func ForwardingOptionsCodec() ValueCodec[BERValue[ForwardingOptions]] {
	return octetValueCodec[ForwardingOptions]("MAP-DataTypes.ForwardingOptions", "ForwardingOptions", []primitiveRule[ForwardingOptions]{{invalid: func(value ForwardingOptions) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value ForwardingOptions) int { return len(value) }}})
}

// UserToUserServiceIndicatorCodec binds MAP-DataTypes.UserToUserServiceIndicator.
func UserToUserServiceIndicatorCodec() ValueCodec[BERValue[UserToUserServiceIndicator]] {
	return octetValueCodec[UserToUserServiceIndicator]("MAP-DataTypes.UserToUserServiceIndicator", "UserToUserServiceIndicator", []primitiveRule[UserToUserServiceIndicator]{{invalid: func(value UserToUserServiceIndicator) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value UserToUserServiceIndicator) int { return len(value) }}})
}

// MaximumConfereesNumberCodec binds MAP-DataTypes.MaximumConfereesNumber.
func MaximumConfereesNumberCodec() ValueCodec[BERValue[MaximumConfereesNumber]] {
	return integerValueCodec[MaximumConfereesNumber]("MAP-DataTypes.MaximumConfereesNumber", "MaximumConfereesNumber", []primitiveRule[MaximumConfereesNumber]{{invalid: func(value MaximumConfereesNumber) bool { return !(int64(value) >= 1 && int64(value) <= 10) }, description: "(1..10)", clause: "37.3", observed: func(value MaximumConfereesNumber) any { return int64(value) }}}, false)
}

// HuntGroupAccessSelectionOrderCodec binds MAP-DataTypes.HuntGroupAccessSelectionOrder.
func HuntGroupAccessSelectionOrderCodec() ValueCodec[BERValue[HuntGroupAccessSelectionOrder]] {
	return integerValueCodec[HuntGroupAccessSelectionOrder]("MAP-DataTypes.HuntGroupAccessSelectionOrder", "HuntGroupAccessSelectionOrder", []primitiveRule[HuntGroupAccessSelectionOrder]{{invalid: func(value HuntGroupAccessSelectionOrder) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "15", observed: func(value HuntGroupAccessSelectionOrder) any { return int64(value) }}}, true)
}

// NoReplyConditionTimeCodec binds MAP-DataTypes.NoReplyConditionTime.
func NoReplyConditionTimeCodec() ValueCodec[BERValue[NoReplyConditionTime]] {
	return integerValueCodec[NoReplyConditionTime]("MAP-DataTypes.NoReplyConditionTime", "NoReplyConditionTime", []primitiveRule[NoReplyConditionTime]{{invalid: func(value NoReplyConditionTime) bool { return !(int64(value) >= 5 && int64(value) <= 30) }, description: "(5..30)", clause: "37.3", observed: func(value NoReplyConditionTime) any { return int64(value) }}}, false)
}

// NumberOfConfereesCodec binds MAP-DataTypes.NumberOfConferees.
func NumberOfConfereesCodec() ValueCodec[BERValue[NumberOfConferees]] {
	return integerValueCodec[NumberOfConferees]("MAP-DataTypes.NumberOfConferees", "NumberOfConferees", []primitiveRule[NumberOfConferees]{{invalid: func(value NumberOfConferees) bool { return !(int64(value) >= 1 && int64(value) <= 10) }, description: "(1..10)", clause: "37.3", observed: func(value NumberOfConferees) any { return int64(value) }}}, false)
}

// CUGFacilitiesCodec binds MAP-DataTypes.CUG-Facilities.
func CUGFacilitiesCodec() ValueCodec[BERValue[CUGFacilities]] {
	return octetValueCodec[CUGFacilities]("MAP-DataTypes.CUG-Facilities", "CUG-Facilities", []primitiveRule[CUGFacilities]{{invalid: func(value CUGFacilities) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value CUGFacilities) int { return len(value) }}})
}

// CUGInterlockCodec binds MAP-DataTypes.CUG-Interlock.
func CUGInterlockCodec() ValueCodec[BERValue[CUGInterlock]] {
	return octetValueCodec[CUGInterlock]("MAP-DataTypes.CUG-Interlock", "CUG-Interlock", []primitiveRule[CUGInterlock]{{invalid: func(value CUGInterlock) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "37.4", length: func(value CUGInterlock) int { return len(value) }}})
}

// CUGIndexCodec binds MAP-DataTypes.CUG-Index.
func CUGIndexCodec() ValueCodec[BERValue[CUGIndex]] {
	return octetValueCodec[CUGIndex]("MAP-DataTypes.CUG-Index", "CUG-Index", []primitiveRule[CUGIndex]{{invalid: func(value CUGIndex) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value CUGIndex) int { return len(value) }}})
}

// CUGOptionsCodec binds MAP-DataTypes.CUG-Options.
func CUGOptionsCodec() ValueCodec[BERValue[CUGOptions]] {
	return octetValueCodec[CUGOptions]("MAP-DataTypes.CUG-Options", "CUG-Options", []primitiveRule[CUGOptions]{{invalid: func(value CUGOptions) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value CUGOptions) int { return len(value) }}})
}

// CUGFeatureCodec binds MAP-DataTypes.CUG-Feature.
func CUGFeatureCodec() ValueCodec[CUGFeature] {
	return compositeValueCodec[CUGFeature, *CUGFeature]()
}

// CUGFeatureListCodec binds MAP-DataTypes.CUG-FeatureList.
func CUGFeatureListCodec() ValueCodec[CUGFeatureList] {
	return pointerValueCodec(UnmarshalBERCUGFeatureList, MarshalBERCUGFeatureList, MarshalDERCUGFeatureList)
}

// CUGInformationCodec binds MAP-DataTypes.CUG-Information.
func CUGInformationCodec() ValueCodec[CUGInformation] {
	return compositeValueCodec[CUGInformation, *CUGInformation]()
}

// ForwardingInfoCodec binds MAP-DataTypes.ForwardingInfo.
func ForwardingInfoCodec() ValueCodec[ForwardingInfo] {
	return compositeValueCodec[ForwardingInfo, *ForwardingInfo]()
}

// ForwardingDataCodec binds MAP-DataTypes.ForwardingData.
func ForwardingDataCodec() ValueCodec[ForwardingData] {
	return compositeValueCodec[ForwardingData, *ForwardingData]()
}

// ForwardingFeatureCodec binds MAP-DataTypes.ForwardingFeature.
func ForwardingFeatureCodec() ValueCodec[ForwardingFeature] {
	return compositeValueCodec[ForwardingFeature, *ForwardingFeature]()
}

// ForwardingFeatureListCodec binds MAP-DataTypes.ForwardingFeatureList.
func ForwardingFeatureListCodec() ValueCodec[ForwardingFeatureList] {
	return pointerValueCodec(UnmarshalBERForwardingFeatureList, MarshalBERForwardingFeatureList, MarshalDERForwardingFeatureList)
}

// CallBarringInfoCodec binds MAP-DataTypes.CallBarringInfo.
func CallBarringInfoCodec() ValueCodec[CallBarringInfo] {
	return compositeValueCodec[CallBarringInfo, *CallBarringInfo]()
}

// CallBarringFeatureCodec binds MAP-DataTypes.CallBarringFeature.
func CallBarringFeatureCodec() ValueCodec[CallBarringFeature] {
	return compositeValueCodec[CallBarringFeature, *CallBarringFeature]()
}

// CallBarringFeatureListCodec binds MAP-DataTypes.CallBarringFeatureList.
func CallBarringFeatureListCodec() ValueCodec[CallBarringFeatureList] {
	return pointerValueCodec(UnmarshalBERCallBarringFeatureList, MarshalBERCallBarringFeatureList, MarshalDERCallBarringFeatureList)
}

// SubscriberDataCodec binds MAP-DataTypes.SubscriberData.
func SubscriberDataCodec() ValueCodec[SubscriberData] {
	return compositeValueCodec[SubscriberData, *SubscriberData]()
}

// SSNotificationCodec binds MAP-DataTypes.SS-Notification.
func SSNotificationCodec() ValueCodec[BERValue[SSNotification]] {
	return octetValueCodec[SSNotification]("MAP-DataTypes.SS-Notification", "SS-Notification", []primitiveRule[SSNotification]{{invalid: func(value SSNotification) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value SSNotification) int { return len(value) }}})
}

// PasswordCodec binds MAP-DataTypes.Password.
func PasswordCodec() ValueCodec[Password] {
	return compositeValueCodec[Password, *Password]()
}

// GuidanceInfoCodec binds MAP-DataTypes.GuidanceInfo.
func GuidanceInfoCodec() ValueCodec[BERValue[GuidanceInfo]] {
	return integerValueCodec[GuidanceInfo]("MAP-DataTypes.GuidanceInfo", "GuidanceInfo", []primitiveRule[GuidanceInfo]{{invalid: func(value GuidanceInfo) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4)
	}, description: "ENUMERATED {0, 1, 2, 3, 4}", clause: "15", observed: func(value GuidanceInfo) any { return int64(value) }}}, true)
}

// SSUserDataCodec binds MAP-DataTypes.SS-UserData.
func SSUserDataCodec() ValueCodec[BERValue[SSUserData]] {
	return pointerValueCodec(UnmarshalBERSSUserData, MarshalBERSSUserData, MarshalDERSSUserData)
}

// CallReferenceCodec binds MAP-DataTypes.CallReference.
func CallReferenceCodec() ValueCodec[BERValue[CallReference]] {
	return octetValueCodec[CallReference]("MAP-DataTypes.CallReference", "CallReference", []primitiveRule[CallReference]{{invalid: func(value CallReference) bool { return !(len(value) >= 1 && len(value) <= 3) }, description: "SIZE (1..3)", clause: "37.4", length: func(value CallReference) int { return len(value) }}})
}

// CallTypeCodec binds MAP-DataTypes.CallType.
func CallTypeCodec() ValueCodec[BERValue[CallType]] {
	return integerValueCodec[CallType]("MAP-DataTypes.CallType", "CallType", []primitiveRule[CallType]{{invalid: func(value CallType) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4)
	}, description: "ENUMERATED {0, 1, 2, 3, 4}", clause: "15", observed: func(value CallType) any { return int64(value) }}}, true)
}

// SSChargingDataCodec binds MAP-DataTypes.SS-ChargingData.
func SSChargingDataCodec() ValueCodec[SSChargingData] {
	return compositeValueCodec[SSChargingData, *SSChargingData]()
}

// SSChargingInfoCodec binds MAP-DataTypes.SS-ChargingInfo.
func SSChargingInfoCodec() ValueCodec[SSChargingInfo] {
	return pointerValueCodec(UnmarshalBERSSChargingInfo, MarshalBERSSChargingInfo, MarshalDERSSChargingInfo)
}

// CallDurationCodec binds MAP-DataTypes.CallDuration.
func CallDurationCodec() ValueCodec[BERValue[CallDuration]] {
	return integerValueCodec[CallDuration]("MAP-DataTypes.CallDuration", "CallDuration", []primitiveRule[CallDuration]{{invalid: func(value CallDuration) bool { return !(int64(value) >= 0 && int64(value) <= 16777215) }, description: "(0..16777215)", clause: "37.3", observed: func(value CallDuration) any { return int64(value) }}}, false)
}

// CallDateTimeCodec binds MAP-DataTypes.CallDateTime.
func CallDateTimeCodec() ValueCodec[BERValue[CallDateTime]] {
	return pointerValueCodec(UnmarshalBERCallDateTime, MarshalBERCallDateTime, MarshalDERCallDateTime)
}

// PacketDataVolumeCodec binds MAP-DataTypes.PacketDataVolume.
func PacketDataVolumeCodec() ValueCodec[BERValue[PacketDataVolume]] {
	return integerValueCodec[PacketDataVolume]("MAP-DataTypes.PacketDataVolume", "PacketDataVolume", []primitiveRule[PacketDataVolume]{{invalid: func(value PacketDataVolume) bool { return !(int64(value) >= 1 && int64(value) <= 100) }, description: "(1..100)", clause: "37.3", observed: func(value PacketDataVolume) any { return int64(value) }}}, false)
}

// ChargeCodec binds MAP-DataTypes.Charge.
func ChargeCodec() ValueCodec[BERValue[Charge]] {
	return integerValueCodec[Charge]("MAP-DataTypes.Charge", "Charge", []primitiveRule[Charge]{{invalid: func(value Charge) bool { return !(int64(value) >= 1 && int64(value) <= 16777215) }, description: "(1..16777215)", clause: "37.3", observed: func(value Charge) any { return int64(value) }}}, false)
}

// ChargingUnitCodec binds MAP-DataTypes.ChargingUnit.
func ChargingUnitCodec() ValueCodec[BERValue[ChargingUnit]] {
	return integerValueCodec[ChargingUnit]("MAP-DataTypes.ChargingUnit", "ChargingUnit", []primitiveRule[ChargingUnit]{{invalid: func(value ChargingUnit) bool { return (int64(value) != 0) }, description: "ENUMERATED {0}", clause: "15", observed: func(value ChargingUnit) any { return int64(value) }}}, true)
}

// CallStatusCodec binds MAP-DataTypes.CallStatus.
func CallStatusCodec() ValueCodec[BERValue[CallStatus]] {
	return integerValueCodec[CallStatus]("MAP-DataTypes.CallStatus", "CallStatus", []primitiveRule[CallStatus]{{invalid: func(value CallStatus) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7 && int64(value) != 8 && int64(value) != 9 && int64(value) != 10 && int64(value) != 11 && int64(value) != 12 && int64(value) != 13)
	}, description: "ENUMERATED {0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}", clause: "15", observed: func(value CallStatus) any { return int64(value) }}}, true)
}

// NumberOfForwardingCodec binds MAP-DataTypes.NumberOfForwarding.
func NumberOfForwardingCodec() ValueCodec[BERValue[NumberOfForwarding]] {
	return integerValueCodec[NumberOfForwarding]("MAP-DataTypes.NumberOfForwarding", "NumberOfForwarding", []primitiveRule[NumberOfForwarding]{{invalid: func(value NumberOfForwarding) bool { return !(int64(value) >= 1 && int64(value) <= 5) }, description: "(1..5)", clause: "37.3", observed: func(value NumberOfForwarding) any { return int64(value) }}}, false)
}

// ChannelTypeCodec binds MAP-DataTypes.ChannelType.
func ChannelTypeCodec() ValueCodec[BERValue[ChannelType]] {
	return octetValueCodec[ChannelType]("MAP-DataTypes.ChannelType", "ChannelType", []primitiveRule[ChannelType]{{invalid: func(value ChannelType) bool { return !(len(value) >= 1 && len(value) <= 10) }, description: "SIZE (1..10)", clause: "37.4", length: func(value ChannelType) int { return len(value) }}})
}

// ClassmarkInformationCodec binds MAP-DataTypes.ClassmarkInformation.
func ClassmarkInformationCodec() ValueCodec[BERValue[ClassmarkInformation]] {
	return octetValueCodec[ClassmarkInformation]("MAP-DataTypes.ClassmarkInformation", "ClassmarkInformation", []primitiveRule[ClassmarkInformation]{{invalid: func(value ClassmarkInformation) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "37.4", length: func(value ClassmarkInformation) int { return len(value) }}})
}

// HandoverPriorityCodec binds MAP-DataTypes.HandoverPriority.
func HandoverPriorityCodec() ValueCodec[BERValue[HandoverPriority]] {
	return octetValueCodec[HandoverPriority]("MAP-DataTypes.HandoverPriority", "HandoverPriority", []primitiveRule[HandoverPriority]{{invalid: func(value HandoverPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value HandoverPriority) int { return len(value) }}})
}

// HandoverTypeCodec binds MAP-DataTypes.HandoverType.
func HandoverTypeCodec() ValueCodec[BERValue[HandoverType]] {
	return integerValueCodec[HandoverType]("MAP-DataTypes.HandoverType", "HandoverType", []primitiveRule[HandoverType]{{invalid: func(value HandoverType) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "15", observed: func(value HandoverType) any { return int64(value) }}}, true)
}

// AuthenticationSetCodec binds MAP-DataTypes.AuthenticationSet.
func AuthenticationSetCodec() ValueCodec[AuthenticationSet] {
	return compositeValueCodec[AuthenticationSet, *AuthenticationSet]()
}

// RandCodec binds MAP-DataTypes.Rand.
func RandCodec() ValueCodec[BERValue[Rand]] {
	return octetValueCodec[Rand]("MAP-DataTypes.Rand", "Rand", []primitiveRule[Rand]{{invalid: func(value Rand) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "37.4", length: func(value Rand) int { return len(value) }}})
}

// SresCodec binds MAP-DataTypes.Sres.
func SresCodec() ValueCodec[BERValue[Sres]] {
	return octetValueCodec[Sres]("MAP-DataTypes.Sres", "Sres", []primitiveRule[Sres]{{invalid: func(value Sres) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "37.4", length: func(value Sres) int { return len(value) }}})
}

// KcCodec binds MAP-DataTypes.Kc.
func KcCodec() ValueCodec[BERValue[Kc]] {
	return octetValueCodec[Kc]("MAP-DataTypes.Kc", "Kc", []primitiveRule[Kc]{{invalid: func(value Kc) bool { return !(len(value) == 8) }, description: "SIZE (8)", clause: "37.4", length: func(value Kc) int { return len(value) }}})
}

// KiCodec binds MAP-DataTypes.Ki.
func KiCodec() ValueCodec[BERValue[Ki]] {
	return octetValueCodec[Ki]("MAP-DataTypes.Ki", "Ki", []primitiveRule[Ki]{{invalid: func(value Ki) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "37.4", length: func(value Ki) int { return len(value) }}})
}

// CKSNCodec binds MAP-DataTypes.CKSN.
func CKSNCodec() ValueCodec[BERValue[CKSN]] {
	return octetValueCodec[CKSN]("MAP-DataTypes.CKSN", "CKSN", []primitiveRule[CKSN]{{invalid: func(value CKSN) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value CKSN) int { return len(value) }}})
}

// CipheringModeCodec binds MAP-DataTypes.CipheringMode.
func CipheringModeCodec() ValueCodec[BERValue[CipheringMode]] {
	return integerValueCodec[CipheringMode]("MAP-DataTypes.CipheringMode", "CipheringMode", []primitiveRule[CipheringMode]{{invalid: func(value CipheringMode) bool { return (int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {1, 2}", clause: "15", observed: func(value CipheringMode) any { return int64(value) }}}, true)
}

// SMRPDACodec binds MAP-DataTypes.SM-RP-DA.
func SMRPDACodec() ValueCodec[SMRPDA] {
	return compositeValueCodec[SMRPDA, *SMRPDA]()
}

// SMRPOACodec binds MAP-DataTypes.SM-RP-OA.
func SMRPOACodec() ValueCodec[SMRPOA] {
	return compositeValueCodec[SMRPOA, *SMRPOA]()
}

// SMRPUICodec binds MAP-DataTypes.SM-RP-UI.
func SMRPUICodec() ValueCodec[BERValue[SMRPUI]] {
	return octetValueCodec[SMRPUI]("MAP-DataTypes.SM-RP-UI", "SM-RP-UI", []primitiveRule[SMRPUI]{{invalid: func(value SMRPUI) bool { return !(len(value) >= 1 && len(value) <= 200) }, description: "SIZE (1..200)", clause: "37.4", length: func(value SMRPUI) int { return len(value) }}})
}

// TraceReferenceCodec binds MAP-DataTypes.TraceReference.
func TraceReferenceCodec() ValueCodec[BERValue[TraceReference]] {
	return octetValueCodec[TraceReference]("MAP-DataTypes.TraceReference", "TraceReference", []primitiveRule[TraceReference]{{invalid: func(value TraceReference) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "37.4", length: func(value TraceReference) int { return len(value) }}})
}

// TraceTypeCodec binds MAP-DataTypes.TraceType.
func TraceTypeCodec() ValueCodec[BERValue[TraceType]] {
	return integerValueCodec[TraceType]("MAP-DataTypes.TraceType", "TraceType", []primitiveRule[TraceType]{{invalid: func(value TraceType) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "37.3", observed: func(value TraceType) any { return int64(value) }}}, false)
}

// NetworkResourceCodec binds MAP-DataTypes.NetworkResource.
func NetworkResourceCodec() ValueCodec[BERValue[NetworkResource]] {
	return integerValueCodec[NetworkResource]("MAP-DataTypes.NetworkResource", "NetworkResource", []primitiveRule[NetworkResource]{{invalid: func(value NetworkResource) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", clause: "15", observed: func(value NetworkResource) any { return int64(value) }}}, true)
}

// RequestParameterCodec binds MAP-DataTypes.RequestParameter.
func RequestParameterCodec() ValueCodec[BERValue[RequestParameter]] {
	return integerValueCodec[RequestParameter]("MAP-DataTypes.RequestParameter", "RequestParameter", []primitiveRule[RequestParameter]{{invalid: func(value RequestParameter) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4)
	}, description: "ENUMERATED {0, 1, 2, 3, 4}", clause: "15", observed: func(value RequestParameter) any { return int64(value) }}}, true)
}

// RequestParametersCodec binds MAP-DataTypes.RequestParameters.
func RequestParametersCodec() ValueCodec[RequestParameters] {
	return pointerValueCodec(UnmarshalBERRequestParameters, MarshalBERRequestParameters, MarshalDERRequestParameters)
}

// SentParameterCodec binds MAP-DataTypes.SentParameter.
func SentParameterCodec() ValueCodec[SentParameter] {
	return compositeValueCodec[SentParameter, *SentParameter]()
}

// SentParametersCodec binds MAP-DataTypes.SentParameters.
func SentParametersCodec() ValueCodec[SentParameters] {
	return pointerValueCodec(UnmarshalBERSentParameters, MarshalBERSentParameters, MarshalDERSentParameters)
}

// CmServiceTypeCodec binds MAP-DataTypes.CmServiceType.
func CmServiceTypeCodec() ValueCodec[BERValue[CmServiceType]] {
	return integerValueCodec[CmServiceType]("MAP-DataTypes.CmServiceType", "CmServiceType", []primitiveRule[CmServiceType]{{invalid: func(value CmServiceType) bool {
		return (int64(value) != 1 && int64(value) != 2 && int64(value) != 4 && int64(value) != 8 && int64(value) != 9 && int64(value) != 10)
	}, description: "ENUMERATED {1, 2, 4, 8, 9, 10}", clause: "15", observed: func(value CmServiceType) any { return int64(value) }}}, true)
}

// AccessConnectionStatusCodec binds MAP-DataTypes.AccessConnectionStatus.
func AccessConnectionStatusCodec() ValueCodec[BERValue[AccessConnectionStatus]] {
	return octetValueCodec[AccessConnectionStatus]("MAP-DataTypes.AccessConnectionStatus", "AccessConnectionStatus", []primitiveRule[AccessConnectionStatus]{{invalid: func(value AccessConnectionStatus) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "37.4", length: func(value AccessConnectionStatus) int { return len(value) }}})
}

// CUGInformationComponent1Codec binds MAP-DataTypes.CUG-Information-component1.
func CUGInformationComponent1Codec() ValueCodec[CUGInformationComponent1] {
	return compositeValueCodec[CUGInformationComponent1, *CUGInformationComponent1]()
}

// CallBarredParameterCodec binds MAP-Errors.CallBarred-parameter.
func CallBarredParameterCodec() ValueCodec[BERValue[CallBarredParameter]] {
	return integerValueCodec[CallBarredParameter]("MAP-Errors.CallBarred-parameter", "CallBarred-parameter", []primitiveRule[CallBarredParameter]{{invalid: func(value CallBarredParameter) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "15", observed: func(value CallBarredParameter) any { return int64(value) }}}, true)
}

// CUGRejectParameterCodec binds MAP-Errors.CUG-Reject-parameter.
func CUGRejectParameterCodec() ValueCodec[BERValue[CUGRejectParameter]] {
	return integerValueCodec[CUGRejectParameter]("MAP-Errors.CUG-Reject-parameter", "CUG-Reject-parameter", []primitiveRule[CUGRejectParameter]{{invalid: func(value CUGRejectParameter) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "15", observed: func(value CUGRejectParameter) any { return int64(value) }}}, true)
}

// PasswordRegistrationFailureParameterCodec binds MAP-Errors.PasswordRegistrationFailure-parameter.
func PasswordRegistrationFailureParameterCodec() ValueCodec[BERValue[PasswordRegistrationFailureParameter]] {
	return integerValueCodec[PasswordRegistrationFailureParameter]("MAP-Errors.PasswordRegistrationFailure-parameter", "PasswordRegistrationFailure-parameter", []primitiveRule[PasswordRegistrationFailureParameter]{{invalid: func(value PasswordRegistrationFailureParameter) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "15", observed: func(value PasswordRegistrationFailureParameter) any { return int64(value) }}}, true)
}

// SMDeliveryFailureParameterCodec binds MAP-Errors.SM-DeliveryFailure-parameter.
func SMDeliveryFailureParameterCodec() ValueCodec[BERValue[SMDeliveryFailureParameter]] {
	return integerValueCodec[SMDeliveryFailureParameter]("MAP-Errors.SM-DeliveryFailure-parameter", "SM-DeliveryFailure-parameter", []primitiveRule[SMDeliveryFailureParameter]{{invalid: func(value SMDeliveryFailureParameter) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "15", observed: func(value SMDeliveryFailureParameter) any { return int64(value) }}}, true)
}

// SSIncompatibilityParameterCodec binds MAP-Errors.SS-Incompatibility-parameter.
func SSIncompatibilityParameterCodec() ValueCodec[SSIncompatibilityParameter] {
	return compositeValueCodec[SSIncompatibilityParameter, *SSIncompatibilityParameter]()
}

// ActivateSSArgumentCodec binds MAP-Operations.ActivateSS-argument.
func ActivateSSArgumentCodec() ValueCodec[ActivateSSArgument] {
	return compositeValueCodec[ActivateSSArgument, *ActivateSSArgument]()
}

// ActivateTraceModeArgumentCodec binds MAP-Operations.ActivateTraceMode-argument.
func ActivateTraceModeArgumentCodec() ValueCodec[ActivateTraceModeArgument] {
	return compositeValueCodec[ActivateTraceModeArgument, *ActivateTraceModeArgument]()
}

// AlertServiceCentreArgumentCodec binds MAP-Operations.AlertServiceCentre-argument.
func AlertServiceCentreArgumentCodec() ValueCodec[AlertServiceCentreArgument] {
	return compositeValueCodec[AlertServiceCentreArgument, *AlertServiceCentreArgument]()
}

// AuthenticateArgumentCodec binds MAP-Operations.Authenticate-argument.
func AuthenticateArgumentCodec() ValueCodec[AuthenticateArgument] {
	return compositeValueCodec[AuthenticateArgument, *AuthenticateArgument]()
}

// BeginSubscriberActivityArgumentCodec binds MAP-Operations.BeginSubscriberActivity-argument.
func BeginSubscriberActivityArgumentCodec() ValueCodec[BeginSubscriberActivityArgument] {
	return compositeValueCodec[BeginSubscriberActivityArgument, *BeginSubscriberActivityArgument]()
}

// CancelLocationArgumentCodec binds MAP-Operations.CancelLocation-argument.
func CancelLocationArgumentCodec() ValueCodec[CancelLocationArgument] {
	return compositeValueCodec[CancelLocationArgument, *CancelLocationArgument]()
}

// CompleteCallArgumentCodec binds MAP-Operations.CompleteCall-argument.
func CompleteCallArgumentCodec() ValueCodec[CompleteCallArgument] {
	return compositeValueCodec[CompleteCallArgument, *CompleteCallArgument]()
}

// ConnectToFollowingAddressArgumentCodec binds MAP-Operations.ConnectToFollowingAddress-argument.
func ConnectToFollowingAddressArgumentCodec() ValueCodec[ConnectToFollowingAddressArgument] {
	return compositeValueCodec[ConnectToFollowingAddressArgument, *ConnectToFollowingAddressArgument]()
}

// DeactivateSSArgumentCodec binds MAP-Operations.DeactivateSS-argument.
func DeactivateSSArgumentCodec() ValueCodec[DeactivateSSArgument] {
	return compositeValueCodec[DeactivateSSArgument, *DeactivateSSArgument]()
}

// DeactivateTraceModeArgumentCodec binds MAP-Operations.DeactivateTraceMode-argument.
func DeactivateTraceModeArgumentCodec() ValueCodec[DeactivateTraceModeArgument] {
	return compositeValueCodec[DeactivateTraceModeArgument, *DeactivateTraceModeArgument]()
}

// DeleteSubscriberDataArgumentCodec binds MAP-Operations.DeleteSubscriberData-argument.
func DeleteSubscriberDataArgumentCodec() ValueCodec[DeleteSubscriberDataArgument] {
	return compositeValueCodec[DeleteSubscriberDataArgument, *DeleteSubscriberDataArgument]()
}

// EraseSSArgumentCodec binds MAP-Operations.EraseSS-argument.
func EraseSSArgumentCodec() ValueCodec[EraseSSArgument] {
	return compositeValueCodec[EraseSSArgument, *EraseSSArgument]()
}

// ForwardShortMessageArgumentCodec binds MAP-Operations.ForwardShortMessage-argument.
func ForwardShortMessageArgumentCodec() ValueCodec[ForwardShortMessageArgument] {
	return compositeValueCodec[ForwardShortMessageArgument, *ForwardShortMessageArgument]()
}

// ForwardSsNotificationArgumentCodec binds MAP-Operations.ForwardSsNotification-argument.
func ForwardSsNotificationArgumentCodec() ValueCodec[ForwardSsNotificationArgument] {
	return compositeValueCodec[ForwardSsNotificationArgument, *ForwardSsNotificationArgument]()
}

// InsertSubscriberDataArgumentCodec binds MAP-Operations.InsertSubscriberData-argument.
func InsertSubscriberDataArgumentCodec() ValueCodec[InsertSubscriberDataArgument] {
	return compositeValueCodec[InsertSubscriberDataArgument, *InsertSubscriberDataArgument]()
}

// InterrogateSSArgumentCodec binds MAP-Operations.InterrogateSS-argument.
func InterrogateSSArgumentCodec() ValueCodec[InterrogateSSArgument] {
	return compositeValueCodec[InterrogateSSArgument, *InterrogateSSArgument]()
}

// InterrogateSSResultCodec binds MAP-Operations.InterrogateSS-result.
func InterrogateSSResultCodec() ValueCodec[InterrogateSSResult] {
	return compositeValueCodec[InterrogateSSResult, *InterrogateSSResult]()
}

// InvokeSSArgumentCodec binds MAP-Operations.InvokeSS-argument.
func InvokeSSArgumentCodec() ValueCodec[InvokeSSArgument] {
	return compositeValueCodec[InvokeSSArgument, *InvokeSSArgument]()
}

// NoteInternalHandoverArgumentCodec binds MAP-Operations.NoteInternalHandover-argument.
func NoteInternalHandoverArgumentCodec() ValueCodec[NoteInternalHandoverArgument] {
	return compositeValueCodec[NoteInternalHandoverArgument, *NoteInternalHandoverArgument]()
}

// PageArgumentCodec binds MAP-Operations.Page-argument.
func PageArgumentCodec() ValueCodec[PageArgument] {
	return compositeValueCodec[PageArgument, *PageArgument]()
}

// PerformHandoverArgumentCodec binds MAP-Operations.PerformHandover-argument.
func PerformHandoverArgumentCodec() ValueCodec[PerformHandoverArgument] {
	return compositeValueCodec[PerformHandoverArgument, *PerformHandoverArgument]()
}

// PerformHandoverResultCodec binds MAP-Operations.PerformHandover-result.
func PerformHandoverResultCodec() ValueCodec[PerformHandoverResult] {
	return compositeValueCodec[PerformHandoverResult, *PerformHandoverResult]()
}

// PerformSubsequentHandoverArgumentCodec binds MAP-Operations.PerformSubsequentHandover-argument.
func PerformSubsequentHandoverArgumentCodec() ValueCodec[PerformSubsequentHandoverArgument] {
	return compositeValueCodec[PerformSubsequentHandoverArgument, *PerformSubsequentHandoverArgument]()
}

// ProcessAccessRequestArgumentCodec binds MAP-Operations.ProcessAccessRequest-argument.
func ProcessAccessRequestArgumentCodec() ValueCodec[ProcessAccessRequestArgument] {
	return compositeValueCodec[ProcessAccessRequestArgument, *ProcessAccessRequestArgument]()
}

// ProcessAccessRequestResultCodec binds MAP-Operations.ProcessAccessRequest-result.
func ProcessAccessRequestResultCodec() ValueCodec[ProcessAccessRequestResult] {
	return compositeValueCodec[ProcessAccessRequestResult, *ProcessAccessRequestResult]()
}

// ProvideRoamingNumberArgumentCodec binds MAP-Operations.ProvideRoamingNumber-argument.
func ProvideRoamingNumberArgumentCodec() ValueCodec[ProvideRoamingNumberArgument] {
	return compositeValueCodec[ProvideRoamingNumberArgument, *ProvideRoamingNumberArgument]()
}

// RegisterChargingInformationArgumentCodec binds MAP-Operations.RegisterChargingInformation-argument.
func RegisterChargingInformationArgumentCodec() ValueCodec[RegisterChargingInformationArgument] {
	return compositeValueCodec[RegisterChargingInformationArgument, *RegisterChargingInformationArgument]()
}

// RegisterSSArgumentCodec binds MAP-Operations.RegisterSS-argument.
func RegisterSSArgumentCodec() ValueCodec[RegisterSSArgument] {
	return compositeValueCodec[RegisterSSArgument, *RegisterSSArgument]()
}

// ResetArgumentCodec binds MAP-Operations.Reset-argument.
func ResetArgumentCodec() ValueCodec[ResetArgument] {
	return compositeValueCodec[ResetArgument, *ResetArgument]()
}

// SearchForMobileSubscriberArgumentCodec binds MAP-Operations.SearchForMobileSubscriber-argument.
func SearchForMobileSubscriberArgumentCodec() ValueCodec[SearchForMobileSubscriberArgument] {
	return compositeValueCodec[SearchForMobileSubscriberArgument, *SearchForMobileSubscriberArgument]()
}

// SendInfoForIncomingCallArgumentCodec binds MAP-Operations.SendInfoForIncomingCall-argument.
func SendInfoForIncomingCallArgumentCodec() ValueCodec[SendInfoForIncomingCallArgument] {
	return compositeValueCodec[SendInfoForIncomingCallArgument, *SendInfoForIncomingCallArgument]()
}

// SendInfoForOutgoingCallArgumentCodec binds MAP-Operations.SendInfoForOutgoingCall-argument.
func SendInfoForOutgoingCallArgumentCodec() ValueCodec[SendInfoForOutgoingCallArgument] {
	return compositeValueCodec[SendInfoForOutgoingCallArgument, *SendInfoForOutgoingCallArgument]()
}

// SendParametersArgumentCodec binds MAP-Operations.SendParameters-argument.
func SendParametersArgumentCodec() ValueCodec[SendParametersArgument] {
	return compositeValueCodec[SendParametersArgument, *SendParametersArgument]()
}

// SendRoutingInfoForSMArgumentCodec binds MAP-Operations.SendRoutingInfoForSM-argument.
func SendRoutingInfoForSMArgumentCodec() ValueCodec[SendRoutingInfoForSMArgument] {
	return compositeValueCodec[SendRoutingInfoForSMArgument, *SendRoutingInfoForSMArgument]()
}

// SendRoutingInfoForSMResultCodec binds MAP-Operations.SendRoutingInfoForSM-result.
func SendRoutingInfoForSMResultCodec() ValueCodec[SendRoutingInfoForSMResult] {
	return compositeValueCodec[SendRoutingInfoForSMResult, *SendRoutingInfoForSMResult]()
}

// SendRoutingInformationArgumentCodec binds MAP-Operations.SendRoutingInformation-argument.
func SendRoutingInformationArgumentCodec() ValueCodec[SendRoutingInformationArgument] {
	return compositeValueCodec[SendRoutingInformationArgument, *SendRoutingInformationArgument]()
}

// SendRoutingInformationResultCodec binds MAP-Operations.SendRoutingInformation-result.
func SendRoutingInformationResultCodec() ValueCodec[SendRoutingInformationResult] {
	return compositeValueCodec[SendRoutingInformationResult, *SendRoutingInformationResult]()
}

// SetCipheringModeArgumentCodec binds MAP-Operations.SetCipheringMode-argument.
func SetCipheringModeArgumentCodec() ValueCodec[SetCipheringModeArgument] {
	return compositeValueCodec[SetCipheringModeArgument, *SetCipheringModeArgument]()
}

// SetMessageWaitingDataArgumentCodec binds MAP-Operations.SetMessageWaitingData-argument.
func SetMessageWaitingDataArgumentCodec() ValueCodec[SetMessageWaitingDataArgument] {
	return compositeValueCodec[SetMessageWaitingDataArgument, *SetMessageWaitingDataArgument]()
}

// TraceSubscriberActivityArgumentCodec binds MAP-Operations.TraceSubscriberActivity-argument.
func TraceSubscriberActivityArgumentCodec() ValueCodec[TraceSubscriberActivityArgument] {
	return compositeValueCodec[TraceSubscriberActivityArgument, *TraceSubscriberActivityArgument]()
}

// UpdateLocationArgumentCodec binds MAP-Operations.UpdateLocation-argument.
func UpdateLocationArgumentCodec() ValueCodec[UpdateLocationArgument] {
	return compositeValueCodec[UpdateLocationArgument, *UpdateLocationArgument]()
}

// UpdateLocationAreaArgumentCodec binds MAP-Operations.UpdateLocationArea-argument.
func UpdateLocationAreaArgumentCodec() ValueCodec[UpdateLocationAreaArgument] {
	return compositeValueCodec[UpdateLocationAreaArgument, *UpdateLocationAreaArgument]()
}

// CancelLocationArgumentAlternative1Codec binds MAP-Operations.CancelLocation-argument-alternative1.
func CancelLocationArgumentAlternative1Codec() ValueCodec[CancelLocationArgumentAlternative1] {
	return compositeValueCodec[CancelLocationArgumentAlternative1, *CancelLocationArgumentAlternative1]()
}

// SearchForMobileSubscriberArgumentStoredLocationAreaCodec binds MAP-Operations.SearchForMobileSubscriber-argument-storedLocationArea.
func SearchForMobileSubscriberArgumentStoredLocationAreaCodec() ValueCodec[SearchForMobileSubscriberArgumentStoredLocationArea] {
	return compositeValueCodec[SearchForMobileSubscriberArgumentStoredLocationArea, *SearchForMobileSubscriberArgumentStoredLocationArea]()
}

// SendInfoForIncomingCallArgumentIncomingIdCodec binds MAP-Operations.SendInfoForIncomingCall-argument-incomingId.
func SendInfoForIncomingCallArgumentIncomingIdCodec() ValueCodec[SendInfoForIncomingCallArgumentIncomingId] {
	return compositeValueCodec[SendInfoForIncomingCallArgumentIncomingId, *SendInfoForIncomingCallArgumentIncomingId]()
}

// SendRoutingInfoForSMResultComponent1Codec binds MAP-Operations.SendRoutingInfoForSM-result-component1.
func SendRoutingInfoForSMResultComponent1Codec() ValueCodec[SendRoutingInfoForSMResultComponent1] {
	return compositeValueCodec[SendRoutingInfoForSMResultComponent1, *SendRoutingInfoForSMResultComponent1]()
}

// SendRoutingInfoForSMResultComponent1Alternative0Codec binds MAP-Operations.SendRoutingInfoForSM-result-component1-alternative0.
func SendRoutingInfoForSMResultComponent1Alternative0Codec() ValueCodec[SendRoutingInfoForSMResultComponent1Alternative0] {
	return compositeValueCodec[SendRoutingInfoForSMResultComponent1Alternative0, *SendRoutingInfoForSMResultComponent1Alternative0]()
}

// SendRoutingInformationResultRoutingInfoCodec binds MAP-Operations.SendRoutingInformation-result-routingInfo.
func SendRoutingInformationResultRoutingInfoCodec() ValueCodec[SendRoutingInformationResultRoutingInfo] {
	return compositeValueCodec[SendRoutingInformationResultRoutingInfo, *SendRoutingInformationResultRoutingInfo]()
}

// UpdateLocationAreaArgumentPreviousLocAreaIdCodec binds MAP-Operations.UpdateLocationArea-argument-previousLocAreaId.
func UpdateLocationAreaArgumentPreviousLocAreaIdCodec() ValueCodec[UpdateLocationAreaArgumentPreviousLocAreaId] {
	return compositeValueCodec[UpdateLocationAreaArgumentPreviousLocAreaId, *UpdateLocationAreaArgumentPreviousLocAreaId]()
}

// X.208 (11/1988) §§17.10, 37.4.3–37.4.4; X.209 (11/1988) §11.2.
func keepEditionBitLength(value runtime.BitString, _ []ber.NamedBitSizeSet, _ ...ber.DecodeOption) runtime.BitString {
	return value
}
func validateEditionBitLength(value runtime.BitString, _ []ber.NamedBitSizeSet, _ ...ber.EncodeOption) (runtime.BitString, error) {
	return value, ber.ValidateBitStringLength(value.Bytes, value.BitLength)
}
func encodeEditionBitString(value []byte, length int) ([]byte, error) {
	if err := ber.ValidateBitStringLength(value, length); err != nil {
		return nil, err
	}
	return ber.EncodeBitString(value, (8-length%8)%8)
}

// X.208 (11/1988) §32.3 incorporates the editions of ISO named here.
// The shared parser has already validated the syntax before these checks.
// An option prefix supplies the diagnostic path without changing the source
// assignment: the check’s leaf stays empty as in the original edition checks.
func editionGeneralizedTimeViolation(value runtime.GeneralizedTime) string {
	text := value.String()
	unit, _ := value.Accuracy()
	if unit == runtime.TimeUnitSecond && len(text) >= 14 && text[12:14] == "60" {
		return "X.208 (11/1988) §32.3; ISO 3307:1975 §2.5: seconds are 00 to 59"
	}
	if index := strings.LastIndexAny(text, "+-"); index >= 0 && len(text)-index != 5 {
		return "X.208 (11/1988) §32.3; ISO 4031:1978 §3: time differential is a sign and four digits"
	}
	return ""
}
func checkDecodedEditionTime(value runtime.GeneralizedTime, source, component string, opts []ber.DecodeOption) error {
	if constraint := editionGeneralizedTimeViolation(value); constraint != "" {
		return ber.CheckDecodedValue(ber.DecodeRule(ber.ChildDecodeOptions(opts, component), source, ber.RuleRef{Document: "CCITT X.208", Edition: "11/1988", Clause: "32.3"}), "", constraint, value.String())
	}
	return nil
}
func decodeEditionGeneralizedTime(data []byte, source, component string, opts ...ber.DecodeOption) (runtime.GeneralizedTime, int, error) {
	value, total, err := ber.DecodeGeneralizedTime(data, opts...)
	if err != nil {
		return runtime.GeneralizedTime{}, 0, err
	}
	if err = checkDecodedEditionTime(value, source, component, opts); err != nil {
		return runtime.GeneralizedTime{}, 0, err
	}
	return value, total, nil
}
func decodeImplicitEditionGeneralizedTime(constructed bool, data []byte, source, component string, opts ...ber.DecodeOption) (runtime.GeneralizedTime, error) {
	value, err := ber.DecodeImplicitGeneralizedTimeValue(constructed, data, opts...)
	if err != nil {
		return runtime.GeneralizedTime{}, err
	}
	if err = checkDecodedEditionTime(value, source, component, opts); err != nil {
		return runtime.GeneralizedTime{}, err
	}
	return value, nil
}
func checkEncodedEditionTime(value runtime.GeneralizedTime, source, component string) error {
	if constraint := editionGeneralizedTimeViolation(value); constraint != "" {
		return ber.CheckEncodedValue(ber.EncodeRule(ber.ChildEncodeOptions(nil, component), source, ber.RuleRef{Document: "CCITT X.208", Edition: "11/1988", Clause: "32.3"}), "", constraint, value.String())
	}
	return nil
}
func encodeEditionGeneralizedTime(value runtime.GeneralizedTime, source, component string) ([]byte, error) {
	if err := checkEncodedEditionTime(value, source, component); err != nil {
		return nil, err
	}
	return ber.EncodeGeneralizedTime(value)
}
func encodeEditionGeneralizedTimeDER(value runtime.GeneralizedTime, source, component string) ([]byte, error) {
	if err := checkEncodedEditionTime(value, source, component); err != nil {
		return nil, err
	}
	return ber.EncodeGeneralizedTimeDER(value)
}
