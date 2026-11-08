// Code generated from ASN.1. DO NOT EDIT.

package gsm0902_v4_19_1

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
// exhausted limits match ber.ErrResourceLimit. MAP source roots apply GSM 09.02
// V4.19.1 §14.1.1; other roots use X.690 (02/2021) §8.
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
// parts. Fresh MAP forms follow GSM 09.02 V4.19.1 §14.1.1; generic BER follows
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
	case "MobileDomainDefinitions":
		return false
	}
	return true
}
func trackMAPSource(opts []ber.DecodeOption, source string) []ber.DecodeOption {
	if strings.HasPrefix(source, "MAP-") {
		return ber.TrackGSM0902Form(opts)
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
// scalar text and screens code-extension controls before any TLV exists. Only invalid
// text needs diagnostic metadata; the encoded TLV is never parsed again.
func encodeUTF8String(value string, opts []ber.EncodeOption, component string, index int, source string) ([]byte, error) {
	if utf8.ValidString(value) && !strings.ContainsAny(value, "\x1b\x0e\x0f\u008e\u008f") {
		// X.680 (02/2021) §§41.6,41.16; ISO/IEC 10646:2003 §§7 a),8 exclude noncharacters.
		for _, r := range value {
			if r >= 0xfdd0 && r <= 0xfdef || r&0xffff >= 0xfffe {
				return encodeInvalidUTF8String(value, opts, component, index, source)
			}
		}
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

// X.690 (02/2021) §8.23.5.3/Table 3: ordinary IA5 text needs no
// diagnostic options or source metadata. Only a possible escape uses the
// runtime's complete-sequence recognizer and tolerant report policy.
func checkIA5Controls(value string, opts []ber.EncodeOption, component, source string) error {
	if !strings.ContainsRune(value, 0x1b) {
		return nil
	}
	rule := ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.5.3"}
	return ber.CheckEncodedValue(ber.EncodeRule(opts, source, rule), component, "IA5String escape sequences", value)
}

// CommonComponentIdCodec binds MobileDomainDefinitions.CommonComponentId.
func CommonComponentIdCodec() ValueCodec[BERValue[CommonComponentId]] {
	return integerValueCodec[CommonComponentId]("MobileDomainDefinitions.CommonComponentId", "CommonComponentId", []primitiveRule[CommonComponentId]{{invalid: func(value CommonComponentId) bool { return !(int64(value) >= 0 && int64(value) <= 9) }, description: "(0..9)", clause: "51.4", observed: func(value CommonComponentId) any { return int64(value) }}}, false)
}

// BearerServiceCodeCodec binds MAP-BS-Code.BearerServiceCode.
func BearerServiceCodeCodec() ValueCodec[BERValue[BearerServiceCode]] {
	return octetValueCodec[BearerServiceCode]("MAP-BS-Code.BearerServiceCode", "BearerServiceCode", []primitiveRule[BearerServiceCode]{{invalid: func(value BearerServiceCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value BearerServiceCode) int { return len(value) }}})
}

// TeleserviceCodeCodec binds MAP-TS-Code.TeleserviceCode.
func TeleserviceCodeCodec() ValueCodec[BERValue[TeleserviceCode]] {
	return octetValueCodec[TeleserviceCode]("MAP-TS-Code.TeleserviceCode", "TeleserviceCode", []primitiveRule[TeleserviceCode]{{invalid: func(value TeleserviceCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value TeleserviceCode) int { return len(value) }}})
}

// TBCDSTRINGCodec binds MAP-CommonDataTypes.TBCD-STRING.
func TBCDSTRINGCodec() ValueCodec[BERValue[TBCDSTRING]] {
	return octetValueCodec[TBCDSTRING]("MAP-CommonDataTypes.TBCD-STRING", "TBCD-STRING", nil)
}

// AddressStringCodec binds MAP-CommonDataTypes.AddressString.
func AddressStringCodec() ValueCodec[BERValue[AddressString]] {
	return octetValueCodec[AddressString]("MAP-CommonDataTypes.AddressString", "AddressString", []primitiveRule[AddressString]{{invalid: func(value AddressString) bool { return !(len(value) >= 1 && len(value) <= 20) }, description: "SIZE (1..20)", clause: "51.5", length: func(value AddressString) int { return len(value) }}})
}

// ISDNAddressStringCodec binds MAP-CommonDataTypes.ISDN-AddressString.
func ISDNAddressStringCodec() ValueCodec[BERValue[ISDNAddressString]] {
	return pointerValueCodec(UnmarshalBERISDNAddressString, MarshalBERISDNAddressString, MarshalDERISDNAddressString)
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

// IMSICodec binds MAP-CommonDataTypes.IMSI.
func IMSICodec() ValueCodec[BERValue[IMSI]] {
	return pointerValueCodec(UnmarshalBERIMSI, MarshalBERIMSI, MarshalDERIMSI)
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

// LocationInfoCodec binds MAP-CommonDataTypes.LocationInfo.
func LocationInfoCodec() ValueCodec[LocationInfo] {
	return compositeValueCodec[LocationInfo, *LocationInfo]()
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

// CategoryCodec binds MAP-CommonDataTypes.Category.
func CategoryCodec() ValueCodec[BERValue[Category]] {
	return octetValueCodec[Category]("MAP-CommonDataTypes.Category", "Category", []primitiveRule[Category]{{invalid: func(value Category) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value Category) int { return len(value) }}})
}

// BearerServiceListCodec binds MAP-CommonDataTypes.BearerServiceList.
func BearerServiceListCodec() ValueCodec[BearerServiceList] {
	return pointerValueCodec(UnmarshalBERBearerServiceList, MarshalBERBearerServiceList, MarshalDERBearerServiceList)
}

// TeleserviceListCodec binds MAP-CommonDataTypes.TeleserviceList.
func TeleserviceListCodec() ValueCodec[TeleserviceList] {
	return pointerValueCodec(UnmarshalBERTeleserviceList, MarshalBERTeleserviceList, MarshalDERTeleserviceList)
}

// BasicServiceCodeCodec binds MAP-CommonDataTypes.BasicServiceCode.
func BasicServiceCodeCodec() ValueCodec[BasicServiceCode] {
	return compositeValueCodec[BasicServiceCode, *BasicServiceCode]()
}

// BasicServiceListCodec binds MAP-CommonDataTypes.BasicServiceList.
func BasicServiceListCodec() ValueCodec[BasicServiceList] {
	return pointerValueCodec(UnmarshalBERBasicServiceList, MarshalBERBasicServiceList, MarshalDERBasicServiceList)
}

// BasicServiceGroupListCodec binds MAP-CommonDataTypes.BasicServiceGroupList.
func BasicServiceGroupListCodec() ValueCodec[BasicServiceGroupList] {
	return pointerValueCodec(UnmarshalBERBasicServiceGroupList, MarshalBERBasicServiceGroupList, MarshalDERBasicServiceGroupList)
}

// SSCodeCodec binds MAP-SS-Code.SS-Code.
func SSCodeCodec() ValueCodec[BERValue[SSCode]] {
	return octetValueCodec[SSCode]("MAP-SS-Code.SS-Code", "SS-Code", []primitiveRule[SSCode]{{invalid: func(value SSCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value SSCode) int { return len(value) }}})
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
	return octetValueCodec[SSStatus]("MAP-SS-DataTypes.SS-Status", "SS-Status", []primitiveRule[SSStatus]{{invalid: func(value SSStatus) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value SSStatus) int { return len(value) }}})
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

// CUGInfoCodec binds MAP-SS-DataTypes.CUG-Info.
func CUGInfoCodec() ValueCodec[CUGInfo] {
	return compositeValueCodec[CUGInfo, *CUGInfo]()
}

// CUGSubscriptionListCodec binds MAP-SS-DataTypes.CUG-SubscriptionList.
func CUGSubscriptionListCodec() ValueCodec[CUGSubscriptionList] {
	return pointerValueCodec(UnmarshalBERCUGSubscriptionList, MarshalBERCUGSubscriptionList, MarshalDERCUGSubscriptionList)
}

// CUGSubscriptionCodec binds MAP-SS-DataTypes.CUG-Subscription.
func CUGSubscriptionCodec() ValueCodec[CUGSubscription] {
	return compositeValueCodec[CUGSubscription, *CUGSubscription]()
}

// CUGIndexCodec binds MAP-SS-DataTypes.CUG-Index.
func CUGIndexCodec() ValueCodec[BERValue[CUGIndex]] {
	return integerValueCodec[CUGIndex]("MAP-SS-DataTypes.CUG-Index", "CUG-Index", []primitiveRule[CUGIndex]{{invalid: func(value CUGIndex) bool { return !(int64(value) >= 0 && int64(value) <= 32767) }, description: "(0..32767)", clause: "51.4", observed: func(value CUGIndex) any { return int64(value) }}}, false)
}

// CUGInterlockCodec binds MAP-SS-DataTypes.CUG-Interlock.
func CUGInterlockCodec() ValueCodec[BERValue[CUGInterlock]] {
	return octetValueCodec[CUGInterlock]("MAP-SS-DataTypes.CUG-Interlock", "CUG-Interlock", []primitiveRule[CUGInterlock]{{invalid: func(value CUGInterlock) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value CUGInterlock) int { return len(value) }}})
}

// IntraCUGOptionsCodec binds MAP-SS-DataTypes.IntraCUG-Options.
func IntraCUGOptionsCodec() ValueCodec[BERValue[IntraCUGOptions]] {
	return integerValueCodec[IntraCUGOptions]("MAP-SS-DataTypes.IntraCUG-Options", "IntraCUG-Options", []primitiveRule[IntraCUGOptions]{{invalid: func(value IntraCUGOptions) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value IntraCUGOptions) any { return int64(value) }}}, true)
}

// CUGFeatureListCodec binds MAP-SS-DataTypes.CUG-FeatureList.
func CUGFeatureListCodec() ValueCodec[CUGFeatureList] {
	return pointerValueCodec(UnmarshalBERCUGFeatureList, MarshalBERCUGFeatureList, MarshalDERCUGFeatureList)
}

// CUGFeatureCodec binds MAP-SS-DataTypes.CUG-Feature.
func CUGFeatureCodec() ValueCodec[CUGFeature] {
	return compositeValueCodec[CUGFeature, *CUGFeature]()
}

// InterCUGRestrictionsCodec binds MAP-SS-DataTypes.InterCUG-Restrictions.
func InterCUGRestrictionsCodec() ValueCodec[BERValue[InterCUGRestrictions]] {
	return octetValueCodec[InterCUGRestrictions]("MAP-SS-DataTypes.InterCUG-Restrictions", "InterCUG-Restrictions", []primitiveRule[InterCUGRestrictions]{{invalid: func(value InterCUGRestrictions) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value InterCUGRestrictions) int { return len(value) }}})
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

// CliRestrictionInfoCodec binds MAP-SS-DataTypes.Cli-RestrictionInfo.
func CliRestrictionInfoCodec() ValueCodec[CliRestrictionInfo] {
	return compositeValueCodec[CliRestrictionInfo, *CliRestrictionInfo]()
}

// InterrogateSSResCodec binds MAP-SS-DataTypes.InterrogateSS-Res.
func InterrogateSSResCodec() ValueCodec[InterrogateSSRes] {
	return compositeValueCodec[InterrogateSSRes, *InterrogateSSRes]()
}

// SSUserDataCodec binds MAP-SS-DataTypes.SS-UserData.
func SSUserDataCodec() ValueCodec[BERValue[SSUserData]] {
	return pointerValueCodec(UnmarshalBERSSUserData, MarshalBERSSUserData, MarshalDERSSUserData)
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
	return integerValueCodec[GuidanceInfo]("MAP-SS-DataTypes.GuidanceInfo", "GuidanceInfo", []primitiveRule[GuidanceInfo]{{invalid: func(value GuidanceInfo) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4)
	}, description: "ENUMERATED {0, 1, 2, 3, 4}", clause: "20", observed: func(value GuidanceInfo) any { return int64(value) }}}, true)
}

// BeginSubscriberActivityArgCodec binds MAP-SS-DataTypes.BeginSubscriberActivityArg.
func BeginSubscriberActivityArgCodec() ValueCodec[BeginSubscriberActivityArg] {
	return compositeValueCodec[BeginSubscriberActivityArg, *BeginSubscriberActivityArg]()
}

// SSListCodec binds MAP-SS-DataTypes.SS-List.
func SSListCodec() ValueCodec[SSList] {
	return pointerValueCodec(UnmarshalBERSSList, MarshalBERSSList, MarshalDERSSList)
}

// SSInfoListCodec binds MAP-SS-DataTypes.SS-InfoList.
func SSInfoListCodec() ValueCodec[SSInfoList] {
	return pointerValueCodec(UnmarshalBERSSInfoList, MarshalBERSSInfoList, MarshalDERSSInfoList)
}

// ForwardingDataCodec binds MAP-SS-DataTypes.ForwardingData.
func ForwardingDataCodec() ValueCodec[ForwardingData] {
	return compositeValueCodec[ForwardingData, *ForwardingData]()
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

// SendRoutingInfoResCodec binds MAP-CH-DataTypes.SendRoutingInfoRes.
func SendRoutingInfoResCodec() ValueCodec[SendRoutingInfoRes] {
	return compositeValueCodec[SendRoutingInfoRes, *SendRoutingInfoRes]()
}

// RoutingInfoCodec binds MAP-CH-DataTypes.RoutingInfo.
func RoutingInfoCodec() ValueCodec[RoutingInfo] {
	return compositeValueCodec[RoutingInfo, *RoutingInfo]()
}

// ProvideRoamingNumberArgCodec binds MAP-CH-DataTypes.ProvideRoamingNumberArg.
func ProvideRoamingNumberArgCodec() ValueCodec[ProvideRoamingNumberArg] {
	return compositeValueCodec[ProvideRoamingNumberArg, *ProvideRoamingNumberArg]()
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

// RoamingNotAllowedCauseCodec binds MAP-ER-DataTypes.RoamingNotAllowedCause.
func RoamingNotAllowedCauseCodec() ValueCodec[BERValue[RoamingNotAllowedCause]] {
	return integerValueCodec[RoamingNotAllowedCause]("MAP-ER-DataTypes.RoamingNotAllowedCause", "RoamingNotAllowedCause", []primitiveRule[RoamingNotAllowedCause]{{invalid: func(value RoamingNotAllowedCause) bool { return (int64(value) != 0 && int64(value) != 3) }, description: "ENUMERATED {0, 3}", clause: "20", observed: func(value RoamingNotAllowedCause) any { return int64(value) }}}, true)
}

// CallBarringCauseCodec binds MAP-ER-DataTypes.CallBarringCause.
func CallBarringCauseCodec() ValueCodec[BERValue[CallBarringCause]] {
	return integerValueCodec[CallBarringCause]("MAP-ER-DataTypes.CallBarringCause", "CallBarringCause", []primitiveRule[CallBarringCause]{{invalid: func(value CallBarringCause) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value CallBarringCause) any { return int64(value) }}}, true)
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
	return integerValueCodec[PWRegistrationFailureCause]("MAP-ER-DataTypes.PW-RegistrationFailureCause", "PW-RegistrationFailureCause", []primitiveRule[PWRegistrationFailureCause]{{invalid: func(value PWRegistrationFailureCause) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value PWRegistrationFailureCause) any { return int64(value) }}}, true)
}

// SMDeliveryFailureCauseCodec binds MAP-ER-DataTypes.SM-DeliveryFailureCause.
func SMDeliveryFailureCauseCodec() ValueCodec[SMDeliveryFailureCause] {
	return compositeValueCodec[SMDeliveryFailureCause, *SMDeliveryFailureCause]()
}

// SMEnumeratedDeliveryFailureCauseCodec binds MAP-ER-DataTypes.SM-EnumeratedDeliveryFailureCause.
func SMEnumeratedDeliveryFailureCauseCodec() ValueCodec[BERValue[SMEnumeratedDeliveryFailureCause]] {
	return integerValueCodec[SMEnumeratedDeliveryFailureCause]("MAP-ER-DataTypes.SM-EnumeratedDeliveryFailureCause", "SM-EnumeratedDeliveryFailureCause", []primitiveRule[SMEnumeratedDeliveryFailureCause]{{invalid: func(value SMEnumeratedDeliveryFailureCause) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value SMEnumeratedDeliveryFailureCause) any { return int64(value) }}}, true)
}

// SMDeliveryFailureCauseWithDiagnosticCodec binds MAP-ER-DataTypes.SM-DeliveryFailureCauseWithDiagnostic.
func SMDeliveryFailureCauseWithDiagnosticCodec() ValueCodec[SMDeliveryFailureCauseWithDiagnostic] {
	return compositeValueCodec[SMDeliveryFailureCauseWithDiagnostic, *SMDeliveryFailureCauseWithDiagnostic]()
}

// UpdateLocationArgCodec binds MAP-MS-DataTypes.UpdateLocationArg.
func UpdateLocationArgCodec() ValueCodec[UpdateLocationArg] {
	return compositeValueCodec[UpdateLocationArg, *UpdateLocationArg]()
}

// UpdateLocationResCodec binds MAP-MS-DataTypes.UpdateLocationRes.
func UpdateLocationResCodec() ValueCodec[UpdateLocationRes] {
	return compositeValueCodec[UpdateLocationRes, *UpdateLocationRes]()
}

// ExtensibleUpdateLocationResCodec binds MAP-MS-DataTypes.ExtensibleUpdateLocationRes.
func ExtensibleUpdateLocationResCodec() ValueCodec[ExtensibleUpdateLocationRes] {
	return compositeValueCodec[ExtensibleUpdateLocationRes, *ExtensibleUpdateLocationRes]()
}

// CancelLocationArgCodec binds MAP-MS-DataTypes.CancelLocationArg.
func CancelLocationArgCodec() ValueCodec[CancelLocationArg] {
	return compositeValueCodec[CancelLocationArg, *CancelLocationArg]()
}

// PurgeMSArgCodec binds MAP-MS-DataTypes.PurgeMS-Arg.
func PurgeMSArgCodec() ValueCodec[PurgeMSArg] {
	return compositeValueCodec[PurgeMSArg, *PurgeMSArg]()
}

// IMSIWithLMSICodec binds MAP-MS-DataTypes.IMSI-WithLMSI.
func IMSIWithLMSICodec() ValueCodec[IMSIWithLMSI] {
	return compositeValueCodec[IMSIWithLMSI, *IMSIWithLMSI]()
}

// SendIdentificationResCodec binds MAP-MS-DataTypes.SendIdentificationRes.
func SendIdentificationResCodec() ValueCodec[SendIdentificationRes] {
	return compositeValueCodec[SendIdentificationRes, *SendIdentificationRes]()
}

// AuthenticationSetListCodec binds MAP-MS-DataTypes.AuthenticationSetList.
func AuthenticationSetListCodec() ValueCodec[AuthenticationSetList] {
	return pointerValueCodec(UnmarshalBERAuthenticationSetList, MarshalBERAuthenticationSetList, MarshalDERAuthenticationSetList)
}

// AuthenticationSetCodec binds MAP-MS-DataTypes.AuthenticationSet.
func AuthenticationSetCodec() ValueCodec[AuthenticationSet] {
	return compositeValueCodec[AuthenticationSet, *AuthenticationSet]()
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

// PrepareHOArgCodec binds MAP-MS-DataTypes.PrepareHO-Arg.
func PrepareHOArgCodec() ValueCodec[PrepareHOArg] {
	return compositeValueCodec[PrepareHOArg, *PrepareHOArg]()
}

// PerformHOArgCodec binds MAP-MS-DataTypes.PerformHO-Arg.
func PerformHOArgCodec() ValueCodec[PerformHOArg] {
	return compositeValueCodec[PerformHOArg, *PerformHOArg]()
}

// ChannelTypeCodec binds MAP-MS-DataTypes.ChannelType.
func ChannelTypeCodec() ValueCodec[BERValue[ChannelType]] {
	return octetValueCodec[ChannelType]("MAP-MS-DataTypes.ChannelType", "ChannelType", []primitiveRule[ChannelType]{{invalid: func(value ChannelType) bool { return !(len(value) >= 1 && len(value) <= 10) }, description: "SIZE (1..10)", clause: "51.5", length: func(value ChannelType) int { return len(value) }}})
}

// ClassmarkInfoCodec binds MAP-MS-DataTypes.ClassmarkInfo.
func ClassmarkInfoCodec() ValueCodec[BERValue[ClassmarkInfo]] {
	return octetValueCodec[ClassmarkInfo]("MAP-MS-DataTypes.ClassmarkInfo", "ClassmarkInfo", []primitiveRule[ClassmarkInfo]{{invalid: func(value ClassmarkInfo) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value ClassmarkInfo) int { return len(value) }}})
}

// HandoverPriorityCodec binds MAP-MS-DataTypes.HandoverPriority.
func HandoverPriorityCodec() ValueCodec[BERValue[HandoverPriority]] {
	return octetValueCodec[HandoverPriority]("MAP-MS-DataTypes.HandoverPriority", "HandoverPriority", []primitiveRule[HandoverPriority]{{invalid: func(value HandoverPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value HandoverPriority) int { return len(value) }}})
}

// PrepareHOResCodec binds MAP-MS-DataTypes.PrepareHO-Res.
func PrepareHOResCodec() ValueCodec[PrepareHORes] {
	return compositeValueCodec[PrepareHORes, *PrepareHORes]()
}

// PerformHOResCodec binds MAP-MS-DataTypes.PerformHO-Res.
func PerformHOResCodec() ValueCodec[PerformHORes] {
	return compositeValueCodec[PerformHORes, *PerformHORes]()
}

// PrepareSubsequentHOArgCodec binds MAP-MS-DataTypes.PrepareSubsequentHO-Arg.
func PrepareSubsequentHOArgCodec() ValueCodec[PrepareSubsequentHOArg] {
	return compositeValueCodec[PrepareSubsequentHOArg, *PrepareSubsequentHOArg]()
}

// PerformSubsequentHOArgCodec binds MAP-MS-DataTypes.PerformSubsequentHO-Arg.
func PerformSubsequentHOArgCodec() ValueCodec[PerformSubsequentHOArg] {
	return compositeValueCodec[PerformSubsequentHOArg, *PerformSubsequentHOArg]()
}

// SendAuthenticationInfoArgCodec binds MAP-MS-DataTypes.SendAuthenticationInfoArg.
func SendAuthenticationInfoArgCodec() ValueCodec[BERValue[SendAuthenticationInfoArg]] {
	return pointerValueCodec(UnmarshalBERSendAuthenticationInfoArg, MarshalBERSendAuthenticationInfoArg, MarshalDERSendAuthenticationInfoArg)
}

// SendAuthenticationInfoResCodec binds MAP-MS-DataTypes.SendAuthenticationInfoRes.
func SendAuthenticationInfoResCodec() ValueCodec[SendAuthenticationInfoRes] {
	return pointerValueCodec(UnmarshalBERSendAuthenticationInfoRes, MarshalBERSendAuthenticationInfoRes, MarshalDERSendAuthenticationInfoRes)
}

// KiCodec binds MAP-MS-DataTypes.Ki.
func KiCodec() ValueCodec[BERValue[Ki]] {
	return octetValueCodec[Ki]("MAP-MS-DataTypes.Ki", "Ki", []primitiveRule[Ki]{{invalid: func(value Ki) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value Ki) int { return len(value) }}})
}

// EquipmentStatusCodec binds MAP-MS-DataTypes.EquipmentStatus.
func EquipmentStatusCodec() ValueCodec[BERValue[EquipmentStatus]] {
	return integerValueCodec[EquipmentStatus]("MAP-MS-DataTypes.EquipmentStatus", "EquipmentStatus", []primitiveRule[EquipmentStatus]{{invalid: func(value EquipmentStatus) bool { return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2) }, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value EquipmentStatus) any { return int64(value) }}}, true)
}

// SendParametersArgCodec binds MAP-MS-DataTypes.SendParametersArg.
func SendParametersArgCodec() ValueCodec[SendParametersArg] {
	return compositeValueCodec[SendParametersArg, *SendParametersArg]()
}

// RequestParameterListCodec binds MAP-MS-DataTypes.RequestParameterList.
func RequestParameterListCodec() ValueCodec[RequestParameterList] {
	return pointerValueCodec(UnmarshalBERRequestParameterList, MarshalBERRequestParameterList, MarshalDERRequestParameterList)
}

// RequestParameterCodec binds MAP-MS-DataTypes.RequestParameter.
func RequestParameterCodec() ValueCodec[BERValue[RequestParameter]] {
	return integerValueCodec[RequestParameter]("MAP-MS-DataTypes.RequestParameter", "RequestParameter", []primitiveRule[RequestParameter]{{invalid: func(value RequestParameter) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 4)
	}, description: "ENUMERATED {0, 1, 2, 4}", clause: "20", observed: func(value RequestParameter) any { return int64(value) }}}, true)
}

// SentParameterListCodec binds MAP-MS-DataTypes.SentParameterList.
func SentParameterListCodec() ValueCodec[SentParameterList] {
	return pointerValueCodec(UnmarshalBERSentParameterList, MarshalBERSentParameterList, MarshalDERSentParameterList)
}

// SentParameterCodec binds MAP-MS-DataTypes.SentParameter.
func SentParameterCodec() ValueCodec[SentParameter] {
	return compositeValueCodec[SentParameter, *SentParameter]()
}

// InsertSubscriberDataArgCodec binds MAP-MS-DataTypes.InsertSubscriberDataArg.
func InsertSubscriberDataArgCodec() ValueCodec[InsertSubscriberDataArg] {
	return compositeValueCodec[InsertSubscriberDataArg, *InsertSubscriberDataArg]()
}

// SubscriberDataCodec binds MAP-MS-DataTypes.SubscriberData.
func SubscriberDataCodec() ValueCodec[SubscriberData] {
	return compositeValueCodec[SubscriberData, *SubscriberData]()
}

// SubscriberStatusCodec binds MAP-MS-DataTypes.SubscriberStatus.
func SubscriberStatusCodec() ValueCodec[BERValue[SubscriberStatus]] {
	return integerValueCodec[SubscriberStatus]("MAP-MS-DataTypes.SubscriberStatus", "SubscriberStatus", []primitiveRule[SubscriberStatus]{{invalid: func(value SubscriberStatus) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value SubscriberStatus) any { return int64(value) }}}, true)
}

// ODBDataCodec binds MAP-MS-DataTypes.ODB-Data.
func ODBDataCodec() ValueCodec[ODBData] {
	return compositeValueCodec[ODBData, *ODBData]()
}

// ODBGeneralDataCodec binds MAP-MS-DataTypes.ODB-GeneralData.
func ODBGeneralDataCodec() ValueCodec[BERValue[ODBGeneralData]] {
	return bitValueCodec("MAP-MS-DataTypes.ODB-GeneralData", "ODB-GeneralData", []primitiveRule[ODBGeneralData]{{invalid: func(value ODBGeneralData) bool { return !(value.BitLength == 6) }, description: "SIZE (6)", clause: "51.5", length: func(value ODBGeneralData) int { return value.BitLength }, encodedLength: func(value ODBGeneralData) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}})
}

// ODBHPLMNDataCodec binds MAP-MS-DataTypes.ODB-HPLMN-Data.
func ODBHPLMNDataCodec() ValueCodec[BERValue[ODBHPLMNData]] {
	return bitValueCodec("MAP-MS-DataTypes.ODB-HPLMN-Data", "ODB-HPLMN-Data", []primitiveRule[ODBHPLMNData]{{invalid: func(value ODBHPLMNData) bool { return !(value.BitLength == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value ODBHPLMNData) int { return value.BitLength }, encodedLength: func(value ODBHPLMNData) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 4}}})
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

// DeleteSubscriberDataResCodec binds MAP-MS-DataTypes.DeleteSubscriberDataRes.
func DeleteSubscriberDataResCodec() ValueCodec[DeleteSubscriberDataRes] {
	return compositeValueCodec[DeleteSubscriberDataRes, *DeleteSubscriberDataRes]()
}

// ResetArgCodec binds MAP-MS-DataTypes.ResetArg.
func ResetArgCodec() ValueCodec[ResetArg] {
	return compositeValueCodec[ResetArg, *ResetArg]()
}

// RestoreDataArgCodec binds MAP-MS-DataTypes.RestoreDataArg.
func RestoreDataArgCodec() ValueCodec[RestoreDataArg] {
	return compositeValueCodec[RestoreDataArg, *RestoreDataArg]()
}

// RestoreDataResCodec binds MAP-MS-DataTypes.RestoreDataRes.
func RestoreDataResCodec() ValueCodec[RestoreDataRes] {
	return compositeValueCodec[RestoreDataRes, *RestoreDataRes]()
}

// ActivateTraceModeArgCodec binds MAP-OM-DataTypes.ActivateTraceModeArg.
func ActivateTraceModeArgCodec() ValueCodec[ActivateTraceModeArg] {
	return compositeValueCodec[ActivateTraceModeArg, *ActivateTraceModeArg]()
}

// TraceReferenceCodec binds MAP-OM-DataTypes.TraceReference.
func TraceReferenceCodec() ValueCodec[BERValue[TraceReference]] {
	return octetValueCodec[TraceReference]("MAP-OM-DataTypes.TraceReference", "TraceReference", []primitiveRule[TraceReference]{{invalid: func(value TraceReference) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value TraceReference) int { return len(value) }}})
}

// TraceTypeCodec binds MAP-OM-DataTypes.TraceType.
func TraceTypeCodec() ValueCodec[BERValue[TraceType]] {
	return integerValueCodec[TraceType]("MAP-OM-DataTypes.TraceType", "TraceType", []primitiveRule[TraceType]{{invalid: func(value TraceType) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "51.4", observed: func(value TraceType) any { return int64(value) }}}, false)
}

// DeactivateTraceModeArgCodec binds MAP-OM-DataTypes.DeactivateTraceModeArg.
func DeactivateTraceModeArgCodec() ValueCodec[DeactivateTraceModeArg] {
	return compositeValueCodec[DeactivateTraceModeArg, *DeactivateTraceModeArg]()
}

// TraceSubscriberActivityArgCodec binds MAP-OM-DataTypes.TraceSubscriberActivityArg.
func TraceSubscriberActivityArgCodec() ValueCodec[TraceSubscriberActivityArg] {
	return compositeValueCodec[TraceSubscriberActivityArg, *TraceSubscriberActivityArg]()
}

// CallReferenceCodec binds MAP-OM-DataTypes.CallReference.
func CallReferenceCodec() ValueCodec[BERValue[CallReference]] {
	return octetValueCodec[CallReference]("MAP-OM-DataTypes.CallReference", "CallReference", []primitiveRule[CallReference]{{invalid: func(value CallReference) bool { return !(len(value) >= 1 && len(value) <= 3) }, description: "SIZE (1..3)", clause: "51.5", length: func(value CallReference) int { return len(value) }}})
}

// NoteInternalHOArgCodec binds MAP-OM-DataTypes.NoteInternalHO-Arg.
func NoteInternalHOArgCodec() ValueCodec[NoteInternalHOArg] {
	return compositeValueCodec[NoteInternalHOArg, *NoteInternalHOArg]()
}

// HandoverTypeCodec binds MAP-OM-DataTypes.HandoverType.
func HandoverTypeCodec() ValueCodec[BERValue[HandoverType]] {
	return integerValueCodec[HandoverType]("MAP-OM-DataTypes.HandoverType", "HandoverType", []primitiveRule[HandoverType]{{invalid: func(value HandoverType) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value HandoverType) any { return int64(value) }}}, true)
}

// RoutingInfoForSMArgCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Arg.
func RoutingInfoForSMArgCodec() ValueCodec[RoutingInfoForSMArg] {
	return compositeValueCodec[RoutingInfoForSMArg, *RoutingInfoForSMArg]()
}

// RoutingInfoForSMResCodec binds MAP-SM-DataTypes.RoutingInfoForSM-Res.
func RoutingInfoForSMResCodec() ValueCodec[RoutingInfoForSMRes] {
	return compositeValueCodec[RoutingInfoForSMRes, *RoutingInfoForSMRes]()
}

// LocationInfoWithLMSICodec binds MAP-SM-DataTypes.LocationInfoWithLMSI.
func LocationInfoWithLMSICodec() ValueCodec[LocationInfoWithLMSI] {
	return compositeValueCodec[LocationInfoWithLMSI, *LocationInfoWithLMSI]()
}

// ForwardSMArgCodec binds MAP-SM-DataTypes.ForwardSM-Arg.
func ForwardSMArgCodec() ValueCodec[ForwardSMArg] {
	return compositeValueCodec[ForwardSMArg, *ForwardSMArg]()
}

// SMRPDACodec binds MAP-SM-DataTypes.SM-RP-DA.
func SMRPDACodec() ValueCodec[SMRPDA] {
	return compositeValueCodec[SMRPDA, *SMRPDA]()
}

// SMRPOACodec binds MAP-SM-DataTypes.SM-RP-OA.
func SMRPOACodec() ValueCodec[SMRPOA] {
	return compositeValueCodec[SMRPOA, *SMRPOA]()
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

// AlertServiceCentreArgCodec binds MAP-SM-DataTypes.AlertServiceCentreArg.
func AlertServiceCentreArgCodec() ValueCodec[AlertServiceCentreArg] {
	return compositeValueCodec[AlertServiceCentreArg, *AlertServiceCentreArg]()
}

// InformServiceCentreArgCodec binds MAP-SM-DataTypes.InformServiceCentreArg.
func InformServiceCentreArgCodec() ValueCodec[InformServiceCentreArg] {
	return compositeValueCodec[InformServiceCentreArg, *InformServiceCentreArg]()
}

// MWStatusCodec binds MAP-SM-DataTypes.MW-Status.
func MWStatusCodec() ValueCodec[BERValue[MWStatus]] {
	return bitValueCodec("MAP-SM-DataTypes.MW-Status", "MW-Status", []primitiveRule[MWStatus]{{invalid: func(value MWStatus) bool { return !(value.BitLength == 6) }, description: "SIZE (6)", clause: "51.5", length: func(value MWStatus) int { return value.BitLength }, encodedLength: func(value MWStatus) int { return namedBitObservedLength(value) }}}, true, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}})
}

// ReadyForSMArgCodec binds MAP-SM-DataTypes.ReadyForSM-Arg.
func ReadyForSMArgCodec() ValueCodec[ReadyForSMArg] {
	return compositeValueCodec[ReadyForSMArg, *ReadyForSMArg]()
}

// AlertReasonCodec binds MAP-SM-DataTypes.AlertReason.
func AlertReasonCodec() ValueCodec[BERValue[AlertReason]] {
	return integerValueCodec[AlertReason]("MAP-SM-DataTypes.AlertReason", "AlertReason", []primitiveRule[AlertReason]{{invalid: func(value AlertReason) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value AlertReason) any { return int64(value) }}}, true)
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
