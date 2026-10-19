// Code generated from ASN.1. DO NOT EDIT.

package v21_map_er_datatypes

import (
	"fmt"
	"math/big"

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
				if err := ber.CheckEncodedLength(opts, name, rule.description, rule.length(value)); err != nil {
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

// ERRoamingNotAllowedParamCodec binds MAP-ER-DataTypes.RoamingNotAllowedParam.
func ERRoamingNotAllowedParamCodec() ValueCodec[ERRoamingNotAllowedParam] {
	return compositeValueCodec[ERRoamingNotAllowedParam, *ERRoamingNotAllowedParam]()
}

// ERAdditionalRoamingNotAllowedCauseCodec binds MAP-ER-DataTypes.AdditionalRoamingNotAllowedCause.
func ERAdditionalRoamingNotAllowedCauseCodec() ValueCodec[BERValue[ERAdditionalRoamingNotAllowedCause]] {
	return integerValueCodec[ERAdditionalRoamingNotAllowedCause]("MAP-ER-DataTypes.AdditionalRoamingNotAllowedCause", "AdditionalRoamingNotAllowedCause", nil, true)
}

// ERRoamingNotAllowedCauseCodec binds MAP-ER-DataTypes.RoamingNotAllowedCause.
func ERRoamingNotAllowedCauseCodec() ValueCodec[BERValue[ERRoamingNotAllowedCause]] {
	return integerValueCodec[ERRoamingNotAllowedCause]("MAP-ER-DataTypes.RoamingNotAllowedCause", "RoamingNotAllowedCause", []primitiveRule[ERRoamingNotAllowedCause]{{invalid: func(value ERRoamingNotAllowedCause) bool { return (int64(value) != 0 && int64(value) != 3) }, description: "ENUMERATED {0, 3}", clause: "20", observed: func(value ERRoamingNotAllowedCause) any { return int64(value) }}}, true)
}

// ERCallBarredParamCodec binds MAP-ER-DataTypes.CallBarredParam.
func ERCallBarredParamCodec() ValueCodec[ERCallBarredParam] {
	return compositeValueCodec[ERCallBarredParam, *ERCallBarredParam]()
}

// ERCallBarringCauseCodec binds MAP-ER-DataTypes.CallBarringCause.
func ERCallBarringCauseCodec() ValueCodec[BERValue[ERCallBarringCause]] {
	return integerValueCodec[ERCallBarringCause]("MAP-ER-DataTypes.CallBarringCause", "CallBarringCause", []primitiveRule[ERCallBarringCause]{{invalid: func(value ERCallBarringCause) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value ERCallBarringCause) any { return int64(value) }}}, true)
}

// ERExtensibleCallBarredParamCodec binds MAP-ER-DataTypes.ExtensibleCallBarredParam.
func ERExtensibleCallBarredParamCodec() ValueCodec[ERExtensibleCallBarredParam] {
	return compositeValueCodec[ERExtensibleCallBarredParam, *ERExtensibleCallBarredParam]()
}

// ERCUGRejectParamCodec binds MAP-ER-DataTypes.CUG-RejectParam.
func ERCUGRejectParamCodec() ValueCodec[ERCUGRejectParam] {
	return compositeValueCodec[ERCUGRejectParam, *ERCUGRejectParam]()
}

// ERCUGRejectCauseCodec binds MAP-ER-DataTypes.CUG-RejectCause.
func ERCUGRejectCauseCodec() ValueCodec[BERValue[ERCUGRejectCause]] {
	return integerValueCodec[ERCUGRejectCause]("MAP-ER-DataTypes.CUG-RejectCause", "CUG-RejectCause", []primitiveRule[ERCUGRejectCause]{{invalid: func(value ERCUGRejectCause) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 5 && int64(value) != 7)
	}, description: "ENUMERATED {0, 1, 5, 7}", clause: "20", observed: func(value ERCUGRejectCause) any { return int64(value) }}}, true)
}

// ERSSIncompatibilityCauseCodec binds MAP-ER-DataTypes.SS-IncompatibilityCause.
func ERSSIncompatibilityCauseCodec() ValueCodec[ERSSIncompatibilityCause] {
	return compositeValueCodec[ERSSIncompatibilityCause, *ERSSIncompatibilityCause]()
}

// ERPWRegistrationFailureCauseCodec binds MAP-ER-DataTypes.PW-RegistrationFailureCause.
func ERPWRegistrationFailureCauseCodec() ValueCodec[BERValue[ERPWRegistrationFailureCause]] {
	return pointerValueCodec(UnmarshalBERERPWRegistrationFailureCause, MarshalBERERPWRegistrationFailureCause, MarshalDERERPWRegistrationFailureCause)
}

// ERSMEnumeratedDeliveryFailureCauseCodec binds MAP-ER-DataTypes.SM-EnumeratedDeliveryFailureCause.
func ERSMEnumeratedDeliveryFailureCauseCodec() ValueCodec[BERValue[ERSMEnumeratedDeliveryFailureCause]] {
	return integerValueCodec[ERSMEnumeratedDeliveryFailureCause]("MAP-ER-DataTypes.SM-EnumeratedDeliveryFailureCause", "SM-EnumeratedDeliveryFailureCause", []primitiveRule[ERSMEnumeratedDeliveryFailureCause]{{invalid: func(value ERSMEnumeratedDeliveryFailureCause) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", clause: "20", observed: func(value ERSMEnumeratedDeliveryFailureCause) any { return int64(value) }}}, true)
}

// ERSMDeliveryFailureCauseCodec binds MAP-ER-DataTypes.SM-DeliveryFailureCause.
func ERSMDeliveryFailureCauseCodec() ValueCodec[ERSMDeliveryFailureCause] {
	return compositeValueCodec[ERSMDeliveryFailureCause, *ERSMDeliveryFailureCause]()
}

// ERAbsentSubscriberSMParamCodec binds MAP-ER-DataTypes.AbsentSubscriberSM-Param.
func ERAbsentSubscriberSMParamCodec() ValueCodec[ERAbsentSubscriberSMParam] {
	return compositeValueCodec[ERAbsentSubscriberSMParam, *ERAbsentSubscriberSMParam]()
}

// ERAbsentSubscriberDiagnosticSMCodec binds MAP-ER-DataTypes.AbsentSubscriberDiagnosticSM.
func ERAbsentSubscriberDiagnosticSMCodec() ValueCodec[BERValue[ERAbsentSubscriberDiagnosticSM]] {
	return integerValueCodec[ERAbsentSubscriberDiagnosticSM]("MAP-ER-DataTypes.AbsentSubscriberDiagnosticSM", "AbsentSubscriberDiagnosticSM", []primitiveRule[ERAbsentSubscriberDiagnosticSM]{{invalid: func(value ERAbsentSubscriberDiagnosticSM) bool { return !(int64(value) >= 0 && int64(value) <= 255) }, description: "(0..255)", clause: "51.4", observed: func(value ERAbsentSubscriberDiagnosticSM) any { return int64(value) }}}, false)
}

// ERSystemFailureParamCodec binds MAP-ER-DataTypes.SystemFailureParam.
func ERSystemFailureParamCodec() ValueCodec[ERSystemFailureParam] {
	return compositeValueCodec[ERSystemFailureParam, *ERSystemFailureParam]()
}

// ERExtensibleSystemFailureParamCodec binds MAP-ER-DataTypes.ExtensibleSystemFailureParam.
func ERExtensibleSystemFailureParamCodec() ValueCodec[ERExtensibleSystemFailureParam] {
	return compositeValueCodec[ERExtensibleSystemFailureParam, *ERExtensibleSystemFailureParam]()
}

// ERFailureCauseParamCodec binds MAP-ER-DataTypes.FailureCauseParam.
func ERFailureCauseParamCodec() ValueCodec[BERValue[ERFailureCauseParam]] {
	return integerValueCodec[ERFailureCauseParam]("MAP-ER-DataTypes.FailureCauseParam", "FailureCauseParam", nil, true)
}

// ERDataMissingParamCodec binds MAP-ER-DataTypes.DataMissingParam.
func ERDataMissingParamCodec() ValueCodec[ERDataMissingParam] {
	return compositeValueCodec[ERDataMissingParam, *ERDataMissingParam]()
}

// ERUnexpectedDataParamCodec binds MAP-ER-DataTypes.UnexpectedDataParam.
func ERUnexpectedDataParamCodec() ValueCodec[ERUnexpectedDataParam] {
	return compositeValueCodec[ERUnexpectedDataParam, *ERUnexpectedDataParam]()
}

// ERFacilityNotSupParamCodec binds MAP-ER-DataTypes.FacilityNotSupParam.
func ERFacilityNotSupParamCodec() ValueCodec[ERFacilityNotSupParam] {
	return compositeValueCodec[ERFacilityNotSupParam, *ERFacilityNotSupParam]()
}

// ERORNotAllowedParamCodec binds MAP-ER-DataTypes.OR-NotAllowedParam.
func ERORNotAllowedParamCodec() ValueCodec[ERORNotAllowedParam] {
	return compositeValueCodec[ERORNotAllowedParam, *ERORNotAllowedParam]()
}

// ERUnknownSubscriberParamCodec binds MAP-ER-DataTypes.UnknownSubscriberParam.
func ERUnknownSubscriberParamCodec() ValueCodec[ERUnknownSubscriberParam] {
	return compositeValueCodec[ERUnknownSubscriberParam, *ERUnknownSubscriberParam]()
}

// ERUnknownSubscriberDiagnosticCodec binds MAP-ER-DataTypes.UnknownSubscriberDiagnostic.
func ERUnknownSubscriberDiagnosticCodec() ValueCodec[BERValue[ERUnknownSubscriberDiagnostic]] {
	return integerValueCodec[ERUnknownSubscriberDiagnostic]("MAP-ER-DataTypes.UnknownSubscriberDiagnostic", "UnknownSubscriberDiagnostic", nil, true)
}

// ERNumberChangedParamCodec binds MAP-ER-DataTypes.NumberChangedParam.
func ERNumberChangedParamCodec() ValueCodec[ERNumberChangedParam] {
	return compositeValueCodec[ERNumberChangedParam, *ERNumberChangedParam]()
}

// ERUnidentifiedSubParamCodec binds MAP-ER-DataTypes.UnidentifiedSubParam.
func ERUnidentifiedSubParamCodec() ValueCodec[ERUnidentifiedSubParam] {
	return compositeValueCodec[ERUnidentifiedSubParam, *ERUnidentifiedSubParam]()
}

// ERIllegalSubscriberParamCodec binds MAP-ER-DataTypes.IllegalSubscriberParam.
func ERIllegalSubscriberParamCodec() ValueCodec[ERIllegalSubscriberParam] {
	return compositeValueCodec[ERIllegalSubscriberParam, *ERIllegalSubscriberParam]()
}

// ERIllegalEquipmentParamCodec binds MAP-ER-DataTypes.IllegalEquipmentParam.
func ERIllegalEquipmentParamCodec() ValueCodec[ERIllegalEquipmentParam] {
	return compositeValueCodec[ERIllegalEquipmentParam, *ERIllegalEquipmentParam]()
}

// ERBearerServNotProvParamCodec binds MAP-ER-DataTypes.BearerServNotProvParam.
func ERBearerServNotProvParamCodec() ValueCodec[ERBearerServNotProvParam] {
	return compositeValueCodec[ERBearerServNotProvParam, *ERBearerServNotProvParam]()
}

// ERTeleservNotProvParamCodec binds MAP-ER-DataTypes.TeleservNotProvParam.
func ERTeleservNotProvParamCodec() ValueCodec[ERTeleservNotProvParam] {
	return compositeValueCodec[ERTeleservNotProvParam, *ERTeleservNotProvParam]()
}

// ERTracingBufferFullParamCodec binds MAP-ER-DataTypes.TracingBufferFullParam.
func ERTracingBufferFullParamCodec() ValueCodec[ERTracingBufferFullParam] {
	return compositeValueCodec[ERTracingBufferFullParam, *ERTracingBufferFullParam]()
}

// ERNoRoamingNbParamCodec binds MAP-ER-DataTypes.NoRoamingNbParam.
func ERNoRoamingNbParamCodec() ValueCodec[ERNoRoamingNbParam] {
	return compositeValueCodec[ERNoRoamingNbParam, *ERNoRoamingNbParam]()
}

// ERAbsentSubscriberParamCodec binds MAP-ER-DataTypes.AbsentSubscriberParam.
func ERAbsentSubscriberParamCodec() ValueCodec[ERAbsentSubscriberParam] {
	return compositeValueCodec[ERAbsentSubscriberParam, *ERAbsentSubscriberParam]()
}

// ERAbsentSubscriberReasonCodec binds MAP-ER-DataTypes.AbsentSubscriberReason.
func ERAbsentSubscriberReasonCodec() ValueCodec[BERValue[ERAbsentSubscriberReason]] {
	return integerValueCodec[ERAbsentSubscriberReason]("MAP-ER-DataTypes.AbsentSubscriberReason", "AbsentSubscriberReason", nil, true)
}

// ERBusySubscriberParamCodec binds MAP-ER-DataTypes.BusySubscriberParam.
func ERBusySubscriberParamCodec() ValueCodec[ERBusySubscriberParam] {
	return compositeValueCodec[ERBusySubscriberParam, *ERBusySubscriberParam]()
}

// ERNoSubscriberReplyParamCodec binds MAP-ER-DataTypes.NoSubscriberReplyParam.
func ERNoSubscriberReplyParamCodec() ValueCodec[ERNoSubscriberReplyParam] {
	return compositeValueCodec[ERNoSubscriberReplyParam, *ERNoSubscriberReplyParam]()
}

// ERForwardingViolationParamCodec binds MAP-ER-DataTypes.ForwardingViolationParam.
func ERForwardingViolationParamCodec() ValueCodec[ERForwardingViolationParam] {
	return compositeValueCodec[ERForwardingViolationParam, *ERForwardingViolationParam]()
}

// ERForwardingFailedParamCodec binds MAP-ER-DataTypes.ForwardingFailedParam.
func ERForwardingFailedParamCodec() ValueCodec[ERForwardingFailedParam] {
	return compositeValueCodec[ERForwardingFailedParam, *ERForwardingFailedParam]()
}

// ERATINotAllowedParamCodec binds MAP-ER-DataTypes.ATI-NotAllowedParam.
func ERATINotAllowedParamCodec() ValueCodec[ERATINotAllowedParam] {
	return compositeValueCodec[ERATINotAllowedParam, *ERATINotAllowedParam]()
}

// ERATSINotAllowedParamCodec binds MAP-ER-DataTypes.ATSI-NotAllowedParam.
func ERATSINotAllowedParamCodec() ValueCodec[ERATSINotAllowedParam] {
	return compositeValueCodec[ERATSINotAllowedParam, *ERATSINotAllowedParam]()
}

// ERATMNotAllowedParamCodec binds MAP-ER-DataTypes.ATM-NotAllowedParam.
func ERATMNotAllowedParamCodec() ValueCodec[ERATMNotAllowedParam] {
	return compositeValueCodec[ERATMNotAllowedParam, *ERATMNotAllowedParam]()
}

// ERIllegalSSOperationParamCodec binds MAP-ER-DataTypes.IllegalSS-OperationParam.
func ERIllegalSSOperationParamCodec() ValueCodec[ERIllegalSSOperationParam] {
	return compositeValueCodec[ERIllegalSSOperationParam, *ERIllegalSSOperationParam]()
}

// ERSSNotAvailableParamCodec binds MAP-ER-DataTypes.SS-NotAvailableParam.
func ERSSNotAvailableParamCodec() ValueCodec[ERSSNotAvailableParam] {
	return compositeValueCodec[ERSSNotAvailableParam, *ERSSNotAvailableParam]()
}

// ERSSSubscriptionViolationParamCodec binds MAP-ER-DataTypes.SS-SubscriptionViolationParam.
func ERSSSubscriptionViolationParamCodec() ValueCodec[ERSSSubscriptionViolationParam] {
	return compositeValueCodec[ERSSSubscriptionViolationParam, *ERSSSubscriptionViolationParam]()
}

// ERInformationNotAvailableParamCodec binds MAP-ER-DataTypes.InformationNotAvailableParam.
func ERInformationNotAvailableParamCodec() ValueCodec[ERInformationNotAvailableParam] {
	return compositeValueCodec[ERInformationNotAvailableParam, *ERInformationNotAvailableParam]()
}

// ERSubBusyForMTSMSParamCodec binds MAP-ER-DataTypes.SubBusyForMT-SMS-Param.
func ERSubBusyForMTSMSParamCodec() ValueCodec[ERSubBusyForMTSMSParam] {
	return compositeValueCodec[ERSubBusyForMTSMSParam, *ERSubBusyForMTSMSParam]()
}

// ERMessageWaitListFullParamCodec binds MAP-ER-DataTypes.MessageWaitListFullParam.
func ERMessageWaitListFullParamCodec() ValueCodec[ERMessageWaitListFullParam] {
	return compositeValueCodec[ERMessageWaitListFullParam, *ERMessageWaitListFullParam]()
}

// ERResourceLimitationParamCodec binds MAP-ER-DataTypes.ResourceLimitationParam.
func ERResourceLimitationParamCodec() ValueCodec[ERResourceLimitationParam] {
	return compositeValueCodec[ERResourceLimitationParam, *ERResourceLimitationParam]()
}

// ERNoGroupCallNbParamCodec binds MAP-ER-DataTypes.NoGroupCallNbParam.
func ERNoGroupCallNbParamCodec() ValueCodec[ERNoGroupCallNbParam] {
	return compositeValueCodec[ERNoGroupCallNbParam, *ERNoGroupCallNbParam]()
}

// ERIncompatibleTerminalParamCodec binds MAP-ER-DataTypes.IncompatibleTerminalParam.
func ERIncompatibleTerminalParamCodec() ValueCodec[ERIncompatibleTerminalParam] {
	return compositeValueCodec[ERIncompatibleTerminalParam, *ERIncompatibleTerminalParam]()
}

// ERShortTermDenialParamCodec binds MAP-ER-DataTypes.ShortTermDenialParam.
func ERShortTermDenialParamCodec() ValueCodec[ERShortTermDenialParam] {
	return compositeValueCodec[ERShortTermDenialParam, *ERShortTermDenialParam]()
}

// ERLongTermDenialParamCodec binds MAP-ER-DataTypes.LongTermDenialParam.
func ERLongTermDenialParamCodec() ValueCodec[ERLongTermDenialParam] {
	return compositeValueCodec[ERLongTermDenialParam, *ERLongTermDenialParam]()
}

// ERUnauthorizedRequestingNetworkParamCodec binds MAP-ER-DataTypes.UnauthorizedRequestingNetwork-Param.
func ERUnauthorizedRequestingNetworkParamCodec() ValueCodec[ERUnauthorizedRequestingNetworkParam] {
	return compositeValueCodec[ERUnauthorizedRequestingNetworkParam, *ERUnauthorizedRequestingNetworkParam]()
}

// ERUnauthorizedLCSClientParamCodec binds MAP-ER-DataTypes.UnauthorizedLCSClient-Param.
func ERUnauthorizedLCSClientParamCodec() ValueCodec[ERUnauthorizedLCSClientParam] {
	return compositeValueCodec[ERUnauthorizedLCSClientParam, *ERUnauthorizedLCSClientParam]()
}

// ERUnauthorizedLCSClientDiagnosticCodec binds MAP-ER-DataTypes.UnauthorizedLCSClient-Diagnostic.
func ERUnauthorizedLCSClientDiagnosticCodec() ValueCodec[BERValue[ERUnauthorizedLCSClientDiagnostic]] {
	return integerValueCodec[ERUnauthorizedLCSClientDiagnostic]("MAP-ER-DataTypes.UnauthorizedLCSClient-Diagnostic", "UnauthorizedLCSClient-Diagnostic", nil, true)
}

// ERPositionMethodFailureParamCodec binds MAP-ER-DataTypes.PositionMethodFailure-Param.
func ERPositionMethodFailureParamCodec() ValueCodec[ERPositionMethodFailureParam] {
	return compositeValueCodec[ERPositionMethodFailureParam, *ERPositionMethodFailureParam]()
}

// ERPositionMethodFailureDiagnosticCodec binds MAP-ER-DataTypes.PositionMethodFailure-Diagnostic.
func ERPositionMethodFailureDiagnosticCodec() ValueCodec[BERValue[ERPositionMethodFailureDiagnostic]] {
	return integerValueCodec[ERPositionMethodFailureDiagnostic]("MAP-ER-DataTypes.PositionMethodFailure-Diagnostic", "PositionMethodFailure-Diagnostic", nil, true)
}

// ERUnknownOrUnreachableLCSClientParamCodec binds MAP-ER-DataTypes.UnknownOrUnreachableLCSClient-Param.
func ERUnknownOrUnreachableLCSClientParamCodec() ValueCodec[ERUnknownOrUnreachableLCSClientParam] {
	return compositeValueCodec[ERUnknownOrUnreachableLCSClientParam, *ERUnknownOrUnreachableLCSClientParam]()
}

// ERMMEventNotSupportedParamCodec binds MAP-ER-DataTypes.MM-EventNotSupported-Param.
func ERMMEventNotSupportedParamCodec() ValueCodec[ERMMEventNotSupportedParam] {
	return compositeValueCodec[ERMMEventNotSupportedParam, *ERMMEventNotSupportedParam]()
}

// ERTargetCellOutsideGCAParamCodec binds MAP-ER-DataTypes.TargetCellOutsideGCA-Param.
func ERTargetCellOutsideGCAParamCodec() ValueCodec[ERTargetCellOutsideGCAParam] {
	return compositeValueCodec[ERTargetCellOutsideGCAParam, *ERTargetCellOutsideGCAParam]()
}

// EROngoingGroupCallParamCodec binds MAP-ER-DataTypes.OngoingGroupCallParam.
func EROngoingGroupCallParamCodec() ValueCodec[EROngoingGroupCallParam] {
	return compositeValueCodec[EROngoingGroupCallParam, *EROngoingGroupCallParam]()
}
