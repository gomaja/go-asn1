// Code generated from ASN.1. DO NOT EDIT.

package v21_map_lcs_datatypes

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

// LCSRoutingInfoForLCSArgCodec binds MAP-LCS-DataTypes.RoutingInfoForLCS-Arg.
func LCSRoutingInfoForLCSArgCodec() ValueCodec[LCSRoutingInfoForLCSArg] {
	return compositeValueCodec[LCSRoutingInfoForLCSArg, *LCSRoutingInfoForLCSArg]()
}

// LCSRoutingInfoForLCSResCodec binds MAP-LCS-DataTypes.RoutingInfoForLCS-Res.
func LCSRoutingInfoForLCSResCodec() ValueCodec[LCSRoutingInfoForLCSRes] {
	return compositeValueCodec[LCSRoutingInfoForLCSRes, *LCSRoutingInfoForLCSRes]()
}

// LCSLCSLocationInfoCodec binds MAP-LCS-DataTypes.LCSLocationInfo.
func LCSLCSLocationInfoCodec() ValueCodec[LCSLCSLocationInfo] {
	return compositeValueCodec[LCSLCSLocationInfo, *LCSLCSLocationInfo]()
}

// LCSProvideSubscriberLocationArgCodec binds MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg.
func LCSProvideSubscriberLocationArgCodec() ValueCodec[LCSProvideSubscriberLocationArg] {
	return compositeValueCodec[LCSProvideSubscriberLocationArg, *LCSProvideSubscriberLocationArg]()
}

// LCSLocationTypeCodec binds MAP-LCS-DataTypes.LocationType.
func LCSLocationTypeCodec() ValueCodec[LCSLocationType] {
	return compositeValueCodec[LCSLocationType, *LCSLocationType]()
}

// LCSLocationEstimateTypeCodec binds MAP-LCS-DataTypes.LocationEstimateType.
func LCSLocationEstimateTypeCodec() ValueCodec[BERValue[LCSLocationEstimateType]] {
	return integerValueCodec[LCSLocationEstimateType]("MAP-LCS-DataTypes.LocationEstimateType", "LocationEstimateType", nil, true)
}

// LCSDeferredLocationEventTypeCodec binds MAP-LCS-DataTypes.DeferredLocationEventType.
func LCSDeferredLocationEventTypeCodec() ValueCodec[BERValue[LCSDeferredLocationEventType]] {
	return bitValueCodec("MAP-LCS-DataTypes.DeferredLocationEventType", "DeferredLocationEventType", []primitiveRule[LCSDeferredLocationEventType]{{invalid: func(value LCSDeferredLocationEventType) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value LCSDeferredLocationEventType) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// LCSLCSClientIDCodec binds MAP-LCS-DataTypes.LCS-ClientID.
func LCSLCSClientIDCodec() ValueCodec[LCSLCSClientID] {
	return compositeValueCodec[LCSLCSClientID, *LCSLCSClientID]()
}

// LCSLCSClientTypeCodec binds MAP-LCS-DataTypes.LCSClientType.
func LCSLCSClientTypeCodec() ValueCodec[BERValue[LCSLCSClientType]] {
	return integerValueCodec[LCSLCSClientType]("MAP-LCS-DataTypes.LCSClientType", "LCSClientType", nil, true)
}

// LCSLCSClientNameCodec binds MAP-LCS-DataTypes.LCSClientName.
func LCSLCSClientNameCodec() ValueCodec[LCSLCSClientName] {
	return compositeValueCodec[LCSLCSClientName, *LCSLCSClientName]()
}

// LCSNameStringCodec binds MAP-LCS-DataTypes.NameString.
func LCSNameStringCodec() ValueCodec[BERValue[LCSNameString]] {
	return pointerValueCodec(UnmarshalBERLCSNameString, MarshalBERLCSNameString, MarshalDERLCSNameString)
}

// LCSLCSRequestorIDCodec binds MAP-LCS-DataTypes.LCSRequestorID.
func LCSLCSRequestorIDCodec() ValueCodec[LCSLCSRequestorID] {
	return compositeValueCodec[LCSLCSRequestorID, *LCSLCSRequestorID]()
}

// LCSRequestorIDStringCodec binds MAP-LCS-DataTypes.RequestorIDString.
func LCSRequestorIDStringCodec() ValueCodec[BERValue[LCSRequestorIDString]] {
	return pointerValueCodec(UnmarshalBERLCSRequestorIDString, MarshalBERLCSRequestorIDString, MarshalDERLCSRequestorIDString)
}

// LCSLCSFormatIndicatorCodec binds MAP-LCS-DataTypes.LCS-FormatIndicator.
func LCSLCSFormatIndicatorCodec() ValueCodec[BERValue[LCSLCSFormatIndicator]] {
	return integerValueCodec[LCSLCSFormatIndicator]("MAP-LCS-DataTypes.LCS-FormatIndicator", "LCS-FormatIndicator", nil, true)
}

// LCSLCSPriorityCodec binds MAP-LCS-DataTypes.LCS-Priority.
func LCSLCSPriorityCodec() ValueCodec[BERValue[LCSLCSPriority]] {
	return octetValueCodec[LCSLCSPriority]("MAP-LCS-DataTypes.LCS-Priority", "LCS-Priority", []primitiveRule[LCSLCSPriority]{{invalid: func(value LCSLCSPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value LCSLCSPriority) int { return len(value) }}})
}

// LCSLCSQoSCodec binds MAP-LCS-DataTypes.LCS-QoS.
func LCSLCSQoSCodec() ValueCodec[LCSLCSQoS] {
	return compositeValueCodec[LCSLCSQoS, *LCSLCSQoS]()
}

// LCSHorizontalAccuracyCodec binds MAP-LCS-DataTypes.Horizontal-Accuracy.
func LCSHorizontalAccuracyCodec() ValueCodec[BERValue[LCSHorizontalAccuracy]] {
	return octetValueCodec[LCSHorizontalAccuracy]("MAP-LCS-DataTypes.Horizontal-Accuracy", "Horizontal-Accuracy", []primitiveRule[LCSHorizontalAccuracy]{{invalid: func(value LCSHorizontalAccuracy) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value LCSHorizontalAccuracy) int { return len(value) }}})
}

// LCSVerticalAccuracyCodec binds MAP-LCS-DataTypes.Vertical-Accuracy.
func LCSVerticalAccuracyCodec() ValueCodec[BERValue[LCSVerticalAccuracy]] {
	return octetValueCodec[LCSVerticalAccuracy]("MAP-LCS-DataTypes.Vertical-Accuracy", "Vertical-Accuracy", []primitiveRule[LCSVerticalAccuracy]{{invalid: func(value LCSVerticalAccuracy) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value LCSVerticalAccuracy) int { return len(value) }}})
}

// LCSResponseTimeCodec binds MAP-LCS-DataTypes.ResponseTime.
func LCSResponseTimeCodec() ValueCodec[LCSResponseTime] {
	return compositeValueCodec[LCSResponseTime, *LCSResponseTime]()
}

// LCSResponseTimeCategoryCodec binds MAP-LCS-DataTypes.ResponseTimeCategory.
func LCSResponseTimeCategoryCodec() ValueCodec[BERValue[LCSResponseTimeCategory]] {
	return integerValueCodec[LCSResponseTimeCategory]("MAP-LCS-DataTypes.ResponseTimeCategory", "ResponseTimeCategory", nil, true)
}

// LCSLCSQoSClassCodec binds MAP-LCS-DataTypes.LCS-QoS-Class.
func LCSLCSQoSClassCodec() ValueCodec[BERValue[LCSLCSQoSClass]] {
	return integerValueCodec[LCSLCSQoSClass]("MAP-LCS-DataTypes.LCS-QoS-Class", "LCS-QoS-Class", nil, true)
}

// LCSSupportedGADShapesCodec binds MAP-LCS-DataTypes.SupportedGADShapes.
func LCSSupportedGADShapesCodec() ValueCodec[BERValue[LCSSupportedGADShapes]] {
	return bitValueCodec("MAP-LCS-DataTypes.SupportedGADShapes", "SupportedGADShapes", []primitiveRule[LCSSupportedGADShapes]{{invalid: func(value LCSSupportedGADShapes) bool { return !(value.BitLength >= 7 && value.BitLength <= 16) }, description: "SIZE (7..16)", clause: "51.5", length: func(value LCSSupportedGADShapes) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}})
}

// LCSLCSReferenceNumberCodec binds MAP-LCS-DataTypes.LCS-ReferenceNumber.
func LCSLCSReferenceNumberCodec() ValueCodec[BERValue[LCSLCSReferenceNumber]] {
	return octetValueCodec[LCSLCSReferenceNumber]("MAP-LCS-DataTypes.LCS-ReferenceNumber", "LCS-ReferenceNumber", []primitiveRule[LCSLCSReferenceNumber]{{invalid: func(value LCSLCSReferenceNumber) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value LCSLCSReferenceNumber) int { return len(value) }}})
}

// LCSLCSCodewordCodec binds MAP-LCS-DataTypes.LCSCodeword.
func LCSLCSCodewordCodec() ValueCodec[LCSLCSCodeword] {
	return compositeValueCodec[LCSLCSCodeword, *LCSLCSCodeword]()
}

// LCSLCSCodewordStringCodec binds MAP-LCS-DataTypes.LCSCodewordString.
func LCSLCSCodewordStringCodec() ValueCodec[BERValue[LCSLCSCodewordString]] {
	return pointerValueCodec(UnmarshalBERLCSLCSCodewordString, MarshalBERLCSLCSCodewordString, MarshalDERLCSLCSCodewordString)
}

// LCSLCSPrivacyCheckCodec binds MAP-LCS-DataTypes.LCS-PrivacyCheck.
func LCSLCSPrivacyCheckCodec() ValueCodec[LCSLCSPrivacyCheck] {
	return compositeValueCodec[LCSLCSPrivacyCheck, *LCSLCSPrivacyCheck]()
}

// LCSPrivacyCheckRelatedActionCodec binds MAP-LCS-DataTypes.PrivacyCheckRelatedAction.
func LCSPrivacyCheckRelatedActionCodec() ValueCodec[BERValue[LCSPrivacyCheckRelatedAction]] {
	return integerValueCodec[LCSPrivacyCheckRelatedAction]("MAP-LCS-DataTypes.PrivacyCheckRelatedAction", "PrivacyCheckRelatedAction", nil, true)
}

// LCSAreaEventInfoCodec binds MAP-LCS-DataTypes.AreaEventInfo.
func LCSAreaEventInfoCodec() ValueCodec[LCSAreaEventInfo] {
	return compositeValueCodec[LCSAreaEventInfo, *LCSAreaEventInfo]()
}

// LCSAreaDefinitionCodec binds MAP-LCS-DataTypes.AreaDefinition.
func LCSAreaDefinitionCodec() ValueCodec[LCSAreaDefinition] {
	return compositeValueCodec[LCSAreaDefinition, *LCSAreaDefinition]()
}

// LCSAreaListCodec binds MAP-LCS-DataTypes.AreaList.
func LCSAreaListCodec() ValueCodec[LCSAreaList] {
	return pointerValueCodec(UnmarshalBERLCSAreaList, MarshalBERLCSAreaList, MarshalDERLCSAreaList)
}

// LCSAreaCodec binds MAP-LCS-DataTypes.Area.
func LCSAreaCodec() ValueCodec[LCSArea] {
	return compositeValueCodec[LCSArea, *LCSArea]()
}

// LCSAreaTypeCodec binds MAP-LCS-DataTypes.AreaType.
func LCSAreaTypeCodec() ValueCodec[BERValue[LCSAreaType]] {
	return integerValueCodec[LCSAreaType]("MAP-LCS-DataTypes.AreaType", "AreaType", nil, true)
}

// LCSAreaIdentificationCodec binds MAP-LCS-DataTypes.AreaIdentification.
func LCSAreaIdentificationCodec() ValueCodec[BERValue[LCSAreaIdentification]] {
	return octetValueCodec[LCSAreaIdentification]("MAP-LCS-DataTypes.AreaIdentification", "AreaIdentification", []primitiveRule[LCSAreaIdentification]{{invalid: func(value LCSAreaIdentification) bool { return !(len(value) >= 2 && len(value) <= 7) }, description: "SIZE (2..7)", clause: "51.5", length: func(value LCSAreaIdentification) int { return len(value) }}})
}

// LCSOccurrenceInfoCodec binds MAP-LCS-DataTypes.OccurrenceInfo.
func LCSOccurrenceInfoCodec() ValueCodec[BERValue[LCSOccurrenceInfo]] {
	return integerValueCodec[LCSOccurrenceInfo]("MAP-LCS-DataTypes.OccurrenceInfo", "OccurrenceInfo", nil, true)
}

// LCSIntervalTimeCodec binds MAP-LCS-DataTypes.IntervalTime.
func LCSIntervalTimeCodec() ValueCodec[BERValue[LCSIntervalTime]] {
	return integerValueCodec[LCSIntervalTime]("MAP-LCS-DataTypes.IntervalTime", "IntervalTime", []primitiveRule[LCSIntervalTime]{{invalid: func(value LCSIntervalTime) bool { return !(int64(value) >= 1 && int64(value) <= 32767) }, description: "(1..32767)", clause: "51.4", observed: func(value LCSIntervalTime) any { return int64(value) }}}, false)
}

// LCSPeriodicLDRInfoCodec binds MAP-LCS-DataTypes.PeriodicLDRInfo.
func LCSPeriodicLDRInfoCodec() ValueCodec[LCSPeriodicLDRInfo] {
	return compositeValueCodec[LCSPeriodicLDRInfo, *LCSPeriodicLDRInfo]()
}

// LCSReportingAmountCodec binds MAP-LCS-DataTypes.ReportingAmount.
func LCSReportingAmountCodec() ValueCodec[BERValue[LCSReportingAmount]] {
	return integerValueCodec[LCSReportingAmount]("MAP-LCS-DataTypes.ReportingAmount", "ReportingAmount", []primitiveRule[LCSReportingAmount]{{invalid: func(value LCSReportingAmount) bool { return !(int64(value) >= 1 && int64(value) <= 8639999) }, description: "(1..8639999)", clause: "51.4", observed: func(value LCSReportingAmount) any { return int64(value) }}}, false)
}

// LCSReportingIntervalCodec binds MAP-LCS-DataTypes.ReportingInterval.
func LCSReportingIntervalCodec() ValueCodec[BERValue[LCSReportingInterval]] {
	return integerValueCodec[LCSReportingInterval]("MAP-LCS-DataTypes.ReportingInterval", "ReportingInterval", []primitiveRule[LCSReportingInterval]{{invalid: func(value LCSReportingInterval) bool { return !(int64(value) >= 1 && int64(value) <= 8639999) }, description: "(1..8639999)", clause: "51.4", observed: func(value LCSReportingInterval) any { return int64(value) }}}, false)
}

// LCSReportingOptionMillisecondsCodec binds MAP-LCS-DataTypes.ReportingOptionMilliseconds.
func LCSReportingOptionMillisecondsCodec() ValueCodec[LCSReportingOptionMilliseconds] {
	return compositeValueCodec[LCSReportingOptionMilliseconds, *LCSReportingOptionMilliseconds]()
}

// LCSReportingAmountMillisecondsCodec binds MAP-LCS-DataTypes.ReportingAmountMilliseconds.
func LCSReportingAmountMillisecondsCodec() ValueCodec[BERValue[LCSReportingAmountMilliseconds]] {
	return integerValueCodec[LCSReportingAmountMilliseconds]("MAP-LCS-DataTypes.ReportingAmountMilliseconds", "ReportingAmountMilliseconds", []primitiveRule[LCSReportingAmountMilliseconds]{{invalid: func(value LCSReportingAmountMilliseconds) bool {
		return !(int64(value) >= 1 && int64(value) <= 8639999000)
	}, description: "(1..8639999000)", clause: "51.4", observed: func(value LCSReportingAmountMilliseconds) any { return int64(value) }}}, false)
}

// LCSReportingIntervalMillisecondsCodec binds MAP-LCS-DataTypes.ReportingIntervalMilliseconds.
func LCSReportingIntervalMillisecondsCodec() ValueCodec[BERValue[LCSReportingIntervalMilliseconds]] {
	return integerValueCodec[LCSReportingIntervalMilliseconds]("MAP-LCS-DataTypes.ReportingIntervalMilliseconds", "ReportingIntervalMilliseconds", []primitiveRule[LCSReportingIntervalMilliseconds]{{invalid: func(value LCSReportingIntervalMilliseconds) bool { return !(int64(value) >= 1 && int64(value) <= 999) }, description: "(1..999)", clause: "51.4", observed: func(value LCSReportingIntervalMilliseconds) any { return int64(value) }}}, false)
}

// LCSReportingPLMNListCodec binds MAP-LCS-DataTypes.ReportingPLMNList.
func LCSReportingPLMNListCodec() ValueCodec[LCSReportingPLMNList] {
	return compositeValueCodec[LCSReportingPLMNList, *LCSReportingPLMNList]()
}

// LCSPLMNListCodec binds MAP-LCS-DataTypes.PLMNList.
func LCSPLMNListCodec() ValueCodec[LCSPLMNList] {
	return pointerValueCodec(UnmarshalBERLCSPLMNList, MarshalBERLCSPLMNList, MarshalDERLCSPLMNList)
}

// LCSReportingPLMNCodec binds MAP-LCS-DataTypes.ReportingPLMN.
func LCSReportingPLMNCodec() ValueCodec[LCSReportingPLMN] {
	return compositeValueCodec[LCSReportingPLMN, *LCSReportingPLMN]()
}

// LCSRANTechnologyCodec binds MAP-LCS-DataTypes.RAN-Technology.
func LCSRANTechnologyCodec() ValueCodec[BERValue[LCSRANTechnology]] {
	return integerValueCodec[LCSRANTechnology]("MAP-LCS-DataTypes.RAN-Technology", "RAN-Technology", nil, true)
}

// LCSProvideSubscriberLocationResCodec binds MAP-LCS-DataTypes.ProvideSubscriberLocation-Res.
func LCSProvideSubscriberLocationResCodec() ValueCodec[LCSProvideSubscriberLocationRes] {
	return compositeValueCodec[LCSProvideSubscriberLocationRes, *LCSProvideSubscriberLocationRes]()
}

// LCSAccuracyFulfilmentIndicatorCodec binds MAP-LCS-DataTypes.AccuracyFulfilmentIndicator.
func LCSAccuracyFulfilmentIndicatorCodec() ValueCodec[BERValue[LCSAccuracyFulfilmentIndicator]] {
	return integerValueCodec[LCSAccuracyFulfilmentIndicator]("MAP-LCS-DataTypes.AccuracyFulfilmentIndicator", "AccuracyFulfilmentIndicator", nil, true)
}

// LCSExtGeographicalInformationCodec binds MAP-LCS-DataTypes.Ext-GeographicalInformation.
func LCSExtGeographicalInformationCodec() ValueCodec[BERValue[LCSExtGeographicalInformation]] {
	return octetValueCodec[LCSExtGeographicalInformation]("MAP-LCS-DataTypes.Ext-GeographicalInformation", "Ext-GeographicalInformation", []primitiveRule[LCSExtGeographicalInformation]{{invalid: func(value LCSExtGeographicalInformation) bool { return !(len(value) >= 1 && len(value) <= 20) }, description: "SIZE (1..20)", clause: "51.5", length: func(value LCSExtGeographicalInformation) int { return len(value) }}})
}

// LCSVelocityEstimateCodec binds MAP-LCS-DataTypes.VelocityEstimate.
func LCSVelocityEstimateCodec() ValueCodec[BERValue[LCSVelocityEstimate]] {
	return octetValueCodec[LCSVelocityEstimate]("MAP-LCS-DataTypes.VelocityEstimate", "VelocityEstimate", []primitiveRule[LCSVelocityEstimate]{{invalid: func(value LCSVelocityEstimate) bool { return !(len(value) >= 4 && len(value) <= 7) }, description: "SIZE (4..7)", clause: "51.5", length: func(value LCSVelocityEstimate) int { return len(value) }}})
}

// LCSPositioningDataInformationCodec binds MAP-LCS-DataTypes.PositioningDataInformation.
func LCSPositioningDataInformationCodec() ValueCodec[BERValue[LCSPositioningDataInformation]] {
	return octetValueCodec[LCSPositioningDataInformation]("MAP-LCS-DataTypes.PositioningDataInformation", "PositioningDataInformation", []primitiveRule[LCSPositioningDataInformation]{{invalid: func(value LCSPositioningDataInformation) bool { return !(len(value) >= 2 && len(value) <= 10) }, description: "SIZE (2..10)", clause: "51.5", length: func(value LCSPositioningDataInformation) int { return len(value) }}})
}

// LCSUtranPositioningDataInfoCodec binds MAP-LCS-DataTypes.UtranPositioningDataInfo.
func LCSUtranPositioningDataInfoCodec() ValueCodec[BERValue[LCSUtranPositioningDataInfo]] {
	return octetValueCodec[LCSUtranPositioningDataInfo]("MAP-LCS-DataTypes.UtranPositioningDataInfo", "UtranPositioningDataInfo", []primitiveRule[LCSUtranPositioningDataInfo]{{invalid: func(value LCSUtranPositioningDataInfo) bool { return !(len(value) >= 3 && len(value) <= 11) }, description: "SIZE (3..11)", clause: "51.5", length: func(value LCSUtranPositioningDataInfo) int { return len(value) }}})
}

// LCSGeranGANSSpositioningDataCodec binds MAP-LCS-DataTypes.GeranGANSSpositioningData.
func LCSGeranGANSSpositioningDataCodec() ValueCodec[BERValue[LCSGeranGANSSpositioningData]] {
	return octetValueCodec[LCSGeranGANSSpositioningData]("MAP-LCS-DataTypes.GeranGANSSpositioningData", "GeranGANSSpositioningData", []primitiveRule[LCSGeranGANSSpositioningData]{{invalid: func(value LCSGeranGANSSpositioningData) bool { return !(len(value) >= 2 && len(value) <= 10) }, description: "SIZE (2..10)", clause: "51.5", length: func(value LCSGeranGANSSpositioningData) int { return len(value) }}})
}

// LCSUtranGANSSpositioningDataCodec binds MAP-LCS-DataTypes.UtranGANSSpositioningData.
func LCSUtranGANSSpositioningDataCodec() ValueCodec[BERValue[LCSUtranGANSSpositioningData]] {
	return octetValueCodec[LCSUtranGANSSpositioningData]("MAP-LCS-DataTypes.UtranGANSSpositioningData", "UtranGANSSpositioningData", []primitiveRule[LCSUtranGANSSpositioningData]{{invalid: func(value LCSUtranGANSSpositioningData) bool { return !(len(value) >= 1 && len(value) <= 9) }, description: "SIZE (1..9)", clause: "51.5", length: func(value LCSUtranGANSSpositioningData) int { return len(value) }}})
}

// LCSUtranAdditionalPositioningDataCodec binds MAP-LCS-DataTypes.UtranAdditionalPositioningData.
func LCSUtranAdditionalPositioningDataCodec() ValueCodec[BERValue[LCSUtranAdditionalPositioningData]] {
	return octetValueCodec[LCSUtranAdditionalPositioningData]("MAP-LCS-DataTypes.UtranAdditionalPositioningData", "UtranAdditionalPositioningData", []primitiveRule[LCSUtranAdditionalPositioningData]{{invalid: func(value LCSUtranAdditionalPositioningData) bool { return !(len(value) >= 1 && len(value) <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value LCSUtranAdditionalPositioningData) int { return len(value) }}})
}

// LCSUtranBaroPressureMeasCodec binds MAP-LCS-DataTypes.UtranBaroPressureMeas.
func LCSUtranBaroPressureMeasCodec() ValueCodec[BERValue[LCSUtranBaroPressureMeas]] {
	return integerValueCodec[LCSUtranBaroPressureMeas]("MAP-LCS-DataTypes.UtranBaroPressureMeas", "UtranBaroPressureMeas", []primitiveRule[LCSUtranBaroPressureMeas]{{invalid: func(value LCSUtranBaroPressureMeas) bool { return !(int64(value) >= 30000 && int64(value) <= 115000) }, description: "(30000..115000)", clause: "51.4", observed: func(value LCSUtranBaroPressureMeas) any { return int64(value) }}}, false)
}

// LCSUtranCivicAddressCodec binds MAP-LCS-DataTypes.UtranCivicAddress.
func LCSUtranCivicAddressCodec() ValueCodec[BERValue[LCSUtranCivicAddress]] {
	return octetValueCodec[LCSUtranCivicAddress]("MAP-LCS-DataTypes.UtranCivicAddress", "UtranCivicAddress", nil)
}

// LCSAddGeographicalInformationCodec binds MAP-LCS-DataTypes.Add-GeographicalInformation.
func LCSAddGeographicalInformationCodec() ValueCodec[BERValue[LCSAddGeographicalInformation]] {
	return octetValueCodec[LCSAddGeographicalInformation]("MAP-LCS-DataTypes.Add-GeographicalInformation", "Add-GeographicalInformation", []primitiveRule[LCSAddGeographicalInformation]{{invalid: func(value LCSAddGeographicalInformation) bool { return !(len(value) >= 1 && len(value) <= 91) }, description: "SIZE (1..91)", clause: "51.5", length: func(value LCSAddGeographicalInformation) int { return len(value) }}})
}

// LCSSubscriberLocationReportArgCodec binds MAP-LCS-DataTypes.SubscriberLocationReport-Arg.
func LCSSubscriberLocationReportArgCodec() ValueCodec[LCSSubscriberLocationReportArg] {
	return compositeValueCodec[LCSSubscriberLocationReportArg, *LCSSubscriberLocationReportArg]()
}

// LCSDeferredmtLrDataCodec binds MAP-LCS-DataTypes.Deferredmt-lrData.
func LCSDeferredmtLrDataCodec() ValueCodec[LCSDeferredmtLrData] {
	return compositeValueCodec[LCSDeferredmtLrData, *LCSDeferredmtLrData]()
}

// LCSLCSEventCodec binds MAP-LCS-DataTypes.LCS-Event.
func LCSLCSEventCodec() ValueCodec[BERValue[LCSLCSEvent]] {
	return integerValueCodec[LCSLCSEvent]("MAP-LCS-DataTypes.LCS-Event", "LCS-Event", nil, true)
}

// LCSTerminationCauseCodec binds MAP-LCS-DataTypes.TerminationCause.
func LCSTerminationCauseCodec() ValueCodec[BERValue[LCSTerminationCause]] {
	return integerValueCodec[LCSTerminationCause]("MAP-LCS-DataTypes.TerminationCause", "TerminationCause", nil, true)
}

// LCSSequenceNumberCodec binds MAP-LCS-DataTypes.SequenceNumber.
func LCSSequenceNumberCodec() ValueCodec[BERValue[LCSSequenceNumber]] {
	return integerValueCodec[LCSSequenceNumber]("MAP-LCS-DataTypes.SequenceNumber", "SequenceNumber", []primitiveRule[LCSSequenceNumber]{{invalid: func(value LCSSequenceNumber) bool { return !(int64(value) >= 1 && int64(value) <= 8639999) }, description: "(1..8639999)", clause: "51.4", observed: func(value LCSSequenceNumber) any { return int64(value) }}}, false)
}

// LCSServingNodeAddressCodec binds MAP-LCS-DataTypes.ServingNodeAddress.
func LCSServingNodeAddressCodec() ValueCodec[LCSServingNodeAddress] {
	return compositeValueCodec[LCSServingNodeAddress, *LCSServingNodeAddress]()
}

// LCSSubscriberLocationReportResCodec binds MAP-LCS-DataTypes.SubscriberLocationReport-Res.
func LCSSubscriberLocationReportResCodec() ValueCodec[LCSSubscriberLocationReportRes] {
	return compositeValueCodec[LCSSubscriberLocationReportRes, *LCSSubscriberLocationReportRes]()
}
