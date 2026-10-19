// Code generated from ASN.1. DO NOT EDIT.

package v21_map_ms_datatypes

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

// MSUpdateLocationArgCodec binds MAP-MS-DataTypes.UpdateLocationArg.
func MSUpdateLocationArgCodec() ValueCodec[MSUpdateLocationArg] {
	return compositeValueCodec[MSUpdateLocationArg, *MSUpdateLocationArg]()
}

// MSVLRCapabilityCodec binds MAP-MS-DataTypes.VLR-Capability.
func MSVLRCapabilityCodec() ValueCodec[MSVLRCapability] {
	return compositeValueCodec[MSVLRCapability, *MSVLRCapability]()
}

// MSSupportedRATTypesCodec binds MAP-MS-DataTypes.SupportedRAT-Types.
func MSSupportedRATTypesCodec() ValueCodec[BERValue[MSSupportedRATTypes]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedRAT-Types", "SupportedRAT-Types", []primitiveRule[MSSupportedRATTypes]{{invalid: func(value MSSupportedRATTypes) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value MSSupportedRATTypes) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// MSSuperChargerInfoCodec binds MAP-MS-DataTypes.SuperChargerInfo.
func MSSuperChargerInfoCodec() ValueCodec[MSSuperChargerInfo] {
	return compositeValueCodec[MSSuperChargerInfo, *MSSuperChargerInfo]()
}

// MSAgeIndicatorCodec binds MAP-MS-DataTypes.AgeIndicator.
func MSAgeIndicatorCodec() ValueCodec[BERValue[MSAgeIndicator]] {
	return octetValueCodec[MSAgeIndicator]("MAP-MS-DataTypes.AgeIndicator", "AgeIndicator", []primitiveRule[MSAgeIndicator]{{invalid: func(value MSAgeIndicator) bool { return !(len(value) >= 1 && len(value) <= 6) }, description: "SIZE (1..6)", clause: "51.5", length: func(value MSAgeIndicator) int { return len(value) }}})
}

// MSISTSupportIndicatorCodec binds MAP-MS-DataTypes.IST-SupportIndicator.
func MSISTSupportIndicatorCodec() ValueCodec[BERValue[MSISTSupportIndicator]] {
	return integerValueCodec[MSISTSupportIndicator]("MAP-MS-DataTypes.IST-SupportIndicator", "IST-SupportIndicator", nil, true)
}

// MSSupportedLCSCapabilitySetsCodec binds MAP-MS-DataTypes.SupportedLCS-CapabilitySets.
func MSSupportedLCSCapabilitySetsCodec() ValueCodec[BERValue[MSSupportedLCSCapabilitySets]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedLCS-CapabilitySets", "SupportedLCS-CapabilitySets", []primitiveRule[MSSupportedLCSCapabilitySets]{{invalid: func(value MSSupportedLCSCapabilitySets) bool { return !(value.BitLength >= 2 && value.BitLength <= 16) }, description: "SIZE (2..16)", clause: "51.5", length: func(value MSSupportedLCSCapabilitySets) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}})
}

// MSUpdateLocationResCodec binds MAP-MS-DataTypes.UpdateLocationRes.
func MSUpdateLocationResCodec() ValueCodec[MSUpdateLocationRes] {
	return compositeValueCodec[MSUpdateLocationRes, *MSUpdateLocationRes]()
}

// MSADDInfoCodec binds MAP-MS-DataTypes.ADD-Info.
func MSADDInfoCodec() ValueCodec[MSADDInfo] {
	return compositeValueCodec[MSADDInfo, *MSADDInfo]()
}

// MSPagingAreaCodec binds MAP-MS-DataTypes.PagingArea.
func MSPagingAreaCodec() ValueCodec[MSPagingArea] {
	return pointerValueCodec(UnmarshalBERMSPagingArea, MarshalBERMSPagingArea, MarshalDERMSPagingArea)
}

// MSLocationAreaCodec binds MAP-MS-DataTypes.LocationArea.
func MSLocationAreaCodec() ValueCodec[MSLocationArea] {
	return compositeValueCodec[MSLocationArea, *MSLocationArea]()
}

// MSLACCodec binds MAP-MS-DataTypes.LAC.
func MSLACCodec() ValueCodec[BERValue[MSLAC]] {
	return octetValueCodec[MSLAC]("MAP-MS-DataTypes.LAC", "LAC", []primitiveRule[MSLAC]{{invalid: func(value MSLAC) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value MSLAC) int { return len(value) }}})
}

// MSCancelLocationArgCodec binds MAP-MS-DataTypes.CancelLocationArg.
func MSCancelLocationArgCodec() ValueCodec[MSCancelLocationArg] {
	return compositeValueCodec[MSCancelLocationArg, *MSCancelLocationArg]()
}

// MSTypeOfUpdateCodec binds MAP-MS-DataTypes.TypeOfUpdate.
func MSTypeOfUpdateCodec() ValueCodec[BERValue[MSTypeOfUpdate]] {
	return integerValueCodec[MSTypeOfUpdate]("MAP-MS-DataTypes.TypeOfUpdate", "TypeOfUpdate", nil, true)
}

// MSCancellationTypeCodec binds MAP-MS-DataTypes.CancellationType.
func MSCancellationTypeCodec() ValueCodec[BERValue[MSCancellationType]] {
	return integerValueCodec[MSCancellationType]("MAP-MS-DataTypes.CancellationType", "CancellationType", nil, true)
}

// MSCancelLocationResCodec binds MAP-MS-DataTypes.CancelLocationRes.
func MSCancelLocationResCodec() ValueCodec[MSCancelLocationRes] {
	return compositeValueCodec[MSCancelLocationRes, *MSCancelLocationRes]()
}

// MSPurgeMSArgCodec binds MAP-MS-DataTypes.PurgeMS-Arg.
func MSPurgeMSArgCodec() ValueCodec[MSPurgeMSArg] {
	return compositeValueCodec[MSPurgeMSArg, *MSPurgeMSArg]()
}

// MSPurgeMSResCodec binds MAP-MS-DataTypes.PurgeMS-Res.
func MSPurgeMSResCodec() ValueCodec[MSPurgeMSRes] {
	return compositeValueCodec[MSPurgeMSRes, *MSPurgeMSRes]()
}

// MSSendIdentificationArgCodec binds MAP-MS-DataTypes.SendIdentificationArg.
func MSSendIdentificationArgCodec() ValueCodec[MSSendIdentificationArg] {
	return compositeValueCodec[MSSendIdentificationArg, *MSSendIdentificationArg]()
}

// MSHopCounterCodec binds MAP-MS-DataTypes.HopCounter.
func MSHopCounterCodec() ValueCodec[BERValue[MSHopCounter]] {
	return integerValueCodec[MSHopCounter]("MAP-MS-DataTypes.HopCounter", "HopCounter", []primitiveRule[MSHopCounter]{{invalid: func(value MSHopCounter) bool { return !(int64(value) >= 0 && int64(value) <= 3) }, description: "(0..3)", clause: "51.4", observed: func(value MSHopCounter) any { return int64(value) }}}, false)
}

// MSSendIdentificationResCodec binds MAP-MS-DataTypes.SendIdentificationRes.
func MSSendIdentificationResCodec() ValueCodec[MSSendIdentificationRes] {
	return compositeValueCodec[MSSendIdentificationRes, *MSSendIdentificationRes]()
}

// MSAuthenticationSetListCodec binds MAP-MS-DataTypes.AuthenticationSetList.
func MSAuthenticationSetListCodec() ValueCodec[MSAuthenticationSetList] {
	return compositeValueCodec[MSAuthenticationSetList, *MSAuthenticationSetList]()
}

// MSTripletListCodec binds MAP-MS-DataTypes.TripletList.
func MSTripletListCodec() ValueCodec[MSTripletList] {
	return pointerValueCodec(UnmarshalBERMSTripletList, MarshalBERMSTripletList, MarshalDERMSTripletList)
}

// MSQuintupletListCodec binds MAP-MS-DataTypes.QuintupletList.
func MSQuintupletListCodec() ValueCodec[MSQuintupletList] {
	return pointerValueCodec(UnmarshalBERMSQuintupletList, MarshalBERMSQuintupletList, MarshalDERMSQuintupletList)
}

// MSAuthenticationTripletCodec binds MAP-MS-DataTypes.AuthenticationTriplet.
func MSAuthenticationTripletCodec() ValueCodec[MSAuthenticationTriplet] {
	return compositeValueCodec[MSAuthenticationTriplet, *MSAuthenticationTriplet]()
}

// MSAuthenticationQuintupletCodec binds MAP-MS-DataTypes.AuthenticationQuintuplet.
func MSAuthenticationQuintupletCodec() ValueCodec[MSAuthenticationQuintuplet] {
	return compositeValueCodec[MSAuthenticationQuintuplet, *MSAuthenticationQuintuplet]()
}

// MSCurrentSecurityContextCodec binds MAP-MS-DataTypes.CurrentSecurityContext.
func MSCurrentSecurityContextCodec() ValueCodec[MSCurrentSecurityContext] {
	return compositeValueCodec[MSCurrentSecurityContext, *MSCurrentSecurityContext]()
}

// MSGSMSecurityContextDataCodec binds MAP-MS-DataTypes.GSM-SecurityContextData.
func MSGSMSecurityContextDataCodec() ValueCodec[MSGSMSecurityContextData] {
	return compositeValueCodec[MSGSMSecurityContextData, *MSGSMSecurityContextData]()
}

// MSUMTSSecurityContextDataCodec binds MAP-MS-DataTypes.UMTS-SecurityContextData.
func MSUMTSSecurityContextDataCodec() ValueCodec[MSUMTSSecurityContextData] {
	return compositeValueCodec[MSUMTSSecurityContextData, *MSUMTSSecurityContextData]()
}

// MSRANDCodec binds MAP-MS-DataTypes.RAND.
func MSRANDCodec() ValueCodec[BERValue[MSRAND]] {
	return octetValueCodec[MSRAND]("MAP-MS-DataTypes.RAND", "RAND", []primitiveRule[MSRAND]{{invalid: func(value MSRAND) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value MSRAND) int { return len(value) }}})
}

// MSSRESCodec binds MAP-MS-DataTypes.SRES.
func MSSRESCodec() ValueCodec[BERValue[MSSRES]] {
	return octetValueCodec[MSSRES]("MAP-MS-DataTypes.SRES", "SRES", []primitiveRule[MSSRES]{{invalid: func(value MSSRES) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value MSSRES) int { return len(value) }}})
}

// MSKcCodec binds MAP-MS-DataTypes.Kc.
func MSKcCodec() ValueCodec[BERValue[MSKc]] {
	return octetValueCodec[MSKc]("MAP-MS-DataTypes.Kc", "Kc", []primitiveRule[MSKc]{{invalid: func(value MSKc) bool { return !(len(value) == 8) }, description: "SIZE (8)", clause: "51.5", length: func(value MSKc) int { return len(value) }}})
}

// MSXRESCodec binds MAP-MS-DataTypes.XRES.
func MSXRESCodec() ValueCodec[BERValue[MSXRES]] {
	return octetValueCodec[MSXRES]("MAP-MS-DataTypes.XRES", "XRES", []primitiveRule[MSXRES]{{invalid: func(value MSXRES) bool { return !(len(value) >= 4 && len(value) <= 16) }, description: "SIZE (4..16)", clause: "51.5", length: func(value MSXRES) int { return len(value) }}})
}

// MSCKCodec binds MAP-MS-DataTypes.CK.
func MSCKCodec() ValueCodec[BERValue[MSCK]] {
	return octetValueCodec[MSCK]("MAP-MS-DataTypes.CK", "CK", []primitiveRule[MSCK]{{invalid: func(value MSCK) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value MSCK) int { return len(value) }}})
}

// MSIKCodec binds MAP-MS-DataTypes.IK.
func MSIKCodec() ValueCodec[BERValue[MSIK]] {
	return octetValueCodec[MSIK]("MAP-MS-DataTypes.IK", "IK", []primitiveRule[MSIK]{{invalid: func(value MSIK) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value MSIK) int { return len(value) }}})
}

// MSAUTNCodec binds MAP-MS-DataTypes.AUTN.
func MSAUTNCodec() ValueCodec[BERValue[MSAUTN]] {
	return octetValueCodec[MSAUTN]("MAP-MS-DataTypes.AUTN", "AUTN", []primitiveRule[MSAUTN]{{invalid: func(value MSAUTN) bool { return !(len(value) == 16) }, description: "SIZE (16)", clause: "51.5", length: func(value MSAUTN) int { return len(value) }}})
}

// MSAUTSCodec binds MAP-MS-DataTypes.AUTS.
func MSAUTSCodec() ValueCodec[BERValue[MSAUTS]] {
	return octetValueCodec[MSAUTS]("MAP-MS-DataTypes.AUTS", "AUTS", []primitiveRule[MSAUTS]{{invalid: func(value MSAUTS) bool { return !(len(value) == 14) }, description: "SIZE (14)", clause: "51.5", length: func(value MSAUTS) int { return len(value) }}})
}

// MSCksnCodec binds MAP-MS-DataTypes.Cksn.
func MSCksnCodec() ValueCodec[BERValue[MSCksn]] {
	return octetValueCodec[MSCksn]("MAP-MS-DataTypes.Cksn", "Cksn", []primitiveRule[MSCksn]{{invalid: func(value MSCksn) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSCksn) int { return len(value) }}})
}

// MSKSICodec binds MAP-MS-DataTypes.KSI.
func MSKSICodec() ValueCodec[BERValue[MSKSI]] {
	return octetValueCodec[MSKSI]("MAP-MS-DataTypes.KSI", "KSI", []primitiveRule[MSKSI]{{invalid: func(value MSKSI) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSKSI) int { return len(value) }}})
}

// MSAuthenticationFailureReportArgCodec binds MAP-MS-DataTypes.AuthenticationFailureReportArg.
func MSAuthenticationFailureReportArgCodec() ValueCodec[MSAuthenticationFailureReportArg] {
	return compositeValueCodec[MSAuthenticationFailureReportArg, *MSAuthenticationFailureReportArg]()
}

// MSAccessTypeCodec binds MAP-MS-DataTypes.AccessType.
func MSAccessTypeCodec() ValueCodec[BERValue[MSAccessType]] {
	return integerValueCodec[MSAccessType]("MAP-MS-DataTypes.AccessType", "AccessType", nil, true)
}

// MSAuthenticationFailureReportResCodec binds MAP-MS-DataTypes.AuthenticationFailureReportRes.
func MSAuthenticationFailureReportResCodec() ValueCodec[MSAuthenticationFailureReportRes] {
	return compositeValueCodec[MSAuthenticationFailureReportRes, *MSAuthenticationFailureReportRes]()
}

// MSFailureCauseCodec binds MAP-MS-DataTypes.FailureCause.
func MSFailureCauseCodec() ValueCodec[BERValue[MSFailureCause]] {
	return integerValueCodec[MSFailureCause]("MAP-MS-DataTypes.FailureCause", "FailureCause", []primitiveRule[MSFailureCause]{{invalid: func(value MSFailureCause) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSFailureCause) any { return int64(value) }}}, true)
}

// MSUpdateGprsLocationArgCodec binds MAP-MS-DataTypes.UpdateGprsLocationArg.
func MSUpdateGprsLocationArgCodec() ValueCodec[MSUpdateGprsLocationArg] {
	return compositeValueCodec[MSUpdateGprsLocationArg, *MSUpdateGprsLocationArg]()
}

// MSSMSRegisterRequestCodec binds MAP-MS-DataTypes.SMSRegisterRequest.
func MSSMSRegisterRequestCodec() ValueCodec[BERValue[MSSMSRegisterRequest]] {
	return integerValueCodec[MSSMSRegisterRequest]("MAP-MS-DataTypes.SMSRegisterRequest", "SMSRegisterRequest", nil, true)
}

// MSUsedRATTypeCodec binds MAP-MS-DataTypes.Used-RAT-Type.
func MSUsedRATTypeCodec() ValueCodec[BERValue[MSUsedRATType]] {
	return integerValueCodec[MSUsedRATType]("MAP-MS-DataTypes.Used-RAT-Type", "Used-RAT-Type", nil, true)
}

// MSEPSInfoCodec binds MAP-MS-DataTypes.EPS-Info.
func MSEPSInfoCodec() ValueCodec[MSEPSInfo] {
	return compositeValueCodec[MSEPSInfo, *MSEPSInfo]()
}

// MSPDNGWUpdateCodec binds MAP-MS-DataTypes.PDN-GW-Update.
func MSPDNGWUpdateCodec() ValueCodec[MSPDNGWUpdate] {
	return compositeValueCodec[MSPDNGWUpdate, *MSPDNGWUpdate]()
}

// MSISRInformationCodec binds MAP-MS-DataTypes.ISR-Information.
func MSISRInformationCodec() ValueCodec[BERValue[MSISRInformation]] {
	return bitValueCodec("MAP-MS-DataTypes.ISR-Information", "ISR-Information", []primitiveRule[MSISRInformation]{{invalid: func(value MSISRInformation) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value MSISRInformation) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// MSSGSNCapabilityCodec binds MAP-MS-DataTypes.SGSN-Capability.
func MSSGSNCapabilityCodec() ValueCodec[MSSGSNCapability] {
	return compositeValueCodec[MSSGSNCapability, *MSSGSNCapability]()
}

// MSSupportedFeaturesCodec binds MAP-MS-DataTypes.SupportedFeatures.
func MSSupportedFeaturesCodec() ValueCodec[BERValue[MSSupportedFeatures]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedFeatures", "SupportedFeatures", []primitiveRule[MSSupportedFeatures]{{invalid: func(value MSSupportedFeatures) bool { return !(value.BitLength >= 26 && value.BitLength <= 40) }, description: "SIZE (26..40)", clause: "51.5", length: func(value MSSupportedFeatures) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 26, Max: 40}}})
}

// MSExtSupportedFeaturesCodec binds MAP-MS-DataTypes.Ext-SupportedFeatures.
func MSExtSupportedFeaturesCodec() ValueCodec[BERValue[MSExtSupportedFeatures]] {
	return bitValueCodec("MAP-MS-DataTypes.Ext-SupportedFeatures", "Ext-SupportedFeatures", []primitiveRule[MSExtSupportedFeatures]{{invalid: func(value MSExtSupportedFeatures) bool { return !(value.BitLength >= 1 && value.BitLength <= 40) }, description: "SIZE (1..40)", clause: "51.5", length: func(value MSExtSupportedFeatures) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 40}}})
}

// MSUESRVCCCapabilityCodec binds MAP-MS-DataTypes.UE-SRVCC-Capability.
func MSUESRVCCCapabilityCodec() ValueCodec[BERValue[MSUESRVCCCapability]] {
	return integerValueCodec[MSUESRVCCCapability]("MAP-MS-DataTypes.UE-SRVCC-Capability", "UE-SRVCC-Capability", nil, true)
}

// MSUpdateGprsLocationResCodec binds MAP-MS-DataTypes.UpdateGprsLocationRes.
func MSUpdateGprsLocationResCodec() ValueCodec[MSUpdateGprsLocationRes] {
	return compositeValueCodec[MSUpdateGprsLocationRes, *MSUpdateGprsLocationRes]()
}

// MSEPLMNListCodec binds MAP-MS-DataTypes.EPLMN-List.
func MSEPLMNListCodec() ValueCodec[MSEPLMNList] {
	return pointerValueCodec(UnmarshalBERMSEPLMNList, MarshalBERMSEPLMNList, MarshalDERMSEPLMNList)
}

// MSAdjacentPLMNListCodec binds MAP-MS-DataTypes.AdjacentPLMN-List.
func MSAdjacentPLMNListCodec() ValueCodec[MSAdjacentPLMNList] {
	return pointerValueCodec(UnmarshalBERMSAdjacentPLMNList, MarshalBERMSAdjacentPLMNList, MarshalDERMSAdjacentPLMNList)
}

// MSForwardAccessSignallingArgCodec binds MAP-MS-DataTypes.ForwardAccessSignalling-Arg.
func MSForwardAccessSignallingArgCodec() ValueCodec[MSForwardAccessSignallingArg] {
	return compositeValueCodec[MSForwardAccessSignallingArg, *MSForwardAccessSignallingArg]()
}

// MSAllowedGSMAlgorithmsCodec binds MAP-MS-DataTypes.AllowedGSM-Algorithms.
func MSAllowedGSMAlgorithmsCodec() ValueCodec[BERValue[MSAllowedGSMAlgorithms]] {
	return octetValueCodec[MSAllowedGSMAlgorithms]("MAP-MS-DataTypes.AllowedGSM-Algorithms", "AllowedGSM-Algorithms", []primitiveRule[MSAllowedGSMAlgorithms]{{invalid: func(value MSAllowedGSMAlgorithms) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSAllowedGSMAlgorithms) int { return len(value) }}})
}

// MSAllowedUMTSAlgorithmsCodec binds MAP-MS-DataTypes.AllowedUMTS-Algorithms.
func MSAllowedUMTSAlgorithmsCodec() ValueCodec[MSAllowedUMTSAlgorithms] {
	return compositeValueCodec[MSAllowedUMTSAlgorithms, *MSAllowedUMTSAlgorithms]()
}

// MSPermittedIntegrityProtectionAlgorithmsCodec binds MAP-MS-DataTypes.PermittedIntegrityProtectionAlgorithms.
func MSPermittedIntegrityProtectionAlgorithmsCodec() ValueCodec[BERValue[MSPermittedIntegrityProtectionAlgorithms]] {
	return octetValueCodec[MSPermittedIntegrityProtectionAlgorithms]("MAP-MS-DataTypes.PermittedIntegrityProtectionAlgorithms", "PermittedIntegrityProtectionAlgorithms", []primitiveRule[MSPermittedIntegrityProtectionAlgorithms]{{invalid: func(value MSPermittedIntegrityProtectionAlgorithms) bool {
		return !(len(value) >= 1 && len(value) <= 9)
	}, description: "SIZE (1..9)", clause: "51.5", length: func(value MSPermittedIntegrityProtectionAlgorithms) int { return len(value) }}})
}

// MSPermittedEncryptionAlgorithmsCodec binds MAP-MS-DataTypes.PermittedEncryptionAlgorithms.
func MSPermittedEncryptionAlgorithmsCodec() ValueCodec[BERValue[MSPermittedEncryptionAlgorithms]] {
	return octetValueCodec[MSPermittedEncryptionAlgorithms]("MAP-MS-DataTypes.PermittedEncryptionAlgorithms", "PermittedEncryptionAlgorithms", []primitiveRule[MSPermittedEncryptionAlgorithms]{{invalid: func(value MSPermittedEncryptionAlgorithms) bool { return !(len(value) >= 1 && len(value) <= 9) }, description: "SIZE (1..9)", clause: "51.5", length: func(value MSPermittedEncryptionAlgorithms) int { return len(value) }}})
}

// MSKeyStatusCodec binds MAP-MS-DataTypes.KeyStatus.
func MSKeyStatusCodec() ValueCodec[BERValue[MSKeyStatus]] {
	return integerValueCodec[MSKeyStatus]("MAP-MS-DataTypes.KeyStatus", "KeyStatus", nil, true)
}

// MSPrepareHOArgCodec binds MAP-MS-DataTypes.PrepareHO-Arg.
func MSPrepareHOArgCodec() ValueCodec[MSPrepareHOArg] {
	return compositeValueCodec[MSPrepareHOArg, *MSPrepareHOArg]()
}

// MSLCLSGlobalCallReferenceCodec binds MAP-MS-DataTypes.LCLS-GlobalCallReference.
func MSLCLSGlobalCallReferenceCodec() ValueCodec[BERValue[MSLCLSGlobalCallReference]] {
	return octetValueCodec[MSLCLSGlobalCallReference]("MAP-MS-DataTypes.LCLS-GlobalCallReference", "LCLS-GlobalCallReference", []primitiveRule[MSLCLSGlobalCallReference]{{invalid: func(value MSLCLSGlobalCallReference) bool { return !(len(value) >= 13 && len(value) <= 15) }, description: "SIZE (13..15)", clause: "51.5", length: func(value MSLCLSGlobalCallReference) int { return len(value) }}})
}

// MSLCLSNegotiationCodec binds MAP-MS-DataTypes.LCLS-Negotiation.
func MSLCLSNegotiationCodec() ValueCodec[BERValue[MSLCLSNegotiation]] {
	return bitValueCodec("MAP-MS-DataTypes.LCLS-Negotiation", "LCLS-Negotiation", []primitiveRule[MSLCLSNegotiation]{{invalid: func(value MSLCLSNegotiation) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value MSLCLSNegotiation) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// MSLCLSConfigurationPreferenceCodec binds MAP-MS-DataTypes.LCLS-ConfigurationPreference.
func MSLCLSConfigurationPreferenceCodec() ValueCodec[BERValue[MSLCLSConfigurationPreference]] {
	return bitValueCodec("MAP-MS-DataTypes.LCLS-ConfigurationPreference", "LCLS-ConfigurationPreference", []primitiveRule[MSLCLSConfigurationPreference]{{invalid: func(value MSLCLSConfigurationPreference) bool { return !(value.BitLength >= 4 && value.BitLength <= 8) }, description: "SIZE (4..8)", clause: "51.5", length: func(value MSLCLSConfigurationPreference) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 8}}})
}

// MSBSSMAPServiceHandoverListCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandoverList.
func MSBSSMAPServiceHandoverListCodec() ValueCodec[MSBSSMAPServiceHandoverList] {
	return pointerValueCodec(UnmarshalBERMSBSSMAPServiceHandoverList, MarshalBERMSBSSMAPServiceHandoverList, MarshalDERMSBSSMAPServiceHandoverList)
}

// MSBSSMAPServiceHandoverInfoCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandoverInfo.
func MSBSSMAPServiceHandoverInfoCodec() ValueCodec[MSBSSMAPServiceHandoverInfo] {
	return compositeValueCodec[MSBSSMAPServiceHandoverInfo, *MSBSSMAPServiceHandoverInfo]()
}

// MSBSSMAPServiceHandoverCodec binds MAP-MS-DataTypes.BSSMAP-ServiceHandover.
func MSBSSMAPServiceHandoverCodec() ValueCodec[BERValue[MSBSSMAPServiceHandover]] {
	return octetValueCodec[MSBSSMAPServiceHandover]("MAP-MS-DataTypes.BSSMAP-ServiceHandover", "BSSMAP-ServiceHandover", []primitiveRule[MSBSSMAPServiceHandover]{{invalid: func(value MSBSSMAPServiceHandover) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSBSSMAPServiceHandover) int { return len(value) }}})
}

// MSRANAPServiceHandoverCodec binds MAP-MS-DataTypes.RANAP-ServiceHandover.
func MSRANAPServiceHandoverCodec() ValueCodec[BERValue[MSRANAPServiceHandover]] {
	return octetValueCodec[MSRANAPServiceHandover]("MAP-MS-DataTypes.RANAP-ServiceHandover", "RANAP-ServiceHandover", []primitiveRule[MSRANAPServiceHandover]{{invalid: func(value MSRANAPServiceHandover) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSRANAPServiceHandover) int { return len(value) }}})
}

// MSRadioResourceListCodec binds MAP-MS-DataTypes.RadioResourceList.
func MSRadioResourceListCodec() ValueCodec[MSRadioResourceList] {
	return pointerValueCodec(UnmarshalBERMSRadioResourceList, MarshalBERMSRadioResourceList, MarshalDERMSRadioResourceList)
}

// MSRadioResourceCodec binds MAP-MS-DataTypes.RadioResource.
func MSRadioResourceCodec() ValueCodec[MSRadioResource] {
	return compositeValueCodec[MSRadioResource, *MSRadioResource]()
}

// MSPrepareHOResCodec binds MAP-MS-DataTypes.PrepareHO-Res.
func MSPrepareHOResCodec() ValueCodec[MSPrepareHORes] {
	return compositeValueCodec[MSPrepareHORes, *MSPrepareHORes]()
}

// MSSelectedUMTSAlgorithmsCodec binds MAP-MS-DataTypes.SelectedUMTS-Algorithms.
func MSSelectedUMTSAlgorithmsCodec() ValueCodec[MSSelectedUMTSAlgorithms] {
	return compositeValueCodec[MSSelectedUMTSAlgorithms, *MSSelectedUMTSAlgorithms]()
}

// MSChosenIntegrityProtectionAlgorithmCodec binds MAP-MS-DataTypes.ChosenIntegrityProtectionAlgorithm.
func MSChosenIntegrityProtectionAlgorithmCodec() ValueCodec[BERValue[MSChosenIntegrityProtectionAlgorithm]] {
	return octetValueCodec[MSChosenIntegrityProtectionAlgorithm]("MAP-MS-DataTypes.ChosenIntegrityProtectionAlgorithm", "ChosenIntegrityProtectionAlgorithm", []primitiveRule[MSChosenIntegrityProtectionAlgorithm]{{invalid: func(value MSChosenIntegrityProtectionAlgorithm) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSChosenIntegrityProtectionAlgorithm) int { return len(value) }}})
}

// MSChosenEncryptionAlgorithmCodec binds MAP-MS-DataTypes.ChosenEncryptionAlgorithm.
func MSChosenEncryptionAlgorithmCodec() ValueCodec[BERValue[MSChosenEncryptionAlgorithm]] {
	return octetValueCodec[MSChosenEncryptionAlgorithm]("MAP-MS-DataTypes.ChosenEncryptionAlgorithm", "ChosenEncryptionAlgorithm", []primitiveRule[MSChosenEncryptionAlgorithm]{{invalid: func(value MSChosenEncryptionAlgorithm) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSChosenEncryptionAlgorithm) int { return len(value) }}})
}

// MSChosenRadioResourceInformationCodec binds MAP-MS-DataTypes.ChosenRadioResourceInformation.
func MSChosenRadioResourceInformationCodec() ValueCodec[MSChosenRadioResourceInformation] {
	return compositeValueCodec[MSChosenRadioResourceInformation, *MSChosenRadioResourceInformation]()
}

// MSChosenChannelInfoCodec binds MAP-MS-DataTypes.ChosenChannelInfo.
func MSChosenChannelInfoCodec() ValueCodec[BERValue[MSChosenChannelInfo]] {
	return octetValueCodec[MSChosenChannelInfo]("MAP-MS-DataTypes.ChosenChannelInfo", "ChosenChannelInfo", []primitiveRule[MSChosenChannelInfo]{{invalid: func(value MSChosenChannelInfo) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSChosenChannelInfo) int { return len(value) }}})
}

// MSChosenSpeechVersionCodec binds MAP-MS-DataTypes.ChosenSpeechVersion.
func MSChosenSpeechVersionCodec() ValueCodec[BERValue[MSChosenSpeechVersion]] {
	return octetValueCodec[MSChosenSpeechVersion]("MAP-MS-DataTypes.ChosenSpeechVersion", "ChosenSpeechVersion", []primitiveRule[MSChosenSpeechVersion]{{invalid: func(value MSChosenSpeechVersion) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSChosenSpeechVersion) int { return len(value) }}})
}

// MSPrepareSubsequentHOArgCodec binds MAP-MS-DataTypes.PrepareSubsequentHO-Arg.
func MSPrepareSubsequentHOArgCodec() ValueCodec[MSPrepareSubsequentHOArg] {
	return compositeValueCodec[MSPrepareSubsequentHOArg, *MSPrepareSubsequentHOArg]()
}

// MSPrepareSubsequentHOResCodec binds MAP-MS-DataTypes.PrepareSubsequentHO-Res.
func MSPrepareSubsequentHOResCodec() ValueCodec[MSPrepareSubsequentHORes] {
	return compositeValueCodec[MSPrepareSubsequentHORes, *MSPrepareSubsequentHORes]()
}

// MSProcessAccessSignallingArgCodec binds MAP-MS-DataTypes.ProcessAccessSignalling-Arg.
func MSProcessAccessSignallingArgCodec() ValueCodec[MSProcessAccessSignallingArg] {
	return compositeValueCodec[MSProcessAccessSignallingArg, *MSProcessAccessSignallingArg]()
}

// MSAoIPCodecsListCodec binds MAP-MS-DataTypes.AoIPCodecsList.
func MSAoIPCodecsListCodec() ValueCodec[MSAoIPCodecsList] {
	return compositeValueCodec[MSAoIPCodecsList, *MSAoIPCodecsList]()
}

// MSAoIPCodecCodec binds MAP-MS-DataTypes.AoIPCodec.
func MSAoIPCodecCodec() ValueCodec[BERValue[MSAoIPCodec]] {
	return octetValueCodec[MSAoIPCodec]("MAP-MS-DataTypes.AoIPCodec", "AoIPCodec", []primitiveRule[MSAoIPCodec]{{invalid: func(value MSAoIPCodec) bool { return !(len(value) >= 1 && len(value) <= 3) }, description: "SIZE (1..3)", clause: "51.5", length: func(value MSAoIPCodec) int { return len(value) }}})
}

// MSSupportedCodecsListCodec binds MAP-MS-DataTypes.SupportedCodecsList.
func MSSupportedCodecsListCodec() ValueCodec[MSSupportedCodecsList] {
	return compositeValueCodec[MSSupportedCodecsList, *MSSupportedCodecsList]()
}

// MSCodecListCodec binds MAP-MS-DataTypes.CodecList.
func MSCodecListCodec() ValueCodec[MSCodecList] {
	return compositeValueCodec[MSCodecList, *MSCodecList]()
}

// MSCodecCodec binds MAP-MS-DataTypes.Codec.
func MSCodecCodec() ValueCodec[BERValue[MSCodec]] {
	return octetValueCodec[MSCodec]("MAP-MS-DataTypes.Codec", "Codec", []primitiveRule[MSCodec]{{invalid: func(value MSCodec) bool { return !(len(value) >= 1 && len(value) <= 4) }, description: "SIZE (1..4)", clause: "51.5", length: func(value MSCodec) int { return len(value) }}})
}

// MSGERANClassmarkCodec binds MAP-MS-DataTypes.GERAN-Classmark.
func MSGERANClassmarkCodec() ValueCodec[BERValue[MSGERANClassmark]] {
	return octetValueCodec[MSGERANClassmark]("MAP-MS-DataTypes.GERAN-Classmark", "GERAN-Classmark", []primitiveRule[MSGERANClassmark]{{invalid: func(value MSGERANClassmark) bool { return !(len(value) >= 2 && len(value) <= 87) }, description: "SIZE (2..87)", clause: "51.5", length: func(value MSGERANClassmark) int { return len(value) }}})
}

// MSSelectedGSMAlgorithmCodec binds MAP-MS-DataTypes.SelectedGSM-Algorithm.
func MSSelectedGSMAlgorithmCodec() ValueCodec[BERValue[MSSelectedGSMAlgorithm]] {
	return octetValueCodec[MSSelectedGSMAlgorithm]("MAP-MS-DataTypes.SelectedGSM-Algorithm", "SelectedGSM-Algorithm", []primitiveRule[MSSelectedGSMAlgorithm]{{invalid: func(value MSSelectedGSMAlgorithm) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSSelectedGSMAlgorithm) int { return len(value) }}})
}

// MSSendEndSignalArgCodec binds MAP-MS-DataTypes.SendEndSignal-Arg.
func MSSendEndSignalArgCodec() ValueCodec[MSSendEndSignalArg] {
	return compositeValueCodec[MSSendEndSignalArg, *MSSendEndSignalArg]()
}

// MSSendEndSignalResCodec binds MAP-MS-DataTypes.SendEndSignal-Res.
func MSSendEndSignalResCodec() ValueCodec[MSSendEndSignalRes] {
	return compositeValueCodec[MSSendEndSignalRes, *MSSendEndSignalRes]()
}

// MSRNCIdCodec binds MAP-MS-DataTypes.RNCId.
func MSRNCIdCodec() ValueCodec[BERValue[MSRNCId]] {
	return octetValueCodec[MSRNCId]("MAP-MS-DataTypes.RNCId", "RNCId", []primitiveRule[MSRNCId]{{invalid: func(value MSRNCId) bool { return !(len(value) == 7) }, description: "SIZE (7)", clause: "51.5", length: func(value MSRNCId) int { return len(value) }}})
}

// MSRelocationNumberListCodec binds MAP-MS-DataTypes.RelocationNumberList.
func MSRelocationNumberListCodec() ValueCodec[MSRelocationNumberList] {
	return pointerValueCodec(UnmarshalBERMSRelocationNumberList, MarshalBERMSRelocationNumberList, MarshalDERMSRelocationNumberList)
}

// MSMulticallBearerInfoCodec binds MAP-MS-DataTypes.MulticallBearerInfo.
func MSMulticallBearerInfoCodec() ValueCodec[BERValue[MSMulticallBearerInfo]] {
	return integerValueCodec[MSMulticallBearerInfo]("MAP-MS-DataTypes.MulticallBearerInfo", "MulticallBearerInfo", []primitiveRule[MSMulticallBearerInfo]{{invalid: func(value MSMulticallBearerInfo) bool { return !(int64(value) >= 1 && int64(value) <= 7) }, description: "(1..7)", clause: "51.4", observed: func(value MSMulticallBearerInfo) any { return int64(value) }}}, false)
}

// MSRelocationNumberCodec binds MAP-MS-DataTypes.RelocationNumber.
func MSRelocationNumberCodec() ValueCodec[MSRelocationNumber] {
	return compositeValueCodec[MSRelocationNumber, *MSRelocationNumber]()
}

// MSRABIdCodec binds MAP-MS-DataTypes.RAB-Id.
func MSRABIdCodec() ValueCodec[BERValue[MSRABId]] {
	return integerValueCodec[MSRABId]("MAP-MS-DataTypes.RAB-Id", "RAB-Id", []primitiveRule[MSRABId]{{invalid: func(value MSRABId) bool { return !(int64(value) >= 1 && int64(value) <= 255) }, description: "(1..255)", clause: "51.4", observed: func(value MSRABId) any { return int64(value) }}}, false)
}

// MSRadioResourceInformationCodec binds MAP-MS-DataTypes.RadioResourceInformation.
func MSRadioResourceInformationCodec() ValueCodec[BERValue[MSRadioResourceInformation]] {
	return octetValueCodec[MSRadioResourceInformation]("MAP-MS-DataTypes.RadioResourceInformation", "RadioResourceInformation", []primitiveRule[MSRadioResourceInformation]{{invalid: func(value MSRadioResourceInformation) bool { return !(len(value) >= 3 && len(value) <= 13) }, description: "SIZE (3..13)", clause: "51.5", length: func(value MSRadioResourceInformation) int { return len(value) }}})
}

// MSIntegrityProtectionInformationCodec binds MAP-MS-DataTypes.IntegrityProtectionInformation.
func MSIntegrityProtectionInformationCodec() ValueCodec[BERValue[MSIntegrityProtectionInformation]] {
	return octetValueCodec[MSIntegrityProtectionInformation]("MAP-MS-DataTypes.IntegrityProtectionInformation", "IntegrityProtectionInformation", []primitiveRule[MSIntegrityProtectionInformation]{{invalid: func(value MSIntegrityProtectionInformation) bool { return !(len(value) >= 18 && len(value) <= 100) }, description: "SIZE (18..100)", clause: "51.5", length: func(value MSIntegrityProtectionInformation) int { return len(value) }}})
}

// MSEncryptionInformationCodec binds MAP-MS-DataTypes.EncryptionInformation.
func MSEncryptionInformationCodec() ValueCodec[BERValue[MSEncryptionInformation]] {
	return octetValueCodec[MSEncryptionInformation]("MAP-MS-DataTypes.EncryptionInformation", "EncryptionInformation", []primitiveRule[MSEncryptionInformation]{{invalid: func(value MSEncryptionInformation) bool { return !(len(value) >= 18 && len(value) <= 100) }, description: "SIZE (18..100)", clause: "51.5", length: func(value MSEncryptionInformation) int { return len(value) }}})
}

// MSSendAuthenticationInfoArgCodec binds MAP-MS-DataTypes.SendAuthenticationInfoArg.
func MSSendAuthenticationInfoArgCodec() ValueCodec[MSSendAuthenticationInfoArg] {
	return compositeValueCodec[MSSendAuthenticationInfoArg, *MSSendAuthenticationInfoArg]()
}

// MSNumberOfRequestedVectorsCodec binds MAP-MS-DataTypes.NumberOfRequestedVectors.
func MSNumberOfRequestedVectorsCodec() ValueCodec[BERValue[MSNumberOfRequestedVectors]] {
	return integerValueCodec[MSNumberOfRequestedVectors]("MAP-MS-DataTypes.NumberOfRequestedVectors", "NumberOfRequestedVectors", []primitiveRule[MSNumberOfRequestedVectors]{{invalid: func(value MSNumberOfRequestedVectors) bool { return !(int64(value) >= 1 && int64(value) <= 5) }, description: "(1..5)", clause: "51.4", observed: func(value MSNumberOfRequestedVectors) any { return int64(value) }}}, false)
}

// MSReSynchronisationInfoCodec binds MAP-MS-DataTypes.Re-synchronisationInfo.
func MSReSynchronisationInfoCodec() ValueCodec[MSReSynchronisationInfo] {
	return compositeValueCodec[MSReSynchronisationInfo, *MSReSynchronisationInfo]()
}

// MSSendAuthenticationInfoResCodec binds MAP-MS-DataTypes.SendAuthenticationInfoRes.
func MSSendAuthenticationInfoResCodec() ValueCodec[MSSendAuthenticationInfoRes] {
	return compositeValueCodec[MSSendAuthenticationInfoRes, *MSSendAuthenticationInfoRes]()
}

// MSEPSAuthenticationSetListCodec binds MAP-MS-DataTypes.EPS-AuthenticationSetList.
func MSEPSAuthenticationSetListCodec() ValueCodec[MSEPSAuthenticationSetList] {
	return pointerValueCodec(UnmarshalBERMSEPSAuthenticationSetList, MarshalBERMSEPSAuthenticationSetList, MarshalDERMSEPSAuthenticationSetList)
}

// MSUEUsageTypeCodec binds MAP-MS-DataTypes.UE-UsageType.
func MSUEUsageTypeCodec() ValueCodec[BERValue[MSUEUsageType]] {
	return octetValueCodec[MSUEUsageType]("MAP-MS-DataTypes.UE-UsageType", "UE-UsageType", []primitiveRule[MSUEUsageType]{{invalid: func(value MSUEUsageType) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value MSUEUsageType) int { return len(value) }}})
}

// MSEPCAVCodec binds MAP-MS-DataTypes.EPC-AV.
func MSEPCAVCodec() ValueCodec[MSEPCAV] {
	return compositeValueCodec[MSEPCAV, *MSEPCAV]()
}

// MSKASMECodec binds MAP-MS-DataTypes.KASME.
func MSKASMECodec() ValueCodec[BERValue[MSKASME]] {
	return octetValueCodec[MSKASME]("MAP-MS-DataTypes.KASME", "KASME", []primitiveRule[MSKASME]{{invalid: func(value MSKASME) bool { return !(len(value) == 32) }, description: "SIZE (32)", clause: "51.5", length: func(value MSKASME) int { return len(value) }}})
}

// MSRequestingNodeTypeCodec binds MAP-MS-DataTypes.RequestingNodeType.
func MSRequestingNodeTypeCodec() ValueCodec[BERValue[MSRequestingNodeType]] {
	return integerValueCodec[MSRequestingNodeType]("MAP-MS-DataTypes.RequestingNodeType", "RequestingNodeType", nil, true)
}

// MSCheckIMEIArgCodec binds MAP-MS-DataTypes.CheckIMEI-Arg.
func MSCheckIMEIArgCodec() ValueCodec[MSCheckIMEIArg] {
	return compositeValueCodec[MSCheckIMEIArg, *MSCheckIMEIArg]()
}

// MSCheckIMEIResCodec binds MAP-MS-DataTypes.CheckIMEI-Res.
func MSCheckIMEIResCodec() ValueCodec[MSCheckIMEIRes] {
	return compositeValueCodec[MSCheckIMEIRes, *MSCheckIMEIRes]()
}

// MSRequestedEquipmentInfoCodec binds MAP-MS-DataTypes.RequestedEquipmentInfo.
func MSRequestedEquipmentInfoCodec() ValueCodec[BERValue[MSRequestedEquipmentInfo]] {
	return bitValueCodec("MAP-MS-DataTypes.RequestedEquipmentInfo", "RequestedEquipmentInfo", []primitiveRule[MSRequestedEquipmentInfo]{{invalid: func(value MSRequestedEquipmentInfo) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value MSRequestedEquipmentInfo) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// MSUESBIIuCodec binds MAP-MS-DataTypes.UESBI-Iu.
func MSUESBIIuCodec() ValueCodec[MSUESBIIu] {
	return compositeValueCodec[MSUESBIIu, *MSUESBIIu]()
}

// MSUESBIIuACodec binds MAP-MS-DataTypes.UESBI-IuA.
func MSUESBIIuACodec() ValueCodec[BERValue[MSUESBIIuA]] {
	return bitValueCodec("MAP-MS-DataTypes.UESBI-IuA", "UESBI-IuA", []primitiveRule[MSUESBIIuA]{{invalid: func(value MSUESBIIuA) bool { return !(value.BitLength >= 1 && value.BitLength <= 128) }, description: "SIZE (1..128)", clause: "51.5", length: func(value MSUESBIIuA) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 1, Max: 128}}})
}

// MSUESBIIuBCodec binds MAP-MS-DataTypes.UESBI-IuB.
func MSUESBIIuBCodec() ValueCodec[BERValue[MSUESBIIuB]] {
	return bitValueCodec("MAP-MS-DataTypes.UESBI-IuB", "UESBI-IuB", []primitiveRule[MSUESBIIuB]{{invalid: func(value MSUESBIIuB) bool { return !(value.BitLength >= 1 && value.BitLength <= 128) }, description: "SIZE (1..128)", clause: "51.5", length: func(value MSUESBIIuB) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 1, Max: 128}}})
}

// MSEquipmentStatusCodec binds MAP-MS-DataTypes.EquipmentStatus.
func MSEquipmentStatusCodec() ValueCodec[BERValue[MSEquipmentStatus]] {
	return integerValueCodec[MSEquipmentStatus]("MAP-MS-DataTypes.EquipmentStatus", "EquipmentStatus", []primitiveRule[MSEquipmentStatus]{{invalid: func(value MSEquipmentStatus) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value MSEquipmentStatus) any { return int64(value) }}}, true)
}

// MSInsertSubscriberDataArgCodec binds MAP-MS-DataTypes.InsertSubscriberDataArg.
func MSInsertSubscriberDataArgCodec() ValueCodec[MSInsertSubscriberDataArg] {
	return compositeValueCodec[MSInsertSubscriberDataArg, *MSInsertSubscriberDataArg]()
}

// MSEDRXCycleLengthListCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length-List.
func MSEDRXCycleLengthListCodec() ValueCodec[MSEDRXCycleLengthList] {
	return pointerValueCodec(UnmarshalBERMSEDRXCycleLengthList, MarshalBERMSEDRXCycleLengthList, MarshalDERMSEDRXCycleLengthList)
}

// MSEDRXCycleLengthCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length.
func MSEDRXCycleLengthCodec() ValueCodec[MSEDRXCycleLength] {
	return compositeValueCodec[MSEDRXCycleLength, *MSEDRXCycleLength]()
}

// MSEDRXCycleLengthValueCodec binds MAP-MS-DataTypes.EDRX-Cycle-Length-Value.
func MSEDRXCycleLengthValueCodec() ValueCodec[BERValue[MSEDRXCycleLengthValue]] {
	return octetValueCodec[MSEDRXCycleLengthValue]("MAP-MS-DataTypes.EDRX-Cycle-Length-Value", "EDRX-Cycle-Length-Value", []primitiveRule[MSEDRXCycleLengthValue]{{invalid: func(value MSEDRXCycleLengthValue) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSEDRXCycleLengthValue) int { return len(value) }}})
}

// MSResetIdListCodec binds MAP-MS-DataTypes.Reset-Id-List.
func MSResetIdListCodec() ValueCodec[MSResetIdList] {
	return pointerValueCodec(UnmarshalBERMSResetIdList, MarshalBERMSResetIdList, MarshalDERMSResetIdList)
}

// MSResetIdCodec binds MAP-MS-DataTypes.Reset-Id.
func MSResetIdCodec() ValueCodec[BERValue[MSResetId]] {
	return octetValueCodec[MSResetId]("MAP-MS-DataTypes.Reset-Id", "Reset-Id", []primitiveRule[MSResetId]{{invalid: func(value MSResetId) bool { return !(len(value) >= 1 && len(value) <= 4) }, description: "SIZE (1..4)", clause: "51.5", length: func(value MSResetId) int { return len(value) }}})
}

// MSDLBufferingSuggestedPacketCountCodec binds MAP-MS-DataTypes.DL-Buffering-Suggested-Packet-Count.
func MSDLBufferingSuggestedPacketCountCodec() ValueCodec[BERValue[MSDLBufferingSuggestedPacketCount]] {
	return integerValueCodec[MSDLBufferingSuggestedPacketCount]("MAP-MS-DataTypes.DL-Buffering-Suggested-Packet-Count", "DL-Buffering-Suggested-Packet-Count", []primitiveRule[MSDLBufferingSuggestedPacketCount]{{invalid: func(value MSDLBufferingSuggestedPacketCount) bool {
		return !(int64(value) >= -1 && int64(value) <= 2147483647)
	}, description: "(-1..2147483647)", clause: "51.4", observed: func(value MSDLBufferingSuggestedPacketCount) any { return int64(value) }}}, false)
}

// MSGroupServiceIDCodec binds MAP-MS-DataTypes.Group-Service-ID.
func MSGroupServiceIDCodec() ValueCodec[BERValue[MSGroupServiceID]] {
	return integerValueCodec[MSGroupServiceID]("MAP-MS-DataTypes.Group-Service-ID", "Group-Service-ID", []primitiveRule[MSGroupServiceID]{{invalid: func(value MSGroupServiceID) bool { return !(int64(value) >= 0 && int64(value) <= 4294967295) }, description: "(0..4294967295)", clause: "51.4", observed: func(value MSGroupServiceID) any { return int64(value) }}}, false)
}

// MSLocalGroupIDCodec binds MAP-MS-DataTypes.Local-GroupID.
func MSLocalGroupIDCodec() ValueCodec[BERValue[MSLocalGroupID]] {
	return octetValueCodec[MSLocalGroupID]("MAP-MS-DataTypes.Local-GroupID", "Local-GroupID", []primitiveRule[MSLocalGroupID]{{invalid: func(value MSLocalGroupID) bool { return !(len(value) >= 1 && len(value) <= 10) }, description: "SIZE (1..10)", clause: "51.5", length: func(value MSLocalGroupID) int { return len(value) }}})
}

// MSIMSIGroupIdListCodec binds MAP-MS-DataTypes.IMSI-GroupIdList.
func MSIMSIGroupIdListCodec() ValueCodec[MSIMSIGroupIdList] {
	return pointerValueCodec(UnmarshalBERMSIMSIGroupIdList, MarshalBERMSIMSIGroupIdList, MarshalDERMSIMSIGroupIdList)
}

// MSIMSIGroupIdCodec binds MAP-MS-DataTypes.IMSI-GroupId.
func MSIMSIGroupIdCodec() ValueCodec[MSIMSIGroupId] {
	return compositeValueCodec[MSIMSIGroupId, *MSIMSIGroupId]()
}

// MSSubscribedPeriodicRAUTAUtimerCodec binds MAP-MS-DataTypes.SubscribedPeriodicRAUTAUtimer.
func MSSubscribedPeriodicRAUTAUtimerCodec() ValueCodec[BERValue[MSSubscribedPeriodicRAUTAUtimer]] {
	return integerValueCodec[MSSubscribedPeriodicRAUTAUtimer]("MAP-MS-DataTypes.SubscribedPeriodicRAUTAUtimer", "SubscribedPeriodicRAUTAUtimer", []primitiveRule[MSSubscribedPeriodicRAUTAUtimer]{{invalid: func(value MSSubscribedPeriodicRAUTAUtimer) bool {
		return !(int64(value) >= 0 && int64(value) <= 4294967295)
	}, description: "(0..4294967295)", clause: "51.4", observed: func(value MSSubscribedPeriodicRAUTAUtimer) any { return int64(value) }}}, false)
}

// MSSubscribedPeriodicLAUtimerCodec binds MAP-MS-DataTypes.SubscribedPeriodicLAUtimer.
func MSSubscribedPeriodicLAUtimerCodec() ValueCodec[BERValue[MSSubscribedPeriodicLAUtimer]] {
	return integerValueCodec[MSSubscribedPeriodicLAUtimer]("MAP-MS-DataTypes.SubscribedPeriodicLAUtimer", "SubscribedPeriodicLAUtimer", []primitiveRule[MSSubscribedPeriodicLAUtimer]{{invalid: func(value MSSubscribedPeriodicLAUtimer) bool {
		return !(int64(value) >= 0 && int64(value) <= 4294967295)
	}, description: "(0..4294967295)", clause: "51.4", observed: func(value MSSubscribedPeriodicLAUtimer) any { return int64(value) }}}, false)
}

// MSCSGSubscriptionDataListCodec binds MAP-MS-DataTypes.CSG-SubscriptionDataList.
func MSCSGSubscriptionDataListCodec() ValueCodec[MSCSGSubscriptionDataList] {
	return pointerValueCodec(UnmarshalBERMSCSGSubscriptionDataList, MarshalBERMSCSGSubscriptionDataList, MarshalDERMSCSGSubscriptionDataList)
}

// MSCSGSubscriptionDataCodec binds MAP-MS-DataTypes.CSG-SubscriptionData.
func MSCSGSubscriptionDataCodec() ValueCodec[MSCSGSubscriptionData] {
	return compositeValueCodec[MSCSGSubscriptionData, *MSCSGSubscriptionData]()
}

// MSVPLMNCSGSubscriptionDataListCodec binds MAP-MS-DataTypes.VPLMN-CSG-SubscriptionDataList.
func MSVPLMNCSGSubscriptionDataListCodec() ValueCodec[MSVPLMNCSGSubscriptionDataList] {
	return pointerValueCodec(UnmarshalBERMSVPLMNCSGSubscriptionDataList, MarshalBERMSVPLMNCSGSubscriptionDataList, MarshalDERMSVPLMNCSGSubscriptionDataList)
}

// MSCSGIdCodec binds MAP-MS-DataTypes.CSG-Id.
func MSCSGIdCodec() ValueCodec[BERValue[MSCSGId]] {
	return bitValueCodec("MAP-MS-DataTypes.CSG-Id", "CSG-Id", []primitiveRule[MSCSGId]{{invalid: func(value MSCSGId) bool { return !(value.BitLength == 27) }, description: "SIZE (27)", clause: "51.5", length: func(value MSCSGId) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 27, Max: 27}}})
}

// MSLIPAAllowedAPNListCodec binds MAP-MS-DataTypes.LIPA-AllowedAPNList.
func MSLIPAAllowedAPNListCodec() ValueCodec[MSLIPAAllowedAPNList] {
	return pointerValueCodec(UnmarshalBERMSLIPAAllowedAPNList, MarshalBERMSLIPAAllowedAPNList, MarshalDERMSLIPAAllowedAPNList)
}

// MSEPSSubscriptionDataCodec binds MAP-MS-DataTypes.EPS-SubscriptionData.
func MSEPSSubscriptionDataCodec() ValueCodec[MSEPSSubscriptionData] {
	return compositeValueCodec[MSEPSSubscriptionData, *MSEPSSubscriptionData]()
}

// MSAPNOIReplacementCodec binds MAP-MS-DataTypes.APN-OI-Replacement.
func MSAPNOIReplacementCodec() ValueCodec[BERValue[MSAPNOIReplacement]] {
	return octetValueCodec[MSAPNOIReplacement]("MAP-MS-DataTypes.APN-OI-Replacement", "APN-OI-Replacement", []primitiveRule[MSAPNOIReplacement]{{invalid: func(value MSAPNOIReplacement) bool { return !(len(value) >= 9 && len(value) <= 100) }, description: "SIZE (9..100)", clause: "51.5", length: func(value MSAPNOIReplacement) int { return len(value) }}})
}

// MSRFSPIDCodec binds MAP-MS-DataTypes.RFSP-ID.
func MSRFSPIDCodec() ValueCodec[BERValue[MSRFSPID]] {
	return integerValueCodec[MSRFSPID]("MAP-MS-DataTypes.RFSP-ID", "RFSP-ID", []primitiveRule[MSRFSPID]{{invalid: func(value MSRFSPID) bool { return !(int64(value) >= 1 && int64(value) <= 256) }, description: "(1..256)", clause: "51.4", observed: func(value MSRFSPID) any { return int64(value) }}}, false)
}

// MSAPNConfigurationProfileCodec binds MAP-MS-DataTypes.APN-ConfigurationProfile.
func MSAPNConfigurationProfileCodec() ValueCodec[MSAPNConfigurationProfile] {
	return compositeValueCodec[MSAPNConfigurationProfile, *MSAPNConfigurationProfile]()
}

// MSEPSDataListCodec binds MAP-MS-DataTypes.EPS-DataList.
func MSEPSDataListCodec() ValueCodec[MSEPSDataList] {
	return pointerValueCodec(UnmarshalBERMSEPSDataList, MarshalBERMSEPSDataList, MarshalDERMSEPSDataList)
}

// MSAPNConfigurationCodec binds MAP-MS-DataTypes.APN-Configuration.
func MSAPNConfigurationCodec() ValueCodec[MSAPNConfiguration] {
	return compositeValueCodec[MSAPNConfiguration, *MSAPNConfiguration]()
}

// MSPDNConnectionContinuityCodec binds MAP-MS-DataTypes.PDN-ConnectionContinuity.
func MSPDNConnectionContinuityCodec() ValueCodec[BERValue[MSPDNConnectionContinuity]] {
	return integerValueCodec[MSPDNConnectionContinuity]("MAP-MS-DataTypes.PDN-ConnectionContinuity", "PDN-ConnectionContinuity", []primitiveRule[MSPDNConnectionContinuity]{{invalid: func(value MSPDNConnectionContinuity) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value MSPDNConnectionContinuity) any { return int64(value) }}}, true)
}

// MSNIDDMechanismCodec binds MAP-MS-DataTypes.NIDD-Mechanism.
func MSNIDDMechanismCodec() ValueCodec[BERValue[MSNIDDMechanism]] {
	return integerValueCodec[MSNIDDMechanism]("MAP-MS-DataTypes.NIDD-Mechanism", "NIDD-Mechanism", []primitiveRule[MSNIDDMechanism]{{invalid: func(value MSNIDDMechanism) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSNIDDMechanism) any { return int64(value) }}}, true)
}

// MSPDNTypeCodec binds MAP-MS-DataTypes.PDN-Type.
func MSPDNTypeCodec() ValueCodec[BERValue[MSPDNType]] {
	return octetValueCodec[MSPDNType]("MAP-MS-DataTypes.PDN-Type", "PDN-Type", []primitiveRule[MSPDNType]{{invalid: func(value MSPDNType) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSPDNType) int { return len(value) }}})
}

// MSEPSQoSSubscribedCodec binds MAP-MS-DataTypes.EPS-QoS-Subscribed.
func MSEPSQoSSubscribedCodec() ValueCodec[MSEPSQoSSubscribed] {
	return compositeValueCodec[MSEPSQoSSubscribed, *MSEPSQoSSubscribed]()
}

// MSAMBRCodec binds MAP-MS-DataTypes.AMBR.
func MSAMBRCodec() ValueCodec[MSAMBR] {
	return compositeValueCodec[MSAMBR, *MSAMBR]()
}

// MSSpecificAPNInfoListCodec binds MAP-MS-DataTypes.SpecificAPNInfoList.
func MSSpecificAPNInfoListCodec() ValueCodec[MSSpecificAPNInfoList] {
	return pointerValueCodec(UnmarshalBERMSSpecificAPNInfoList, MarshalBERMSSpecificAPNInfoList, MarshalDERMSSpecificAPNInfoList)
}

// MSSpecificAPNInfoCodec binds MAP-MS-DataTypes.SpecificAPNInfo.
func MSSpecificAPNInfoCodec() ValueCodec[MSSpecificAPNInfo] {
	return compositeValueCodec[MSSpecificAPNInfo, *MSSpecificAPNInfo]()
}

// MSBandwidthCodec binds MAP-MS-DataTypes.Bandwidth.
func MSBandwidthCodec() ValueCodec[BERValue[MSBandwidth]] {
	return bigIntegerValueCodec("MAP-MS-DataTypes.Bandwidth", "Bandwidth")
}

// MSBandwidthExtCodec binds MAP-MS-DataTypes.BandwidthExt.
func MSBandwidthExtCodec() ValueCodec[BERValue[MSBandwidthExt]] {
	return bigIntegerValueCodec("MAP-MS-DataTypes.BandwidthExt", "BandwidthExt")
}

// MSQoSClassIdentifierCodec binds MAP-MS-DataTypes.QoS-Class-Identifier.
func MSQoSClassIdentifierCodec() ValueCodec[BERValue[MSQoSClassIdentifier]] {
	return integerValueCodec[MSQoSClassIdentifier]("MAP-MS-DataTypes.QoS-Class-Identifier", "QoS-Class-Identifier", []primitiveRule[MSQoSClassIdentifier]{{invalid: func(value MSQoSClassIdentifier) bool { return !(int64(value) >= 1 && int64(value) <= 9) }, description: "(1..9)", clause: "51.4", observed: func(value MSQoSClassIdentifier) any { return int64(value) }}}, false)
}

// MSAllocationRetentionPriorityCodec binds MAP-MS-DataTypes.Allocation-Retention-Priority.
func MSAllocationRetentionPriorityCodec() ValueCodec[MSAllocationRetentionPriority] {
	return compositeValueCodec[MSAllocationRetentionPriority, *MSAllocationRetentionPriority]()
}

// MSPDNGWIdentityCodec binds MAP-MS-DataTypes.PDN-GW-Identity.
func MSPDNGWIdentityCodec() ValueCodec[MSPDNGWIdentity] {
	return compositeValueCodec[MSPDNGWIdentity, *MSPDNGWIdentity]()
}

// MSFQDNCodec binds MAP-MS-DataTypes.FQDN.
func MSFQDNCodec() ValueCodec[BERValue[MSFQDN]] {
	return octetValueCodec[MSFQDN]("MAP-MS-DataTypes.FQDN", "FQDN", []primitiveRule[MSFQDN]{{invalid: func(value MSFQDN) bool { return !(len(value) >= 9 && len(value) <= 255) }, description: "SIZE (9..255)", clause: "51.5", length: func(value MSFQDN) int { return len(value) }}})
}

// MSPDNGWAllocationTypeCodec binds MAP-MS-DataTypes.PDN-GW-AllocationType.
func MSPDNGWAllocationTypeCodec() ValueCodec[BERValue[MSPDNGWAllocationType]] {
	return integerValueCodec[MSPDNGWAllocationType]("MAP-MS-DataTypes.PDN-GW-AllocationType", "PDN-GW-AllocationType", []primitiveRule[MSPDNGWAllocationType]{{invalid: func(value MSPDNGWAllocationType) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSPDNGWAllocationType) any { return int64(value) }}}, true)
}

// MSWLANOffloadabilityCodec binds MAP-MS-DataTypes.WLAN-Offloadability.
func MSWLANOffloadabilityCodec() ValueCodec[MSWLANOffloadability] {
	return compositeValueCodec[MSWLANOffloadability, *MSWLANOffloadability]()
}

// MSWLANOffloadabilityIndicationCodec binds MAP-MS-DataTypes.WLAN-Offloadability-Indication.
func MSWLANOffloadabilityIndicationCodec() ValueCodec[BERValue[MSWLANOffloadabilityIndication]] {
	return integerValueCodec[MSWLANOffloadabilityIndication]("MAP-MS-DataTypes.WLAN-Offloadability-Indication", "WLAN-Offloadability-Indication", []primitiveRule[MSWLANOffloadabilityIndication]{{invalid: func(value MSWLANOffloadabilityIndication) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSWLANOffloadabilityIndication) any { return int64(value) }}}, true)
}

// MSAccessRestrictionDataCodec binds MAP-MS-DataTypes.AccessRestrictionData.
func MSAccessRestrictionDataCodec() ValueCodec[BERValue[MSAccessRestrictionData]] {
	return bitValueCodec("MAP-MS-DataTypes.AccessRestrictionData", "AccessRestrictionData", []primitiveRule[MSAccessRestrictionData]{{invalid: func(value MSAccessRestrictionData) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value MSAccessRestrictionData) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// MSExtAccessRestrictionDataCodec binds MAP-MS-DataTypes.Ext-AccessRestrictionData.
func MSExtAccessRestrictionDataCodec() ValueCodec[BERValue[MSExtAccessRestrictionData]] {
	return bitValueCodec("MAP-MS-DataTypes.Ext-AccessRestrictionData", "Ext-AccessRestrictionData", []primitiveRule[MSExtAccessRestrictionData]{{invalid: func(value MSExtAccessRestrictionData) bool { return !(value.BitLength >= 1 && value.BitLength <= 32) }, description: "SIZE (1..32)", clause: "51.5", length: func(value MSExtAccessRestrictionData) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 32}}})
}

// MSAdjacentAccessRestrictionDataListCodec binds MAP-MS-DataTypes.AdjacentAccessRestrictionDataList.
func MSAdjacentAccessRestrictionDataListCodec() ValueCodec[MSAdjacentAccessRestrictionDataList] {
	return pointerValueCodec(UnmarshalBERMSAdjacentAccessRestrictionDataList, MarshalBERMSAdjacentAccessRestrictionDataList, MarshalDERMSAdjacentAccessRestrictionDataList)
}

// MSAdjacentAccessRestrictionDataCodec binds MAP-MS-DataTypes.AdjacentAccessRestrictionData.
func MSAdjacentAccessRestrictionDataCodec() ValueCodec[MSAdjacentAccessRestrictionData] {
	return compositeValueCodec[MSAdjacentAccessRestrictionData, *MSAdjacentAccessRestrictionData]()
}

// MSCSAllocationRetentionPriorityCodec binds MAP-MS-DataTypes.CS-AllocationRetentionPriority.
func MSCSAllocationRetentionPriorityCodec() ValueCodec[BERValue[MSCSAllocationRetentionPriority]] {
	return octetValueCodec[MSCSAllocationRetentionPriority]("MAP-MS-DataTypes.CS-AllocationRetentionPriority", "CS-AllocationRetentionPriority", []primitiveRule[MSCSAllocationRetentionPriority]{{invalid: func(value MSCSAllocationRetentionPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSCSAllocationRetentionPriority) int { return len(value) }}})
}

// MSISTAlertTimerValueCodec binds MAP-MS-DataTypes.IST-AlertTimerValue.
func MSISTAlertTimerValueCodec() ValueCodec[BERValue[MSISTAlertTimerValue]] {
	return integerValueCodec[MSISTAlertTimerValue]("MAP-MS-DataTypes.IST-AlertTimerValue", "IST-AlertTimerValue", []primitiveRule[MSISTAlertTimerValue]{{invalid: func(value MSISTAlertTimerValue) bool { return !(int64(value) >= 15 && int64(value) <= 255) }, description: "(15..255)", clause: "51.4", observed: func(value MSISTAlertTimerValue) any { return int64(value) }}}, false)
}

// MSLCSInformationCodec binds MAP-MS-DataTypes.LCSInformation.
func MSLCSInformationCodec() ValueCodec[MSLCSInformation] {
	return compositeValueCodec[MSLCSInformation, *MSLCSInformation]()
}

// MSGMLCListCodec binds MAP-MS-DataTypes.GMLC-List.
func MSGMLCListCodec() ValueCodec[MSGMLCList] {
	return pointerValueCodec(UnmarshalBERMSGMLCList, MarshalBERMSGMLCList, MarshalDERMSGMLCList)
}

// MSNetworkAccessModeCodec binds MAP-MS-DataTypes.NetworkAccessMode.
func MSNetworkAccessModeCodec() ValueCodec[BERValue[MSNetworkAccessMode]] {
	return integerValueCodec[MSNetworkAccessMode]("MAP-MS-DataTypes.NetworkAccessMode", "NetworkAccessMode", nil, true)
}

// MSGPRSDataListCodec binds MAP-MS-DataTypes.GPRSDataList.
func MSGPRSDataListCodec() ValueCodec[MSGPRSDataList] {
	return pointerValueCodec(UnmarshalBERMSGPRSDataList, MarshalBERMSGPRSDataList, MarshalDERMSGPRSDataList)
}

// MSPDPContextCodec binds MAP-MS-DataTypes.PDP-Context.
func MSPDPContextCodec() ValueCodec[MSPDPContext] {
	return compositeValueCodec[MSPDPContext, *MSPDPContext]()
}

// MSRestorationPriorityCodec binds MAP-MS-DataTypes.Restoration-Priority.
func MSRestorationPriorityCodec() ValueCodec[BERValue[MSRestorationPriority]] {
	return octetValueCodec[MSRestorationPriority]("MAP-MS-DataTypes.Restoration-Priority", "Restoration-Priority", []primitiveRule[MSRestorationPriority]{{invalid: func(value MSRestorationPriority) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSRestorationPriority) int { return len(value) }}})
}

// MSSIPTOPermissionCodec binds MAP-MS-DataTypes.SIPTO-Permission.
func MSSIPTOPermissionCodec() ValueCodec[BERValue[MSSIPTOPermission]] {
	return integerValueCodec[MSSIPTOPermission]("MAP-MS-DataTypes.SIPTO-Permission", "SIPTO-Permission", []primitiveRule[MSSIPTOPermission]{{invalid: func(value MSSIPTOPermission) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSSIPTOPermission) any { return int64(value) }}}, true)
}

// MSSIPTOLocalNetworkPermissionCodec binds MAP-MS-DataTypes.SIPTO-Local-Network-Permission.
func MSSIPTOLocalNetworkPermissionCodec() ValueCodec[BERValue[MSSIPTOLocalNetworkPermission]] {
	return integerValueCodec[MSSIPTOLocalNetworkPermission]("MAP-MS-DataTypes.SIPTO-Local-Network-Permission", "SIPTO-Local-Network-Permission", []primitiveRule[MSSIPTOLocalNetworkPermission]{{invalid: func(value MSSIPTOLocalNetworkPermission) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSSIPTOLocalNetworkPermission) any { return int64(value) }}}, true)
}

// MSLIPAPermissionCodec binds MAP-MS-DataTypes.LIPA-Permission.
func MSLIPAPermissionCodec() ValueCodec[BERValue[MSLIPAPermission]] {
	return integerValueCodec[MSLIPAPermission]("MAP-MS-DataTypes.LIPA-Permission", "LIPA-Permission", []primitiveRule[MSLIPAPermission]{{invalid: func(value MSLIPAPermission) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value MSLIPAPermission) any { return int64(value) }}}, true)
}

// MSContextIdCodec binds MAP-MS-DataTypes.ContextId.
func MSContextIdCodec() ValueCodec[BERValue[MSContextId]] {
	return integerValueCodec[MSContextId]("MAP-MS-DataTypes.ContextId", "ContextId", []primitiveRule[MSContextId]{{invalid: func(value MSContextId) bool { return !(int64(value) >= 1 && int64(value) <= 50) }, description: "(1..50)", clause: "51.4", observed: func(value MSContextId) any { return int64(value) }}}, false)
}

// MSGPRSSubscriptionDataCodec binds MAP-MS-DataTypes.GPRSSubscriptionData.
func MSGPRSSubscriptionDataCodec() ValueCodec[MSGPRSSubscriptionData] {
	return compositeValueCodec[MSGPRSSubscriptionData, *MSGPRSSubscriptionData]()
}

// MSSGSNCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.SGSN-CAMEL-SubscriptionInfo.
func MSSGSNCAMELSubscriptionInfoCodec() ValueCodec[MSSGSNCAMELSubscriptionInfo] {
	return compositeValueCodec[MSSGSNCAMELSubscriptionInfo, *MSSGSNCAMELSubscriptionInfo]()
}

// MSGPRSCSICodec binds MAP-MS-DataTypes.GPRS-CSI.
func MSGPRSCSICodec() ValueCodec[MSGPRSCSI] {
	return compositeValueCodec[MSGPRSCSI, *MSGPRSCSI]()
}

// MSGPRSCamelTDPDataListCodec binds MAP-MS-DataTypes.GPRS-CamelTDPDataList.
func MSGPRSCamelTDPDataListCodec() ValueCodec[MSGPRSCamelTDPDataList] {
	return pointerValueCodec(UnmarshalBERMSGPRSCamelTDPDataList, MarshalBERMSGPRSCamelTDPDataList, MarshalDERMSGPRSCamelTDPDataList)
}

// MSGPRSCamelTDPDataCodec binds MAP-MS-DataTypes.GPRS-CamelTDPData.
func MSGPRSCamelTDPDataCodec() ValueCodec[MSGPRSCamelTDPData] {
	return compositeValueCodec[MSGPRSCamelTDPData, *MSGPRSCamelTDPData]()
}

// MSDefaultGPRSHandlingCodec binds MAP-MS-DataTypes.DefaultGPRS-Handling.
func MSDefaultGPRSHandlingCodec() ValueCodec[BERValue[MSDefaultGPRSHandling]] {
	return integerValueCodec[MSDefaultGPRSHandling]("MAP-MS-DataTypes.DefaultGPRS-Handling", "DefaultGPRS-Handling", nil, true)
}

// MSGPRSTriggerDetectionPointCodec binds MAP-MS-DataTypes.GPRS-TriggerDetectionPoint.
func MSGPRSTriggerDetectionPointCodec() ValueCodec[BERValue[MSGPRSTriggerDetectionPoint]] {
	return integerValueCodec[MSGPRSTriggerDetectionPoint]("MAP-MS-DataTypes.GPRS-TriggerDetectionPoint", "GPRS-TriggerDetectionPoint", nil, true)
}

// MSAPNCodec binds MAP-MS-DataTypes.APN.
func MSAPNCodec() ValueCodec[BERValue[MSAPN]] {
	return octetValueCodec[MSAPN]("MAP-MS-DataTypes.APN", "APN", []primitiveRule[MSAPN]{{invalid: func(value MSAPN) bool { return !(len(value) >= 2 && len(value) <= 63) }, description: "SIZE (2..63)", clause: "51.5", length: func(value MSAPN) int { return len(value) }}})
}

// MSPDPTypeCodec binds MAP-MS-DataTypes.PDP-Type.
func MSPDPTypeCodec() ValueCodec[BERValue[MSPDPType]] {
	return octetValueCodec[MSPDPType]("MAP-MS-DataTypes.PDP-Type", "PDP-Type", []primitiveRule[MSPDPType]{{invalid: func(value MSPDPType) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value MSPDPType) int { return len(value) }}})
}

// MSExtPDPTypeCodec binds MAP-MS-DataTypes.Ext-PDP-Type.
func MSExtPDPTypeCodec() ValueCodec[BERValue[MSExtPDPType]] {
	return octetValueCodec[MSExtPDPType]("MAP-MS-DataTypes.Ext-PDP-Type", "Ext-PDP-Type", []primitiveRule[MSExtPDPType]{{invalid: func(value MSExtPDPType) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value MSExtPDPType) int { return len(value) }}})
}

// MSPDPAddressCodec binds MAP-MS-DataTypes.PDP-Address.
func MSPDPAddressCodec() ValueCodec[BERValue[MSPDPAddress]] {
	return octetValueCodec[MSPDPAddress]("MAP-MS-DataTypes.PDP-Address", "PDP-Address", []primitiveRule[MSPDPAddress]{{invalid: func(value MSPDPAddress) bool { return !(len(value) >= 1 && len(value) <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value MSPDPAddress) int { return len(value) }}})
}

// MSQoSSubscribedCodec binds MAP-MS-DataTypes.QoS-Subscribed.
func MSQoSSubscribedCodec() ValueCodec[BERValue[MSQoSSubscribed]] {
	return octetValueCodec[MSQoSSubscribed]("MAP-MS-DataTypes.QoS-Subscribed", "QoS-Subscribed", []primitiveRule[MSQoSSubscribed]{{invalid: func(value MSQoSSubscribed) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value MSQoSSubscribed) int { return len(value) }}})
}

// MSExtQoSSubscribedCodec binds MAP-MS-DataTypes.Ext-QoS-Subscribed.
func MSExtQoSSubscribedCodec() ValueCodec[BERValue[MSExtQoSSubscribed]] {
	return octetValueCodec[MSExtQoSSubscribed]("MAP-MS-DataTypes.Ext-QoS-Subscribed", "Ext-QoS-Subscribed", []primitiveRule[MSExtQoSSubscribed]{{invalid: func(value MSExtQoSSubscribed) bool { return !(len(value) >= 1 && len(value) <= 9) }, description: "SIZE (1..9)", clause: "51.5", length: func(value MSExtQoSSubscribed) int { return len(value) }}})
}

// MSExt2QoSSubscribedCodec binds MAP-MS-DataTypes.Ext2-QoS-Subscribed.
func MSExt2QoSSubscribedCodec() ValueCodec[BERValue[MSExt2QoSSubscribed]] {
	return octetValueCodec[MSExt2QoSSubscribed]("MAP-MS-DataTypes.Ext2-QoS-Subscribed", "Ext2-QoS-Subscribed", []primitiveRule[MSExt2QoSSubscribed]{{invalid: func(value MSExt2QoSSubscribed) bool { return !(len(value) >= 1 && len(value) <= 3) }, description: "SIZE (1..3)", clause: "51.5", length: func(value MSExt2QoSSubscribed) int { return len(value) }}})
}

// MSExt3QoSSubscribedCodec binds MAP-MS-DataTypes.Ext3-QoS-Subscribed.
func MSExt3QoSSubscribedCodec() ValueCodec[BERValue[MSExt3QoSSubscribed]] {
	return octetValueCodec[MSExt3QoSSubscribed]("MAP-MS-DataTypes.Ext3-QoS-Subscribed", "Ext3-QoS-Subscribed", []primitiveRule[MSExt3QoSSubscribed]{{invalid: func(value MSExt3QoSSubscribed) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value MSExt3QoSSubscribed) int { return len(value) }}})
}

// MSExt4QoSSubscribedCodec binds MAP-MS-DataTypes.Ext4-QoS-Subscribed.
func MSExt4QoSSubscribedCodec() ValueCodec[BERValue[MSExt4QoSSubscribed]] {
	return octetValueCodec[MSExt4QoSSubscribed]("MAP-MS-DataTypes.Ext4-QoS-Subscribed", "Ext4-QoS-Subscribed", []primitiveRule[MSExt4QoSSubscribed]{{invalid: func(value MSExt4QoSSubscribed) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSExt4QoSSubscribed) int { return len(value) }}})
}

// MSChargingCharacteristicsCodec binds MAP-MS-DataTypes.ChargingCharacteristics.
func MSChargingCharacteristicsCodec() ValueCodec[BERValue[MSChargingCharacteristics]] {
	return octetValueCodec[MSChargingCharacteristics]("MAP-MS-DataTypes.ChargingCharacteristics", "ChargingCharacteristics", []primitiveRule[MSChargingCharacteristics]{{invalid: func(value MSChargingCharacteristics) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value MSChargingCharacteristics) int { return len(value) }}})
}

// MSLSAOnlyAccessIndicatorCodec binds MAP-MS-DataTypes.LSAOnlyAccessIndicator.
func MSLSAOnlyAccessIndicatorCodec() ValueCodec[BERValue[MSLSAOnlyAccessIndicator]] {
	return integerValueCodec[MSLSAOnlyAccessIndicator]("MAP-MS-DataTypes.LSAOnlyAccessIndicator", "LSAOnlyAccessIndicator", []primitiveRule[MSLSAOnlyAccessIndicator]{{invalid: func(value MSLSAOnlyAccessIndicator) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSLSAOnlyAccessIndicator) any { return int64(value) }}}, true)
}

// MSLSADataListCodec binds MAP-MS-DataTypes.LSADataList.
func MSLSADataListCodec() ValueCodec[MSLSADataList] {
	return pointerValueCodec(UnmarshalBERMSLSADataList, MarshalBERMSLSADataList, MarshalDERMSLSADataList)
}

// MSLSADataCodec binds MAP-MS-DataTypes.LSAData.
func MSLSADataCodec() ValueCodec[MSLSAData] {
	return compositeValueCodec[MSLSAData, *MSLSAData]()
}

// MSLSAInformationCodec binds MAP-MS-DataTypes.LSAInformation.
func MSLSAInformationCodec() ValueCodec[MSLSAInformation] {
	return compositeValueCodec[MSLSAInformation, *MSLSAInformation]()
}

// MSLSAIdentityCodec binds MAP-MS-DataTypes.LSAIdentity.
func MSLSAIdentityCodec() ValueCodec[BERValue[MSLSAIdentity]] {
	return octetValueCodec[MSLSAIdentity]("MAP-MS-DataTypes.LSAIdentity", "LSAIdentity", []primitiveRule[MSLSAIdentity]{{invalid: func(value MSLSAIdentity) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value MSLSAIdentity) int { return len(value) }}})
}

// MSLSAAttributesCodec binds MAP-MS-DataTypes.LSAAttributes.
func MSLSAAttributesCodec() ValueCodec[BERValue[MSLSAAttributes]] {
	return octetValueCodec[MSLSAAttributes]("MAP-MS-DataTypes.LSAAttributes", "LSAAttributes", []primitiveRule[MSLSAAttributes]{{invalid: func(value MSLSAAttributes) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSLSAAttributes) int { return len(value) }}})
}

// MSSubscriberDataCodec binds MAP-MS-DataTypes.SubscriberData.
func MSSubscriberDataCodec() ValueCodec[MSSubscriberData] {
	return compositeValueCodec[MSSubscriberData, *MSSubscriberData]()
}

// MSCategoryCodec binds MAP-MS-DataTypes.Category.
func MSCategoryCodec() ValueCodec[BERValue[MSCategory]] {
	return octetValueCodec[MSCategory]("MAP-MS-DataTypes.Category", "Category", []primitiveRule[MSCategory]{{invalid: func(value MSCategory) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSCategory) int { return len(value) }}})
}

// MSSubscriberStatusCodec binds MAP-MS-DataTypes.SubscriberStatus.
func MSSubscriberStatusCodec() ValueCodec[BERValue[MSSubscriberStatus]] {
	return integerValueCodec[MSSubscriberStatus]("MAP-MS-DataTypes.SubscriberStatus", "SubscriberStatus", []primitiveRule[MSSubscriberStatus]{{invalid: func(value MSSubscriberStatus) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSSubscriberStatus) any { return int64(value) }}}, true)
}

// MSBearerServiceListCodec binds MAP-MS-DataTypes.BearerServiceList.
func MSBearerServiceListCodec() ValueCodec[MSBearerServiceList] {
	return pointerValueCodec(UnmarshalBERMSBearerServiceList, MarshalBERMSBearerServiceList, MarshalDERMSBearerServiceList)
}

// MSTeleserviceListCodec binds MAP-MS-DataTypes.TeleserviceList.
func MSTeleserviceListCodec() ValueCodec[MSTeleserviceList] {
	return pointerValueCodec(UnmarshalBERMSTeleserviceList, MarshalBERMSTeleserviceList, MarshalDERMSTeleserviceList)
}

// MSODBDataCodec binds MAP-MS-DataTypes.ODB-Data.
func MSODBDataCodec() ValueCodec[MSODBData] {
	return compositeValueCodec[MSODBData, *MSODBData]()
}

// MSODBGeneralDataCodec binds MAP-MS-DataTypes.ODB-GeneralData.
func MSODBGeneralDataCodec() ValueCodec[BERValue[MSODBGeneralData]] {
	return bitValueCodec("MAP-MS-DataTypes.ODB-GeneralData", "ODB-GeneralData", []primitiveRule[MSODBGeneralData]{{invalid: func(value MSODBGeneralData) bool { return !(value.BitLength >= 15 && value.BitLength <= 32) }, description: "SIZE (15..32)", clause: "51.5", length: func(value MSODBGeneralData) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 15, Max: 32}}})
}

// MSODBHPLMNDataCodec binds MAP-MS-DataTypes.ODB-HPLMN-Data.
func MSODBHPLMNDataCodec() ValueCodec[BERValue[MSODBHPLMNData]] {
	return bitValueCodec("MAP-MS-DataTypes.ODB-HPLMN-Data", "ODB-HPLMN-Data", []primitiveRule[MSODBHPLMNData]{{invalid: func(value MSODBHPLMNData) bool { return !(value.BitLength >= 4 && value.BitLength <= 32) }, description: "SIZE (4..32)", clause: "51.5", length: func(value MSODBHPLMNData) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 4, Max: 32}}})
}

// MSExtSSInfoListCodec binds MAP-MS-DataTypes.Ext-SS-InfoList.
func MSExtSSInfoListCodec() ValueCodec[MSExtSSInfoList] {
	return pointerValueCodec(UnmarshalBERMSExtSSInfoList, MarshalBERMSExtSSInfoList, MarshalDERMSExtSSInfoList)
}

// MSExtSSInfoCodec binds MAP-MS-DataTypes.Ext-SS-Info.
func MSExtSSInfoCodec() ValueCodec[MSExtSSInfo] {
	return compositeValueCodec[MSExtSSInfo, *MSExtSSInfo]()
}

// MSExtForwInfoCodec binds MAP-MS-DataTypes.Ext-ForwInfo.
func MSExtForwInfoCodec() ValueCodec[MSExtForwInfo] {
	return compositeValueCodec[MSExtForwInfo, *MSExtForwInfo]()
}

// MSExtForwFeatureListCodec binds MAP-MS-DataTypes.Ext-ForwFeatureList.
func MSExtForwFeatureListCodec() ValueCodec[MSExtForwFeatureList] {
	return pointerValueCodec(UnmarshalBERMSExtForwFeatureList, MarshalBERMSExtForwFeatureList, MarshalDERMSExtForwFeatureList)
}

// MSExtForwFeatureCodec binds MAP-MS-DataTypes.Ext-ForwFeature.
func MSExtForwFeatureCodec() ValueCodec[MSExtForwFeature] {
	return compositeValueCodec[MSExtForwFeature, *MSExtForwFeature]()
}

// MSExtForwOptionsCodec binds MAP-MS-DataTypes.Ext-ForwOptions.
func MSExtForwOptionsCodec() ValueCodec[BERValue[MSExtForwOptions]] {
	return octetValueCodec[MSExtForwOptions]("MAP-MS-DataTypes.Ext-ForwOptions", "Ext-ForwOptions", []primitiveRule[MSExtForwOptions]{{invalid: func(value MSExtForwOptions) bool { return !(len(value) >= 1 && len(value) <= 5) }, description: "SIZE (1..5)", clause: "51.5", length: func(value MSExtForwOptions) int { return len(value) }}})
}

// MSExtNoRepCondTimeCodec binds MAP-MS-DataTypes.Ext-NoRepCondTime.
func MSExtNoRepCondTimeCodec() ValueCodec[BERValue[MSExtNoRepCondTime]] {
	return integerValueCodec[MSExtNoRepCondTime]("MAP-MS-DataTypes.Ext-NoRepCondTime", "Ext-NoRepCondTime", []primitiveRule[MSExtNoRepCondTime]{{invalid: func(value MSExtNoRepCondTime) bool { return !(int64(value) >= 1 && int64(value) <= 100) }, description: "(1..100)", clause: "51.4", observed: func(value MSExtNoRepCondTime) any { return int64(value) }}}, false)
}

// MSExtCallBarInfoCodec binds MAP-MS-DataTypes.Ext-CallBarInfo.
func MSExtCallBarInfoCodec() ValueCodec[MSExtCallBarInfo] {
	return compositeValueCodec[MSExtCallBarInfo, *MSExtCallBarInfo]()
}

// MSExtCallBarFeatureListCodec binds MAP-MS-DataTypes.Ext-CallBarFeatureList.
func MSExtCallBarFeatureListCodec() ValueCodec[MSExtCallBarFeatureList] {
	return pointerValueCodec(UnmarshalBERMSExtCallBarFeatureList, MarshalBERMSExtCallBarFeatureList, MarshalDERMSExtCallBarFeatureList)
}

// MSExtCallBarringFeatureCodec binds MAP-MS-DataTypes.Ext-CallBarringFeature.
func MSExtCallBarringFeatureCodec() ValueCodec[MSExtCallBarringFeature] {
	return compositeValueCodec[MSExtCallBarringFeature, *MSExtCallBarringFeature]()
}

// MSCUGInfoCodec binds MAP-MS-DataTypes.CUG-Info.
func MSCUGInfoCodec() ValueCodec[MSCUGInfo] {
	return compositeValueCodec[MSCUGInfo, *MSCUGInfo]()
}

// MSCUGSubscriptionListCodec binds MAP-MS-DataTypes.CUG-SubscriptionList.
func MSCUGSubscriptionListCodec() ValueCodec[MSCUGSubscriptionList] {
	return pointerValueCodec(UnmarshalBERMSCUGSubscriptionList, MarshalBERMSCUGSubscriptionList, MarshalDERMSCUGSubscriptionList)
}

// MSCUGSubscriptionCodec binds MAP-MS-DataTypes.CUG-Subscription.
func MSCUGSubscriptionCodec() ValueCodec[MSCUGSubscription] {
	return compositeValueCodec[MSCUGSubscription, *MSCUGSubscription]()
}

// MSCUGIndexCodec binds MAP-MS-DataTypes.CUG-Index.
func MSCUGIndexCodec() ValueCodec[BERValue[MSCUGIndex]] {
	return integerValueCodec[MSCUGIndex]("MAP-MS-DataTypes.CUG-Index", "CUG-Index", []primitiveRule[MSCUGIndex]{{invalid: func(value MSCUGIndex) bool { return !(int64(value) >= 0 && int64(value) <= 32767) }, description: "(0..32767)", clause: "51.4", observed: func(value MSCUGIndex) any { return int64(value) }}}, false)
}

// MSCUGInterlockCodec binds MAP-MS-DataTypes.CUG-Interlock.
func MSCUGInterlockCodec() ValueCodec[BERValue[MSCUGInterlock]] {
	return octetValueCodec[MSCUGInterlock]("MAP-MS-DataTypes.CUG-Interlock", "CUG-Interlock", []primitiveRule[MSCUGInterlock]{{invalid: func(value MSCUGInterlock) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value MSCUGInterlock) int { return len(value) }}})
}

// MSIntraCUGOptionsCodec binds MAP-MS-DataTypes.IntraCUG-Options.
func MSIntraCUGOptionsCodec() ValueCodec[BERValue[MSIntraCUGOptions]] {
	return integerValueCodec[MSIntraCUGOptions]("MAP-MS-DataTypes.IntraCUG-Options", "IntraCUG-Options", []primitiveRule[MSIntraCUGOptions]{{invalid: func(value MSIntraCUGOptions) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value MSIntraCUGOptions) any { return int64(value) }}}, true)
}

// MSCUGFeatureListCodec binds MAP-MS-DataTypes.CUG-FeatureList.
func MSCUGFeatureListCodec() ValueCodec[MSCUGFeatureList] {
	return pointerValueCodec(UnmarshalBERMSCUGFeatureList, MarshalBERMSCUGFeatureList, MarshalDERMSCUGFeatureList)
}

// MSExtBasicServiceGroupListCodec binds MAP-MS-DataTypes.Ext-BasicServiceGroupList.
func MSExtBasicServiceGroupListCodec() ValueCodec[MSExtBasicServiceGroupList] {
	return pointerValueCodec(UnmarshalBERMSExtBasicServiceGroupList, MarshalBERMSExtBasicServiceGroupList, MarshalDERMSExtBasicServiceGroupList)
}

// MSCUGFeatureCodec binds MAP-MS-DataTypes.CUG-Feature.
func MSCUGFeatureCodec() ValueCodec[MSCUGFeature] {
	return compositeValueCodec[MSCUGFeature, *MSCUGFeature]()
}

// MSInterCUGRestrictionsCodec binds MAP-MS-DataTypes.InterCUG-Restrictions.
func MSInterCUGRestrictionsCodec() ValueCodec[BERValue[MSInterCUGRestrictions]] {
	return octetValueCodec[MSInterCUGRestrictions]("MAP-MS-DataTypes.InterCUG-Restrictions", "InterCUG-Restrictions", []primitiveRule[MSInterCUGRestrictions]{{invalid: func(value MSInterCUGRestrictions) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSInterCUGRestrictions) int { return len(value) }}})
}

// MSExtSSDataCodec binds MAP-MS-DataTypes.Ext-SS-Data.
func MSExtSSDataCodec() ValueCodec[MSExtSSData] {
	return compositeValueCodec[MSExtSSData, *MSExtSSData]()
}

// MSLCSPrivacyExceptionListCodec binds MAP-MS-DataTypes.LCS-PrivacyExceptionList.
func MSLCSPrivacyExceptionListCodec() ValueCodec[MSLCSPrivacyExceptionList] {
	return pointerValueCodec(UnmarshalBERMSLCSPrivacyExceptionList, MarshalBERMSLCSPrivacyExceptionList, MarshalDERMSLCSPrivacyExceptionList)
}

// MSLCSPrivacyClassCodec binds MAP-MS-DataTypes.LCS-PrivacyClass.
func MSLCSPrivacyClassCodec() ValueCodec[MSLCSPrivacyClass] {
	return compositeValueCodec[MSLCSPrivacyClass, *MSLCSPrivacyClass]()
}

// MSExternalClientListCodec binds MAP-MS-DataTypes.ExternalClientList.
func MSExternalClientListCodec() ValueCodec[MSExternalClientList] {
	return pointerValueCodec(UnmarshalBERMSExternalClientList, MarshalBERMSExternalClientList, MarshalDERMSExternalClientList)
}

// MSPLMNClientListCodec binds MAP-MS-DataTypes.PLMNClientList.
func MSPLMNClientListCodec() ValueCodec[MSPLMNClientList] {
	return pointerValueCodec(UnmarshalBERMSPLMNClientList, MarshalBERMSPLMNClientList, MarshalDERMSPLMNClientList)
}

// MSExtExternalClientListCodec binds MAP-MS-DataTypes.Ext-ExternalClientList.
func MSExtExternalClientListCodec() ValueCodec[MSExtExternalClientList] {
	return pointerValueCodec(UnmarshalBERMSExtExternalClientList, MarshalBERMSExtExternalClientList, MarshalDERMSExtExternalClientList)
}

// MSExternalClientCodec binds MAP-MS-DataTypes.ExternalClient.
func MSExternalClientCodec() ValueCodec[MSExternalClient] {
	return compositeValueCodec[MSExternalClient, *MSExternalClient]()
}

// MSGMLCRestrictionCodec binds MAP-MS-DataTypes.GMLC-Restriction.
func MSGMLCRestrictionCodec() ValueCodec[BERValue[MSGMLCRestriction]] {
	return integerValueCodec[MSGMLCRestriction]("MAP-MS-DataTypes.GMLC-Restriction", "GMLC-Restriction", nil, true)
}

// MSNotificationToMSUserCodec binds MAP-MS-DataTypes.NotificationToMSUser.
func MSNotificationToMSUserCodec() ValueCodec[BERValue[MSNotificationToMSUser]] {
	return integerValueCodec[MSNotificationToMSUser]("MAP-MS-DataTypes.NotificationToMSUser", "NotificationToMSUser", nil, true)
}

// MSServiceTypeListCodec binds MAP-MS-DataTypes.ServiceTypeList.
func MSServiceTypeListCodec() ValueCodec[MSServiceTypeList] {
	return pointerValueCodec(UnmarshalBERMSServiceTypeList, MarshalBERMSServiceTypeList, MarshalDERMSServiceTypeList)
}

// MSServiceTypeCodec binds MAP-MS-DataTypes.ServiceType.
func MSServiceTypeCodec() ValueCodec[MSServiceType] {
	return compositeValueCodec[MSServiceType, *MSServiceType]()
}

// MSMOLRListCodec binds MAP-MS-DataTypes.MOLR-List.
func MSMOLRListCodec() ValueCodec[MSMOLRList] {
	return pointerValueCodec(UnmarshalBERMSMOLRList, MarshalBERMSMOLRList, MarshalDERMSMOLRList)
}

// MSMOLRClassCodec binds MAP-MS-DataTypes.MOLR-Class.
func MSMOLRClassCodec() ValueCodec[MSMOLRClass] {
	return compositeValueCodec[MSMOLRClass, *MSMOLRClass]()
}

// MSZoneCodeListCodec binds MAP-MS-DataTypes.ZoneCodeList.
func MSZoneCodeListCodec() ValueCodec[MSZoneCodeList] {
	return pointerValueCodec(UnmarshalBERMSZoneCodeList, MarshalBERMSZoneCodeList, MarshalDERMSZoneCodeList)
}

// MSZoneCodeCodec binds MAP-MS-DataTypes.ZoneCode.
func MSZoneCodeCodec() ValueCodec[BERValue[MSZoneCode]] {
	return octetValueCodec[MSZoneCode]("MAP-MS-DataTypes.ZoneCode", "ZoneCode", []primitiveRule[MSZoneCode]{{invalid: func(value MSZoneCode) bool { return !(len(value) == 2) }, description: "SIZE (2)", clause: "51.5", length: func(value MSZoneCode) int { return len(value) }}})
}

// MSInsertSubscriberDataResCodec binds MAP-MS-DataTypes.InsertSubscriberDataRes.
func MSInsertSubscriberDataResCodec() ValueCodec[MSInsertSubscriberDataRes] {
	return compositeValueCodec[MSInsertSubscriberDataRes, *MSInsertSubscriberDataRes]()
}

// MSRegionalSubscriptionResponseCodec binds MAP-MS-DataTypes.RegionalSubscriptionResponse.
func MSRegionalSubscriptionResponseCodec() ValueCodec[BERValue[MSRegionalSubscriptionResponse]] {
	return integerValueCodec[MSRegionalSubscriptionResponse]("MAP-MS-DataTypes.RegionalSubscriptionResponse", "RegionalSubscriptionResponse", []primitiveRule[MSRegionalSubscriptionResponse]{{invalid: func(value MSRegionalSubscriptionResponse) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3)
	}, description: "ENUMERATED {0, 1, 2, 3}", clause: "20", observed: func(value MSRegionalSubscriptionResponse) any { return int64(value) }}}, true)
}

// MSDeleteSubscriberDataArgCodec binds MAP-MS-DataTypes.DeleteSubscriberDataArg.
func MSDeleteSubscriberDataArgCodec() ValueCodec[MSDeleteSubscriberDataArg] {
	return compositeValueCodec[MSDeleteSubscriberDataArg, *MSDeleteSubscriberDataArg]()
}

// MSSpecificCSIWithdrawCodec binds MAP-MS-DataTypes.SpecificCSI-Withdraw.
func MSSpecificCSIWithdrawCodec() ValueCodec[BERValue[MSSpecificCSIWithdraw]] {
	return bitValueCodec("MAP-MS-DataTypes.SpecificCSI-Withdraw", "SpecificCSI-Withdraw", []primitiveRule[MSSpecificCSIWithdraw]{{invalid: func(value MSSpecificCSIWithdraw) bool { return !(value.BitLength >= 8 && value.BitLength <= 32) }, description: "SIZE (8..32)", clause: "51.5", length: func(value MSSpecificCSIWithdraw) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 8, Max: 32}}})
}

// MSGPRSSubscriptionDataWithdrawCodec binds MAP-MS-DataTypes.GPRSSubscriptionDataWithdraw.
func MSGPRSSubscriptionDataWithdrawCodec() ValueCodec[MSGPRSSubscriptionDataWithdraw] {
	return compositeValueCodec[MSGPRSSubscriptionDataWithdraw, *MSGPRSSubscriptionDataWithdraw]()
}

// MSEPSSubscriptionDataWithdrawCodec binds MAP-MS-DataTypes.EPS-SubscriptionDataWithdraw.
func MSEPSSubscriptionDataWithdrawCodec() ValueCodec[MSEPSSubscriptionDataWithdraw] {
	return compositeValueCodec[MSEPSSubscriptionDataWithdraw, *MSEPSSubscriptionDataWithdraw]()
}

// MSContextIdListCodec binds MAP-MS-DataTypes.ContextIdList.
func MSContextIdListCodec() ValueCodec[MSContextIdList] {
	return pointerValueCodec(UnmarshalBERMSContextIdList, MarshalBERMSContextIdList, MarshalDERMSContextIdList)
}

// MSLSAInformationWithdrawCodec binds MAP-MS-DataTypes.LSAInformationWithdraw.
func MSLSAInformationWithdrawCodec() ValueCodec[MSLSAInformationWithdraw] {
	return compositeValueCodec[MSLSAInformationWithdraw, *MSLSAInformationWithdraw]()
}

// MSLSAIdentityListCodec binds MAP-MS-DataTypes.LSAIdentityList.
func MSLSAIdentityListCodec() ValueCodec[MSLSAIdentityList] {
	return pointerValueCodec(UnmarshalBERMSLSAIdentityList, MarshalBERMSLSAIdentityList, MarshalDERMSLSAIdentityList)
}

// MSBasicServiceListCodec binds MAP-MS-DataTypes.BasicServiceList.
func MSBasicServiceListCodec() ValueCodec[MSBasicServiceList] {
	return pointerValueCodec(UnmarshalBERMSBasicServiceList, MarshalBERMSBasicServiceList, MarshalDERMSBasicServiceList)
}

// MSDeleteSubscriberDataResCodec binds MAP-MS-DataTypes.DeleteSubscriberDataRes.
func MSDeleteSubscriberDataResCodec() ValueCodec[MSDeleteSubscriberDataRes] {
	return compositeValueCodec[MSDeleteSubscriberDataRes, *MSDeleteSubscriberDataRes]()
}

// MSVlrCamelSubscriptionInfoCodec binds MAP-MS-DataTypes.VlrCamelSubscriptionInfo.
func MSVlrCamelSubscriptionInfoCodec() ValueCodec[MSVlrCamelSubscriptionInfo] {
	return compositeValueCodec[MSVlrCamelSubscriptionInfo, *MSVlrCamelSubscriptionInfo]()
}

// MSMTSmsCAMELTDPCriteriaListCodec binds MAP-MS-DataTypes.MT-smsCAMELTDP-CriteriaList.
func MSMTSmsCAMELTDPCriteriaListCodec() ValueCodec[MSMTSmsCAMELTDPCriteriaList] {
	return pointerValueCodec(UnmarshalBERMSMTSmsCAMELTDPCriteriaList, MarshalBERMSMTSmsCAMELTDPCriteriaList, MarshalDERMSMTSmsCAMELTDPCriteriaList)
}

// MSMTSmsCAMELTDPCriteriaCodec binds MAP-MS-DataTypes.MT-smsCAMELTDP-Criteria.
func MSMTSmsCAMELTDPCriteriaCodec() ValueCodec[MSMTSmsCAMELTDPCriteria] {
	return compositeValueCodec[MSMTSmsCAMELTDPCriteria, *MSMTSmsCAMELTDPCriteria]()
}

// MSTPDUTypeCriterionCodec binds MAP-MS-DataTypes.TPDU-TypeCriterion.
func MSTPDUTypeCriterionCodec() ValueCodec[MSTPDUTypeCriterion] {
	return pointerValueCodec(UnmarshalBERMSTPDUTypeCriterion, MarshalBERMSTPDUTypeCriterion, MarshalDERMSTPDUTypeCriterion)
}

// MSMTSMSTPDUTypeCodec binds MAP-MS-DataTypes.MT-SMS-TPDU-Type.
func MSMTSMSTPDUTypeCodec() ValueCodec[BERValue[MSMTSMSTPDUType]] {
	return integerValueCodec[MSMTSMSTPDUType]("MAP-MS-DataTypes.MT-SMS-TPDU-Type", "MT-SMS-TPDU-Type", nil, true)
}

// MSDCSICodec binds MAP-MS-DataTypes.D-CSI.
func MSDCSICodec() ValueCodec[MSDCSI] {
	return compositeValueCodec[MSDCSI, *MSDCSI]()
}

// MSDPAnalysedInfoCriteriaListCodec binds MAP-MS-DataTypes.DP-AnalysedInfoCriteriaList.
func MSDPAnalysedInfoCriteriaListCodec() ValueCodec[MSDPAnalysedInfoCriteriaList] {
	return pointerValueCodec(UnmarshalBERMSDPAnalysedInfoCriteriaList, MarshalBERMSDPAnalysedInfoCriteriaList, MarshalDERMSDPAnalysedInfoCriteriaList)
}

// MSDPAnalysedInfoCriteriumCodec binds MAP-MS-DataTypes.DP-AnalysedInfoCriterium.
func MSDPAnalysedInfoCriteriumCodec() ValueCodec[MSDPAnalysedInfoCriterium] {
	return compositeValueCodec[MSDPAnalysedInfoCriterium, *MSDPAnalysedInfoCriterium]()
}

// MSSSCSICodec binds MAP-MS-DataTypes.SS-CSI.
func MSSSCSICodec() ValueCodec[MSSSCSI] {
	return compositeValueCodec[MSSSCSI, *MSSSCSI]()
}

// MSSSCamelDataCodec binds MAP-MS-DataTypes.SS-CamelData.
func MSSSCamelDataCodec() ValueCodec[MSSSCamelData] {
	return compositeValueCodec[MSSSCamelData, *MSSSCamelData]()
}

// MSSSEventListCodec binds MAP-MS-DataTypes.SS-EventList.
func MSSSEventListCodec() ValueCodec[MSSSEventList] {
	return pointerValueCodec(UnmarshalBERMSSSEventList, MarshalBERMSSSEventList, MarshalDERMSSSEventList)
}

// MSOCSICodec binds MAP-MS-DataTypes.O-CSI.
func MSOCSICodec() ValueCodec[MSOCSI] {
	return compositeValueCodec[MSOCSI, *MSOCSI]()
}

// MSOBcsmCamelTDPDataListCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPDataList.
func MSOBcsmCamelTDPDataListCodec() ValueCodec[MSOBcsmCamelTDPDataList] {
	return pointerValueCodec(UnmarshalBERMSOBcsmCamelTDPDataList, MarshalBERMSOBcsmCamelTDPDataList, MarshalDERMSOBcsmCamelTDPDataList)
}

// MSOBcsmCamelTDPDataCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPData.
func MSOBcsmCamelTDPDataCodec() ValueCodec[MSOBcsmCamelTDPData] {
	return compositeValueCodec[MSOBcsmCamelTDPData, *MSOBcsmCamelTDPData]()
}

// MSServiceKeyCodec binds MAP-MS-DataTypes.ServiceKey.
func MSServiceKeyCodec() ValueCodec[BERValue[MSServiceKey]] {
	return integerValueCodec[MSServiceKey]("MAP-MS-DataTypes.ServiceKey", "ServiceKey", []primitiveRule[MSServiceKey]{{invalid: func(value MSServiceKey) bool { return !(int64(value) >= 0 && int64(value) <= 2147483647) }, description: "(0..2147483647)", clause: "51.4", observed: func(value MSServiceKey) any { return int64(value) }}}, false)
}

// MSOBcsmTriggerDetectionPointCodec binds MAP-MS-DataTypes.O-BcsmTriggerDetectionPoint.
func MSOBcsmTriggerDetectionPointCodec() ValueCodec[BERValue[MSOBcsmTriggerDetectionPoint]] {
	return integerValueCodec[MSOBcsmTriggerDetectionPoint]("MAP-MS-DataTypes.O-BcsmTriggerDetectionPoint", "O-BcsmTriggerDetectionPoint", nil, true)
}

// MSOBcsmCamelTDPCriteriaListCodec binds MAP-MS-DataTypes.O-BcsmCamelTDPCriteriaList.
func MSOBcsmCamelTDPCriteriaListCodec() ValueCodec[MSOBcsmCamelTDPCriteriaList] {
	return pointerValueCodec(UnmarshalBERMSOBcsmCamelTDPCriteriaList, MarshalBERMSOBcsmCamelTDPCriteriaList, MarshalDERMSOBcsmCamelTDPCriteriaList)
}

// MSTBCSMCAMELTDPCriteriaListCodec binds MAP-MS-DataTypes.T-BCSM-CAMEL-TDP-CriteriaList.
func MSTBCSMCAMELTDPCriteriaListCodec() ValueCodec[MSTBCSMCAMELTDPCriteriaList] {
	return pointerValueCodec(UnmarshalBERMSTBCSMCAMELTDPCriteriaList, MarshalBERMSTBCSMCAMELTDPCriteriaList, MarshalDERMSTBCSMCAMELTDPCriteriaList)
}

// MSOBcsmCamelTDPCriteriaCodec binds MAP-MS-DataTypes.O-BcsmCamelTDP-Criteria.
func MSOBcsmCamelTDPCriteriaCodec() ValueCodec[MSOBcsmCamelTDPCriteria] {
	return compositeValueCodec[MSOBcsmCamelTDPCriteria, *MSOBcsmCamelTDPCriteria]()
}

// MSTBCSMCAMELTDPCriteriaCodec binds MAP-MS-DataTypes.T-BCSM-CAMEL-TDP-Criteria.
func MSTBCSMCAMELTDPCriteriaCodec() ValueCodec[MSTBCSMCAMELTDPCriteria] {
	return compositeValueCodec[MSTBCSMCAMELTDPCriteria, *MSTBCSMCAMELTDPCriteria]()
}

// MSDestinationNumberCriteriaCodec binds MAP-MS-DataTypes.DestinationNumberCriteria.
func MSDestinationNumberCriteriaCodec() ValueCodec[MSDestinationNumberCriteria] {
	return compositeValueCodec[MSDestinationNumberCriteria, *MSDestinationNumberCriteria]()
}

// MSDestinationNumberListCodec binds MAP-MS-DataTypes.DestinationNumberList.
func MSDestinationNumberListCodec() ValueCodec[MSDestinationNumberList] {
	return pointerValueCodec(UnmarshalBERMSDestinationNumberList, MarshalBERMSDestinationNumberList, MarshalDERMSDestinationNumberList)
}

// MSDestinationNumberLengthListCodec binds MAP-MS-DataTypes.DestinationNumberLengthList.
func MSDestinationNumberLengthListCodec() ValueCodec[MSDestinationNumberLengthList] {
	return pointerValueCodec(UnmarshalBERMSDestinationNumberLengthList, MarshalBERMSDestinationNumberLengthList, MarshalDERMSDestinationNumberLengthList)
}

// MSBasicServiceCriteriaCodec binds MAP-MS-DataTypes.BasicServiceCriteria.
func MSBasicServiceCriteriaCodec() ValueCodec[MSBasicServiceCriteria] {
	return pointerValueCodec(UnmarshalBERMSBasicServiceCriteria, MarshalBERMSBasicServiceCriteria, MarshalDERMSBasicServiceCriteria)
}

// MSCallTypeCriteriaCodec binds MAP-MS-DataTypes.CallTypeCriteria.
func MSCallTypeCriteriaCodec() ValueCodec[BERValue[MSCallTypeCriteria]] {
	return integerValueCodec[MSCallTypeCriteria]("MAP-MS-DataTypes.CallTypeCriteria", "CallTypeCriteria", []primitiveRule[MSCallTypeCriteria]{{invalid: func(value MSCallTypeCriteria) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSCallTypeCriteria) any { return int64(value) }}}, true)
}

// MSMatchTypeCodec binds MAP-MS-DataTypes.MatchType.
func MSMatchTypeCodec() ValueCodec[BERValue[MSMatchType]] {
	return integerValueCodec[MSMatchType]("MAP-MS-DataTypes.MatchType", "MatchType", []primitiveRule[MSMatchType]{{invalid: func(value MSMatchType) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSMatchType) any { return int64(value) }}}, true)
}

// MSOCauseValueCriteriaCodec binds MAP-MS-DataTypes.O-CauseValueCriteria.
func MSOCauseValueCriteriaCodec() ValueCodec[MSOCauseValueCriteria] {
	return pointerValueCodec(UnmarshalBERMSOCauseValueCriteria, MarshalBERMSOCauseValueCriteria, MarshalDERMSOCauseValueCriteria)
}

// MSTCauseValueCriteriaCodec binds MAP-MS-DataTypes.T-CauseValueCriteria.
func MSTCauseValueCriteriaCodec() ValueCodec[MSTCauseValueCriteria] {
	return pointerValueCodec(UnmarshalBERMSTCauseValueCriteria, MarshalBERMSTCauseValueCriteria, MarshalDERMSTCauseValueCriteria)
}

// MSCauseValueCodec binds MAP-MS-DataTypes.CauseValue.
func MSCauseValueCodec() ValueCodec[BERValue[MSCauseValue]] {
	return octetValueCodec[MSCauseValue]("MAP-MS-DataTypes.CauseValue", "CauseValue", []primitiveRule[MSCauseValue]{{invalid: func(value MSCauseValue) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSCauseValue) int { return len(value) }}})
}

// MSDefaultCallHandlingCodec binds MAP-MS-DataTypes.DefaultCallHandling.
func MSDefaultCallHandlingCodec() ValueCodec[BERValue[MSDefaultCallHandling]] {
	return integerValueCodec[MSDefaultCallHandling]("MAP-MS-DataTypes.DefaultCallHandling", "DefaultCallHandling", nil, true)
}

// MSCamelCapabilityHandlingCodec binds MAP-MS-DataTypes.CamelCapabilityHandling.
func MSCamelCapabilityHandlingCodec() ValueCodec[BERValue[MSCamelCapabilityHandling]] {
	return integerValueCodec[MSCamelCapabilityHandling]("MAP-MS-DataTypes.CamelCapabilityHandling", "CamelCapabilityHandling", []primitiveRule[MSCamelCapabilityHandling]{{invalid: func(value MSCamelCapabilityHandling) bool { return !(int64(value) >= 1 && int64(value) <= 16) }, description: "(1..16)", clause: "51.4", observed: func(value MSCamelCapabilityHandling) any { return int64(value) }}}, false)
}

// MSSupportedCamelPhasesCodec binds MAP-MS-DataTypes.SupportedCamelPhases.
func MSSupportedCamelPhasesCodec() ValueCodec[BERValue[MSSupportedCamelPhases]] {
	return bitValueCodec("MAP-MS-DataTypes.SupportedCamelPhases", "SupportedCamelPhases", []primitiveRule[MSSupportedCamelPhases]{{invalid: func(value MSSupportedCamelPhases) bool { return !(value.BitLength >= 1 && value.BitLength <= 16) }, description: "SIZE (1..16)", clause: "51.5", length: func(value MSSupportedCamelPhases) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}})
}

// MSOfferedCamel4CSIsCodec binds MAP-MS-DataTypes.OfferedCamel4CSIs.
func MSOfferedCamel4CSIsCodec() ValueCodec[BERValue[MSOfferedCamel4CSIs]] {
	return bitValueCodec("MAP-MS-DataTypes.OfferedCamel4CSIs", "OfferedCamel4CSIs", []primitiveRule[MSOfferedCamel4CSIs]{{invalid: func(value MSOfferedCamel4CSIs) bool { return !(value.BitLength >= 7 && value.BitLength <= 16) }, description: "SIZE (7..16)", clause: "51.5", length: func(value MSOfferedCamel4CSIs) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}})
}

// MSOfferedCamel4FunctionalitiesCodec binds MAP-MS-DataTypes.OfferedCamel4Functionalities.
func MSOfferedCamel4FunctionalitiesCodec() ValueCodec[BERValue[MSOfferedCamel4Functionalities]] {
	return bitValueCodec("MAP-MS-DataTypes.OfferedCamel4Functionalities", "OfferedCamel4Functionalities", []primitiveRule[MSOfferedCamel4Functionalities]{{invalid: func(value MSOfferedCamel4Functionalities) bool {
		return !(value.BitLength >= 15 && value.BitLength <= 64)
	}, description: "SIZE (15..64)", clause: "51.5", length: func(value MSOfferedCamel4Functionalities) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 15, Max: 64}}})
}

// MSSMSCSICodec binds MAP-MS-DataTypes.SMS-CSI.
func MSSMSCSICodec() ValueCodec[MSSMSCSI] {
	return compositeValueCodec[MSSMSCSI, *MSSMSCSI]()
}

// MSSMSCAMELTDPDataListCodec binds MAP-MS-DataTypes.SMS-CAMEL-TDP-DataList.
func MSSMSCAMELTDPDataListCodec() ValueCodec[MSSMSCAMELTDPDataList] {
	return pointerValueCodec(UnmarshalBERMSSMSCAMELTDPDataList, MarshalBERMSSMSCAMELTDPDataList, MarshalDERMSSMSCAMELTDPDataList)
}

// MSSMSCAMELTDPDataCodec binds MAP-MS-DataTypes.SMS-CAMEL-TDP-Data.
func MSSMSCAMELTDPDataCodec() ValueCodec[MSSMSCAMELTDPData] {
	return compositeValueCodec[MSSMSCAMELTDPData, *MSSMSCAMELTDPData]()
}

// MSSMSTriggerDetectionPointCodec binds MAP-MS-DataTypes.SMS-TriggerDetectionPoint.
func MSSMSTriggerDetectionPointCodec() ValueCodec[BERValue[MSSMSTriggerDetectionPoint]] {
	return integerValueCodec[MSSMSTriggerDetectionPoint]("MAP-MS-DataTypes.SMS-TriggerDetectionPoint", "SMS-TriggerDetectionPoint", nil, true)
}

// MSDefaultSMSHandlingCodec binds MAP-MS-DataTypes.DefaultSMS-Handling.
func MSDefaultSMSHandlingCodec() ValueCodec[BERValue[MSDefaultSMSHandling]] {
	return integerValueCodec[MSDefaultSMSHandling]("MAP-MS-DataTypes.DefaultSMS-Handling", "DefaultSMS-Handling", nil, true)
}

// MSMCSICodec binds MAP-MS-DataTypes.M-CSI.
func MSMCSICodec() ValueCodec[MSMCSI] {
	return compositeValueCodec[MSMCSI, *MSMCSI]()
}

// MSMGCSICodec binds MAP-MS-DataTypes.MG-CSI.
func MSMGCSICodec() ValueCodec[MSMGCSI] {
	return compositeValueCodec[MSMGCSI, *MSMGCSI]()
}

// MSMobilityTriggersCodec binds MAP-MS-DataTypes.MobilityTriggers.
func MSMobilityTriggersCodec() ValueCodec[MSMobilityTriggers] {
	return pointerValueCodec(UnmarshalBERMSMobilityTriggers, MarshalBERMSMobilityTriggers, MarshalDERMSMobilityTriggers)
}

// MSMMCodeCodec binds MAP-MS-DataTypes.MM-Code.
func MSMMCodeCodec() ValueCodec[BERValue[MSMMCode]] {
	return octetValueCodec[MSMMCode]("MAP-MS-DataTypes.MM-Code", "MM-Code", []primitiveRule[MSMMCode]{{invalid: func(value MSMMCode) bool { return !(len(value) == 1) }, description: "SIZE (1)", clause: "51.5", length: func(value MSMMCode) int { return len(value) }}})
}

// MSTCSICodec binds MAP-MS-DataTypes.T-CSI.
func MSTCSICodec() ValueCodec[MSTCSI] {
	return compositeValueCodec[MSTCSI, *MSTCSI]()
}

// MSTBcsmCamelTDPDataListCodec binds MAP-MS-DataTypes.T-BcsmCamelTDPDataList.
func MSTBcsmCamelTDPDataListCodec() ValueCodec[MSTBcsmCamelTDPDataList] {
	return pointerValueCodec(UnmarshalBERMSTBcsmCamelTDPDataList, MarshalBERMSTBcsmCamelTDPDataList, MarshalDERMSTBcsmCamelTDPDataList)
}

// MSTBcsmCamelTDPDataCodec binds MAP-MS-DataTypes.T-BcsmCamelTDPData.
func MSTBcsmCamelTDPDataCodec() ValueCodec[MSTBcsmCamelTDPData] {
	return compositeValueCodec[MSTBcsmCamelTDPData, *MSTBcsmCamelTDPData]()
}

// MSTBcsmTriggerDetectionPointCodec binds MAP-MS-DataTypes.T-BcsmTriggerDetectionPoint.
func MSTBcsmTriggerDetectionPointCodec() ValueCodec[BERValue[MSTBcsmTriggerDetectionPoint]] {
	return integerValueCodec[MSTBcsmTriggerDetectionPoint]("MAP-MS-DataTypes.T-BcsmTriggerDetectionPoint", "T-BcsmTriggerDetectionPoint", nil, true)
}

// MSSendRoutingInfoForGprsArgCodec binds MAP-MS-DataTypes.SendRoutingInfoForGprsArg.
func MSSendRoutingInfoForGprsArgCodec() ValueCodec[MSSendRoutingInfoForGprsArg] {
	return compositeValueCodec[MSSendRoutingInfoForGprsArg, *MSSendRoutingInfoForGprsArg]()
}

// MSSendRoutingInfoForGprsResCodec binds MAP-MS-DataTypes.SendRoutingInfoForGprsRes.
func MSSendRoutingInfoForGprsResCodec() ValueCodec[MSSendRoutingInfoForGprsRes] {
	return compositeValueCodec[MSSendRoutingInfoForGprsRes, *MSSendRoutingInfoForGprsRes]()
}

// MSFailureReportArgCodec binds MAP-MS-DataTypes.FailureReportArg.
func MSFailureReportArgCodec() ValueCodec[MSFailureReportArg] {
	return compositeValueCodec[MSFailureReportArg, *MSFailureReportArg]()
}

// MSFailureReportResCodec binds MAP-MS-DataTypes.FailureReportRes.
func MSFailureReportResCodec() ValueCodec[MSFailureReportRes] {
	return compositeValueCodec[MSFailureReportRes, *MSFailureReportRes]()
}

// MSNoteMsPresentForGprsArgCodec binds MAP-MS-DataTypes.NoteMsPresentForGprsArg.
func MSNoteMsPresentForGprsArgCodec() ValueCodec[MSNoteMsPresentForGprsArg] {
	return compositeValueCodec[MSNoteMsPresentForGprsArg, *MSNoteMsPresentForGprsArg]()
}

// MSNoteMsPresentForGprsResCodec binds MAP-MS-DataTypes.NoteMsPresentForGprsRes.
func MSNoteMsPresentForGprsResCodec() ValueCodec[MSNoteMsPresentForGprsRes] {
	return compositeValueCodec[MSNoteMsPresentForGprsRes, *MSNoteMsPresentForGprsRes]()
}

// MSResetArgCodec binds MAP-MS-DataTypes.ResetArg.
func MSResetArgCodec() ValueCodec[MSResetArg] {
	return compositeValueCodec[MSResetArg, *MSResetArg]()
}

// MSSendingNodeNumberCodec binds MAP-MS-DataTypes.SendingNode-Number.
func MSSendingNodeNumberCodec() ValueCodec[MSSendingNodeNumber] {
	return compositeValueCodec[MSSendingNodeNumber, *MSSendingNodeNumber]()
}

// MSRestoreDataArgCodec binds MAP-MS-DataTypes.RestoreDataArg.
func MSRestoreDataArgCodec() ValueCodec[MSRestoreDataArg] {
	return compositeValueCodec[MSRestoreDataArg, *MSRestoreDataArg]()
}

// MSRestoreDataResCodec binds MAP-MS-DataTypes.RestoreDataRes.
func MSRestoreDataResCodec() ValueCodec[MSRestoreDataRes] {
	return compositeValueCodec[MSRestoreDataRes, *MSRestoreDataRes]()
}

// MSVBSDataListCodec binds MAP-MS-DataTypes.VBSDataList.
func MSVBSDataListCodec() ValueCodec[MSVBSDataList] {
	return pointerValueCodec(UnmarshalBERMSVBSDataList, MarshalBERMSVBSDataList, MarshalDERMSVBSDataList)
}

// MSVGCSDataListCodec binds MAP-MS-DataTypes.VGCSDataList.
func MSVGCSDataListCodec() ValueCodec[MSVGCSDataList] {
	return pointerValueCodec(UnmarshalBERMSVGCSDataList, MarshalBERMSVGCSDataList, MarshalDERMSVGCSDataList)
}

// MSVoiceGroupCallDataCodec binds MAP-MS-DataTypes.VoiceGroupCallData.
func MSVoiceGroupCallDataCodec() ValueCodec[MSVoiceGroupCallData] {
	return compositeValueCodec[MSVoiceGroupCallData, *MSVoiceGroupCallData]()
}

// MSAdditionalInfoCodec binds MAP-MS-DataTypes.AdditionalInfo.
func MSAdditionalInfoCodec() ValueCodec[BERValue[MSAdditionalInfo]] {
	return bitValueCodec("MAP-MS-DataTypes.AdditionalInfo", "AdditionalInfo", []primitiveRule[MSAdditionalInfo]{{invalid: func(value MSAdditionalInfo) bool { return !(value.BitLength >= 1 && value.BitLength <= 136) }, description: "SIZE (1..136)", clause: "51.5", length: func(value MSAdditionalInfo) int { return value.BitLength }}}, false, []ber.NamedBitSizeSet{{{Min: 1, Max: 136}}})
}

// MSAdditionalSubscriptionsCodec binds MAP-MS-DataTypes.AdditionalSubscriptions.
func MSAdditionalSubscriptionsCodec() ValueCodec[BERValue[MSAdditionalSubscriptions]] {
	return bitValueCodec("MAP-MS-DataTypes.AdditionalSubscriptions", "AdditionalSubscriptions", []primitiveRule[MSAdditionalSubscriptions]{{invalid: func(value MSAdditionalSubscriptions) bool { return !(value.BitLength >= 3 && value.BitLength <= 8) }, description: "SIZE (3..8)", clause: "51.5", length: func(value MSAdditionalSubscriptions) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}})
}

// MSVoiceBroadcastDataCodec binds MAP-MS-DataTypes.VoiceBroadcastData.
func MSVoiceBroadcastDataCodec() ValueCodec[MSVoiceBroadcastData] {
	return compositeValueCodec[MSVoiceBroadcastData, *MSVoiceBroadcastData]()
}

// MSGroupIdCodec binds MAP-MS-DataTypes.GroupId.
func MSGroupIdCodec() ValueCodec[BERValue[MSGroupId]] {
	return pointerValueCodec(UnmarshalBERMSGroupId, MarshalBERMSGroupId, MarshalDERMSGroupId)
}

// MSLongGroupIdCodec binds MAP-MS-DataTypes.Long-GroupId.
func MSLongGroupIdCodec() ValueCodec[BERValue[MSLongGroupId]] {
	return pointerValueCodec(UnmarshalBERMSLongGroupId, MarshalBERMSLongGroupId, MarshalDERMSLongGroupId)
}

// MSProvideSubscriberInfoArgCodec binds MAP-MS-DataTypes.ProvideSubscriberInfoArg.
func MSProvideSubscriberInfoArgCodec() ValueCodec[MSProvideSubscriberInfoArg] {
	return compositeValueCodec[MSProvideSubscriberInfoArg, *MSProvideSubscriberInfoArg]()
}

// MSProvideSubscriberInfoResCodec binds MAP-MS-DataTypes.ProvideSubscriberInfoRes.
func MSProvideSubscriberInfoResCodec() ValueCodec[MSProvideSubscriberInfoRes] {
	return compositeValueCodec[MSProvideSubscriberInfoRes, *MSProvideSubscriberInfoRes]()
}

// MSSubscriberInfoCodec binds MAP-MS-DataTypes.SubscriberInfo.
func MSSubscriberInfoCodec() ValueCodec[MSSubscriberInfo] {
	return compositeValueCodec[MSSubscriberInfo, *MSSubscriberInfo]()
}

// MSIMSVoiceOverPSSessionsIndCodec binds MAP-MS-DataTypes.IMS-VoiceOverPS-SessionsInd.
func MSIMSVoiceOverPSSessionsIndCodec() ValueCodec[BERValue[MSIMSVoiceOverPSSessionsInd]] {
	return integerValueCodec[MSIMSVoiceOverPSSessionsInd]("MAP-MS-DataTypes.IMS-VoiceOverPS-SessionsInd", "IMS-VoiceOverPS-SessionsInd", []primitiveRule[MSIMSVoiceOverPSSessionsInd]{{invalid: func(value MSIMSVoiceOverPSSessionsInd) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value MSIMSVoiceOverPSSessionsInd) any { return int64(value) }}}, true)
}

// MSTimeZoneCodec binds MAP-MS-DataTypes.TimeZone.
func MSTimeZoneCodec() ValueCodec[BERValue[MSTimeZone]] {
	return octetValueCodec[MSTimeZone]("MAP-MS-DataTypes.TimeZone", "TimeZone", []primitiveRule[MSTimeZone]{{invalid: func(value MSTimeZone) bool { return !(len(value) >= 2 && len(value) <= 3) }, description: "SIZE (2..3)", clause: "51.5", length: func(value MSTimeZone) int { return len(value) }}})
}

// MSDaylightSavingTimeCodec binds MAP-MS-DataTypes.DaylightSavingTime.
func MSDaylightSavingTimeCodec() ValueCodec[BERValue[MSDaylightSavingTime]] {
	return integerValueCodec[MSDaylightSavingTime]("MAP-MS-DataTypes.DaylightSavingTime", "DaylightSavingTime", []primitiveRule[MSDaylightSavingTime]{{invalid: func(value MSDaylightSavingTime) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2)
	}, description: "ENUMERATED {0, 1, 2}", clause: "20", observed: func(value MSDaylightSavingTime) any { return int64(value) }}}, true)
}

// MSMNPInfoResCodec binds MAP-MS-DataTypes.MNPInfoRes.
func MSMNPInfoResCodec() ValueCodec[MSMNPInfoRes] {
	return compositeValueCodec[MSMNPInfoRes, *MSMNPInfoRes]()
}

// MSRouteingNumberCodec binds MAP-MS-DataTypes.RouteingNumber.
func MSRouteingNumberCodec() ValueCodec[BERValue[MSRouteingNumber]] {
	return pointerValueCodec(UnmarshalBERMSRouteingNumber, MarshalBERMSRouteingNumber, MarshalDERMSRouteingNumber)
}

// MSNumberPortabilityStatusCodec binds MAP-MS-DataTypes.NumberPortabilityStatus.
func MSNumberPortabilityStatusCodec() ValueCodec[BERValue[MSNumberPortabilityStatus]] {
	return integerValueCodec[MSNumberPortabilityStatus]("MAP-MS-DataTypes.NumberPortabilityStatus", "NumberPortabilityStatus", nil, true)
}

// MSMSClassmark2Codec binds MAP-MS-DataTypes.MS-Classmark2.
func MSMSClassmark2Codec() ValueCodec[BERValue[MSMSClassmark2]] {
	return octetValueCodec[MSMSClassmark2]("MAP-MS-DataTypes.MS-Classmark2", "MS-Classmark2", []primitiveRule[MSMSClassmark2]{{invalid: func(value MSMSClassmark2) bool { return !(len(value) == 3) }, description: "SIZE (3)", clause: "51.5", length: func(value MSMSClassmark2) int { return len(value) }}})
}

// MSGPRSMSClassCodec binds MAP-MS-DataTypes.GPRSMSClass.
func MSGPRSMSClassCodec() ValueCodec[MSGPRSMSClass] {
	return compositeValueCodec[MSGPRSMSClass, *MSGPRSMSClass]()
}

// MSMSNetworkCapabilityCodec binds MAP-MS-DataTypes.MSNetworkCapability.
func MSMSNetworkCapabilityCodec() ValueCodec[BERValue[MSMSNetworkCapability]] {
	return octetValueCodec[MSMSNetworkCapability]("MAP-MS-DataTypes.MSNetworkCapability", "MSNetworkCapability", []primitiveRule[MSMSNetworkCapability]{{invalid: func(value MSMSNetworkCapability) bool { return !(len(value) >= 1 && len(value) <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value MSMSNetworkCapability) int { return len(value) }}})
}

// MSMSRadioAccessCapabilityCodec binds MAP-MS-DataTypes.MSRadioAccessCapability.
func MSMSRadioAccessCapabilityCodec() ValueCodec[BERValue[MSMSRadioAccessCapability]] {
	return octetValueCodec[MSMSRadioAccessCapability]("MAP-MS-DataTypes.MSRadioAccessCapability", "MSRadioAccessCapability", []primitiveRule[MSMSRadioAccessCapability]{{invalid: func(value MSMSRadioAccessCapability) bool { return !(len(value) >= 1 && len(value) <= 50) }, description: "SIZE (1..50)", clause: "51.5", length: func(value MSMSRadioAccessCapability) int { return len(value) }}})
}

// MSRequestedInfoCodec binds MAP-MS-DataTypes.RequestedInfo.
func MSRequestedInfoCodec() ValueCodec[MSRequestedInfo] {
	return compositeValueCodec[MSRequestedInfo, *MSRequestedInfo]()
}

// MSDomainTypeCodec binds MAP-MS-DataTypes.DomainType.
func MSDomainTypeCodec() ValueCodec[BERValue[MSDomainType]] {
	return integerValueCodec[MSDomainType]("MAP-MS-DataTypes.DomainType", "DomainType", nil, true)
}

// MSRequestedNodesCodec binds MAP-MS-DataTypes.RequestedNodes.
func MSRequestedNodesCodec() ValueCodec[BERValue[MSRequestedNodes]] {
	return bitValueCodec("MAP-MS-DataTypes.RequestedNodes", "RequestedNodes", []primitiveRule[MSRequestedNodes]{{invalid: func(value MSRequestedNodes) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value MSRequestedNodes) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// MSLocationInformationCodec binds MAP-MS-DataTypes.LocationInformation.
func MSLocationInformationCodec() ValueCodec[MSLocationInformation] {
	return compositeValueCodec[MSLocationInformation, *MSLocationInformation]()
}

// MSLocationInformationEPSCodec binds MAP-MS-DataTypes.LocationInformationEPS.
func MSLocationInformationEPSCodec() ValueCodec[MSLocationInformationEPS] {
	return compositeValueCodec[MSLocationInformationEPS, *MSLocationInformationEPS]()
}

// MSLocationInformationGPRSCodec binds MAP-MS-DataTypes.LocationInformationGPRS.
func MSLocationInformationGPRSCodec() ValueCodec[MSLocationInformationGPRS] {
	return compositeValueCodec[MSLocationInformationGPRS, *MSLocationInformationGPRS]()
}

// MSLocationInformation5GSCodec binds MAP-MS-DataTypes.LocationInformation5GS.
func MSLocationInformation5GSCodec() ValueCodec[MSLocationInformation5GS] {
	return compositeValueCodec[MSLocationInformation5GS, *MSLocationInformation5GS]()
}

// MSUserCSGInformationCodec binds MAP-MS-DataTypes.UserCSGInformation.
func MSUserCSGInformationCodec() ValueCodec[MSUserCSGInformation] {
	return compositeValueCodec[MSUserCSGInformation, *MSUserCSGInformation]()
}

// MSGeographicalInformationCodec binds MAP-MS-DataTypes.GeographicalInformation.
func MSGeographicalInformationCodec() ValueCodec[BERValue[MSGeographicalInformation]] {
	return octetValueCodec[MSGeographicalInformation]("MAP-MS-DataTypes.GeographicalInformation", "GeographicalInformation", []primitiveRule[MSGeographicalInformation]{{invalid: func(value MSGeographicalInformation) bool { return !(len(value) == 8) }, description: "SIZE (8)", clause: "51.5", length: func(value MSGeographicalInformation) int { return len(value) }}})
}

// MSGeodeticInformationCodec binds MAP-MS-DataTypes.GeodeticInformation.
func MSGeodeticInformationCodec() ValueCodec[BERValue[MSGeodeticInformation]] {
	return octetValueCodec[MSGeodeticInformation]("MAP-MS-DataTypes.GeodeticInformation", "GeodeticInformation", []primitiveRule[MSGeodeticInformation]{{invalid: func(value MSGeodeticInformation) bool { return !(len(value) == 10) }, description: "SIZE (10)", clause: "51.5", length: func(value MSGeodeticInformation) int { return len(value) }}})
}

// MSLocationNumberCodec binds MAP-MS-DataTypes.LocationNumber.
func MSLocationNumberCodec() ValueCodec[BERValue[MSLocationNumber]] {
	return octetValueCodec[MSLocationNumber]("MAP-MS-DataTypes.LocationNumber", "LocationNumber", []primitiveRule[MSLocationNumber]{{invalid: func(value MSLocationNumber) bool { return !(len(value) >= 2 && len(value) <= 10) }, description: "SIZE (2..10)", clause: "51.5", length: func(value MSLocationNumber) int { return len(value) }}})
}

// MSSubscriberStateCodec binds MAP-MS-DataTypes.SubscriberState.
func MSSubscriberStateCodec() ValueCodec[MSSubscriberState] {
	return compositeValueCodec[MSSubscriberState, *MSSubscriberState]()
}

// MSPSSubscriberStateCodec binds MAP-MS-DataTypes.PS-SubscriberState.
func MSPSSubscriberStateCodec() ValueCodec[MSPSSubscriberState] {
	return compositeValueCodec[MSPSSubscriberState, *MSPSSubscriberState]()
}

// MSPDPContextInfoListCodec binds MAP-MS-DataTypes.PDP-ContextInfoList.
func MSPDPContextInfoListCodec() ValueCodec[MSPDPContextInfoList] {
	return pointerValueCodec(UnmarshalBERMSPDPContextInfoList, MarshalBERMSPDPContextInfoList, MarshalDERMSPDPContextInfoList)
}

// MSPDPContextInfoCodec binds MAP-MS-DataTypes.PDP-ContextInfo.
func MSPDPContextInfoCodec() ValueCodec[MSPDPContextInfo] {
	return compositeValueCodec[MSPDPContextInfo, *MSPDPContextInfo]()
}

// MSNSAPICodec binds MAP-MS-DataTypes.NSAPI.
func MSNSAPICodec() ValueCodec[BERValue[MSNSAPI]] {
	return integerValueCodec[MSNSAPI]("MAP-MS-DataTypes.NSAPI", "NSAPI", []primitiveRule[MSNSAPI]{{invalid: func(value MSNSAPI) bool { return !(int64(value) >= 0 && int64(value) <= 15) }, description: "(0..15)", clause: "51.4", observed: func(value MSNSAPI) any { return int64(value) }}}, false)
}

// MSTransactionIdCodec binds MAP-MS-DataTypes.TransactionId.
func MSTransactionIdCodec() ValueCodec[BERValue[MSTransactionId]] {
	return octetValueCodec[MSTransactionId]("MAP-MS-DataTypes.TransactionId", "TransactionId", []primitiveRule[MSTransactionId]{{invalid: func(value MSTransactionId) bool { return !(len(value) >= 1 && len(value) <= 2) }, description: "SIZE (1..2)", clause: "51.5", length: func(value MSTransactionId) int { return len(value) }}})
}

// MSTEIDCodec binds MAP-MS-DataTypes.TEID.
func MSTEIDCodec() ValueCodec[BERValue[MSTEID]] {
	return octetValueCodec[MSTEID]("MAP-MS-DataTypes.TEID", "TEID", []primitiveRule[MSTEID]{{invalid: func(value MSTEID) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value MSTEID) int { return len(value) }}})
}

// MSGPRSChargingIDCodec binds MAP-MS-DataTypes.GPRSChargingID.
func MSGPRSChargingIDCodec() ValueCodec[BERValue[MSGPRSChargingID]] {
	return octetValueCodec[MSGPRSChargingID]("MAP-MS-DataTypes.GPRSChargingID", "GPRSChargingID", []primitiveRule[MSGPRSChargingID]{{invalid: func(value MSGPRSChargingID) bool { return !(len(value) == 4) }, description: "SIZE (4)", clause: "51.5", length: func(value MSGPRSChargingID) int { return len(value) }}})
}

// MSNotReachableReasonCodec binds MAP-MS-DataTypes.NotReachableReason.
func MSNotReachableReasonCodec() ValueCodec[BERValue[MSNotReachableReason]] {
	return integerValueCodec[MSNotReachableReason]("MAP-MS-DataTypes.NotReachableReason", "NotReachableReason", []primitiveRule[MSNotReachableReason]{{invalid: func(value MSNotReachableReason) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3)
	}, description: "ENUMERATED {0, 1, 2, 3}", clause: "20", observed: func(value MSNotReachableReason) any { return int64(value) }}}, true)
}

// MSAnyTimeInterrogationArgCodec binds MAP-MS-DataTypes.AnyTimeInterrogationArg.
func MSAnyTimeInterrogationArgCodec() ValueCodec[MSAnyTimeInterrogationArg] {
	return compositeValueCodec[MSAnyTimeInterrogationArg, *MSAnyTimeInterrogationArg]()
}

// MSAnyTimeInterrogationResCodec binds MAP-MS-DataTypes.AnyTimeInterrogationRes.
func MSAnyTimeInterrogationResCodec() ValueCodec[MSAnyTimeInterrogationRes] {
	return compositeValueCodec[MSAnyTimeInterrogationRes, *MSAnyTimeInterrogationRes]()
}

// MSAnyTimeSubscriptionInterrogationArgCodec binds MAP-MS-DataTypes.AnyTimeSubscriptionInterrogationArg.
func MSAnyTimeSubscriptionInterrogationArgCodec() ValueCodec[MSAnyTimeSubscriptionInterrogationArg] {
	return compositeValueCodec[MSAnyTimeSubscriptionInterrogationArg, *MSAnyTimeSubscriptionInterrogationArg]()
}

// MSAnyTimeSubscriptionInterrogationResCodec binds MAP-MS-DataTypes.AnyTimeSubscriptionInterrogationRes.
func MSAnyTimeSubscriptionInterrogationResCodec() ValueCodec[MSAnyTimeSubscriptionInterrogationRes] {
	return compositeValueCodec[MSAnyTimeSubscriptionInterrogationRes, *MSAnyTimeSubscriptionInterrogationRes]()
}

// MSCallWaitingDataCodec binds MAP-MS-DataTypes.CallWaitingData.
func MSCallWaitingDataCodec() ValueCodec[MSCallWaitingData] {
	return compositeValueCodec[MSCallWaitingData, *MSCallWaitingData]()
}

// MSExtCwFeatureListCodec binds MAP-MS-DataTypes.Ext-CwFeatureList.
func MSExtCwFeatureListCodec() ValueCodec[MSExtCwFeatureList] {
	return pointerValueCodec(UnmarshalBERMSExtCwFeatureList, MarshalBERMSExtCwFeatureList, MarshalDERMSExtCwFeatureList)
}

// MSExtCwFeatureCodec binds MAP-MS-DataTypes.Ext-CwFeature.
func MSExtCwFeatureCodec() ValueCodec[MSExtCwFeature] {
	return compositeValueCodec[MSExtCwFeature, *MSExtCwFeature]()
}

// MSClipDataCodec binds MAP-MS-DataTypes.ClipData.
func MSClipDataCodec() ValueCodec[MSClipData] {
	return compositeValueCodec[MSClipData, *MSClipData]()
}

// MSClirDataCodec binds MAP-MS-DataTypes.ClirData.
func MSClirDataCodec() ValueCodec[MSClirData] {
	return compositeValueCodec[MSClirData, *MSClirData]()
}

// MSCallHoldDataCodec binds MAP-MS-DataTypes.CallHoldData.
func MSCallHoldDataCodec() ValueCodec[MSCallHoldData] {
	return compositeValueCodec[MSCallHoldData, *MSCallHoldData]()
}

// MSEctDataCodec binds MAP-MS-DataTypes.EctData.
func MSEctDataCodec() ValueCodec[MSEctData] {
	return compositeValueCodec[MSEctData, *MSEctData]()
}

// MSRequestedSubscriptionInfoCodec binds MAP-MS-DataTypes.RequestedSubscriptionInfo.
func MSRequestedSubscriptionInfoCodec() ValueCodec[MSRequestedSubscriptionInfo] {
	return compositeValueCodec[MSRequestedSubscriptionInfo, *MSRequestedSubscriptionInfo]()
}

// MSMSISDNBSListCodec binds MAP-MS-DataTypes.MSISDN-BS-List.
func MSMSISDNBSListCodec() ValueCodec[MSMSISDNBSList] {
	return pointerValueCodec(UnmarshalBERMSMSISDNBSList, MarshalBERMSMSISDNBSList, MarshalDERMSMSISDNBSList)
}

// MSMSISDNBSCodec binds MAP-MS-DataTypes.MSISDN-BS.
func MSMSISDNBSCodec() ValueCodec[MSMSISDNBS] {
	return compositeValueCodec[MSMSISDNBS, *MSMSISDNBS]()
}

// MSRequestedCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.RequestedCAMEL-SubscriptionInfo.
func MSRequestedCAMELSubscriptionInfoCodec() ValueCodec[BERValue[MSRequestedCAMELSubscriptionInfo]] {
	return integerValueCodec[MSRequestedCAMELSubscriptionInfo]("MAP-MS-DataTypes.RequestedCAMEL-SubscriptionInfo", "RequestedCAMEL-SubscriptionInfo", []primitiveRule[MSRequestedCAMELSubscriptionInfo]{{invalid: func(value MSRequestedCAMELSubscriptionInfo) bool {
		return (int64(value) != 0 && int64(value) != 1 && int64(value) != 2 && int64(value) != 3 && int64(value) != 4 && int64(value) != 5 && int64(value) != 6 && int64(value) != 7 && int64(value) != 8)
	}, description: "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8}", clause: "20", observed: func(value MSRequestedCAMELSubscriptionInfo) any { return int64(value) }}}, true)
}

// MSAdditionalRequestedCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.AdditionalRequestedCAMEL-SubscriptionInfo.
func MSAdditionalRequestedCAMELSubscriptionInfoCodec() ValueCodec[BERValue[MSAdditionalRequestedCAMELSubscriptionInfo]] {
	return integerValueCodec[MSAdditionalRequestedCAMELSubscriptionInfo]("MAP-MS-DataTypes.AdditionalRequestedCAMEL-SubscriptionInfo", "AdditionalRequestedCAMEL-SubscriptionInfo", nil, true)
}

// MSCallForwardingDataCodec binds MAP-MS-DataTypes.CallForwardingData.
func MSCallForwardingDataCodec() ValueCodec[MSCallForwardingData] {
	return compositeValueCodec[MSCallForwardingData, *MSCallForwardingData]()
}

// MSCallBarringDataCodec binds MAP-MS-DataTypes.CallBarringData.
func MSCallBarringDataCodec() ValueCodec[MSCallBarringData] {
	return compositeValueCodec[MSCallBarringData, *MSCallBarringData]()
}

// MSWrongPasswordAttemptsCounterCodec binds MAP-MS-DataTypes.WrongPasswordAttemptsCounter.
func MSWrongPasswordAttemptsCounterCodec() ValueCodec[BERValue[MSWrongPasswordAttemptsCounter]] {
	return integerValueCodec[MSWrongPasswordAttemptsCounter]("MAP-MS-DataTypes.WrongPasswordAttemptsCounter", "WrongPasswordAttemptsCounter", []primitiveRule[MSWrongPasswordAttemptsCounter]{{invalid: func(value MSWrongPasswordAttemptsCounter) bool { return !(int64(value) >= 0 && int64(value) <= 4) }, description: "(0..4)", clause: "51.4", observed: func(value MSWrongPasswordAttemptsCounter) any { return int64(value) }}}, false)
}

// MSODBInfoCodec binds MAP-MS-DataTypes.ODB-Info.
func MSODBInfoCodec() ValueCodec[MSODBInfo] {
	return compositeValueCodec[MSODBInfo, *MSODBInfo]()
}

// MSCAMELSubscriptionInfoCodec binds MAP-MS-DataTypes.CAMEL-SubscriptionInfo.
func MSCAMELSubscriptionInfoCodec() ValueCodec[MSCAMELSubscriptionInfo] {
	return compositeValueCodec[MSCAMELSubscriptionInfo, *MSCAMELSubscriptionInfo]()
}

// MSAnyTimeModificationArgCodec binds MAP-MS-DataTypes.AnyTimeModificationArg.
func MSAnyTimeModificationArgCodec() ValueCodec[MSAnyTimeModificationArg] {
	return compositeValueCodec[MSAnyTimeModificationArg, *MSAnyTimeModificationArg]()
}

// MSModificationRequestForCWInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CW-Info.
func MSModificationRequestForCWInfoCodec() ValueCodec[MSModificationRequestForCWInfo] {
	return compositeValueCodec[MSModificationRequestForCWInfo, *MSModificationRequestForCWInfo]()
}

// MSModificationRequestForCHInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CH-Info.
func MSModificationRequestForCHInfoCodec() ValueCodec[MSModificationRequestForCHInfo] {
	return compositeValueCodec[MSModificationRequestForCHInfo, *MSModificationRequestForCHInfo]()
}

// MSModificationRequestForECTInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-ECT-Info.
func MSModificationRequestForECTInfoCodec() ValueCodec[MSModificationRequestForECTInfo] {
	return compositeValueCodec[MSModificationRequestForECTInfo, *MSModificationRequestForECTInfo]()
}

// MSModificationRequestForCLIRInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CLIR-Info.
func MSModificationRequestForCLIRInfoCodec() ValueCodec[MSModificationRequestForCLIRInfo] {
	return compositeValueCodec[MSModificationRequestForCLIRInfo, *MSModificationRequestForCLIRInfo]()
}

// MSModificationRequestForCLIPInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CLIP-Info.
func MSModificationRequestForCLIPInfoCodec() ValueCodec[MSModificationRequestForCLIPInfo] {
	return compositeValueCodec[MSModificationRequestForCLIPInfo, *MSModificationRequestForCLIPInfo]()
}

// MSModificationRequestForCSGCodec binds MAP-MS-DataTypes.ModificationRequestFor-CSG.
func MSModificationRequestForCSGCodec() ValueCodec[MSModificationRequestForCSG] {
	return compositeValueCodec[MSModificationRequestForCSG, *MSModificationRequestForCSG]()
}

// MSRequestedServingNodeCodec binds MAP-MS-DataTypes.RequestedServingNode.
func MSRequestedServingNodeCodec() ValueCodec[BERValue[MSRequestedServingNode]] {
	return bitValueCodec("MAP-MS-DataTypes.RequestedServingNode", "RequestedServingNode", []primitiveRule[MSRequestedServingNode]{{invalid: func(value MSRequestedServingNode) bool { return !(value.BitLength >= 1 && value.BitLength <= 8) }, description: "SIZE (1..8)", clause: "51.5", length: func(value MSRequestedServingNode) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}})
}

// MSServingNodeCodec binds MAP-MS-DataTypes.ServingNode.
func MSServingNodeCodec() ValueCodec[BERValue[MSServingNode]] {
	return bitValueCodec("MAP-MS-DataTypes.ServingNode", "ServingNode", []primitiveRule[MSServingNode]{{invalid: func(value MSServingNode) bool { return !(value.BitLength >= 2 && value.BitLength <= 8) }, description: "SIZE (2..8)", clause: "51.5", length: func(value MSServingNode) int { return value.BitLength }}}, true, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}})
}

// MSAnyTimeModificationResCodec binds MAP-MS-DataTypes.AnyTimeModificationRes.
func MSAnyTimeModificationResCodec() ValueCodec[MSAnyTimeModificationRes] {
	return compositeValueCodec[MSAnyTimeModificationRes, *MSAnyTimeModificationRes]()
}

// MSModificationRequestForCFInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CF-Info.
func MSModificationRequestForCFInfoCodec() ValueCodec[MSModificationRequestForCFInfo] {
	return compositeValueCodec[MSModificationRequestForCFInfo, *MSModificationRequestForCFInfo]()
}

// MSModificationRequestForCBInfoCodec binds MAP-MS-DataTypes.ModificationRequestFor-CB-Info.
func MSModificationRequestForCBInfoCodec() ValueCodec[MSModificationRequestForCBInfo] {
	return compositeValueCodec[MSModificationRequestForCBInfo, *MSModificationRequestForCBInfo]()
}

// MSModificationRequestForODBDataCodec binds MAP-MS-DataTypes.ModificationRequestFor-ODB-data.
func MSModificationRequestForODBDataCodec() ValueCodec[MSModificationRequestForODBData] {
	return compositeValueCodec[MSModificationRequestForODBData, *MSModificationRequestForODBData]()
}

// MSModificationRequestForCSICodec binds MAP-MS-DataTypes.ModificationRequestFor-CSI.
func MSModificationRequestForCSICodec() ValueCodec[MSModificationRequestForCSI] {
	return compositeValueCodec[MSModificationRequestForCSI, *MSModificationRequestForCSI]()
}

// MSModificationRequestForIPSMGWDataCodec binds MAP-MS-DataTypes.ModificationRequestFor-IP-SM-GW-Data.
func MSModificationRequestForIPSMGWDataCodec() ValueCodec[MSModificationRequestForIPSMGWData] {
	return compositeValueCodec[MSModificationRequestForIPSMGWData, *MSModificationRequestForIPSMGWData]()
}

// MSModificationInstructionCodec binds MAP-MS-DataTypes.ModificationInstruction.
func MSModificationInstructionCodec() ValueCodec[BERValue[MSModificationInstruction]] {
	return integerValueCodec[MSModificationInstruction]("MAP-MS-DataTypes.ModificationInstruction", "ModificationInstruction", []primitiveRule[MSModificationInstruction]{{invalid: func(value MSModificationInstruction) bool { return (int64(value) != 0 && int64(value) != 1) }, description: "ENUMERATED {0, 1}", clause: "20", observed: func(value MSModificationInstruction) any { return int64(value) }}}, true)
}

// MSNoteSubscriberDataModifiedArgCodec binds MAP-MS-DataTypes.NoteSubscriberDataModifiedArg.
func MSNoteSubscriberDataModifiedArgCodec() ValueCodec[MSNoteSubscriberDataModifiedArg] {
	return compositeValueCodec[MSNoteSubscriberDataModifiedArg, *MSNoteSubscriberDataModifiedArg]()
}

// MSNoteSubscriberDataModifiedResCodec binds MAP-MS-DataTypes.NoteSubscriberDataModifiedRes.
func MSNoteSubscriberDataModifiedResCodec() ValueCodec[MSNoteSubscriberDataModifiedRes] {
	return compositeValueCodec[MSNoteSubscriberDataModifiedRes, *MSNoteSubscriberDataModifiedRes]()
}

// MSNoteMMEventArgCodec binds MAP-MS-DataTypes.NoteMM-EventArg.
func MSNoteMMEventArgCodec() ValueCodec[MSNoteMMEventArg] {
	return compositeValueCodec[MSNoteMMEventArg, *MSNoteMMEventArg]()
}

// MSNoteMMEventResCodec binds MAP-MS-DataTypes.NoteMM-EventRes.
func MSNoteMMEventResCodec() ValueCodec[MSNoteMMEventRes] {
	return compositeValueCodec[MSNoteMMEventRes, *MSNoteMMEventRes]()
}

// MSExtSSInfoForCSECodec binds MAP-MS-DataTypes.Ext-SS-InfoFor-CSE.
func MSExtSSInfoForCSECodec() ValueCodec[MSExtSSInfoForCSE] {
	return compositeValueCodec[MSExtSSInfoForCSE, *MSExtSSInfoForCSE]()
}

// MSExtForwardingInfoForCSECodec binds MAP-MS-DataTypes.Ext-ForwardingInfoFor-CSE.
func MSExtForwardingInfoForCSECodec() ValueCodec[MSExtForwardingInfoForCSE] {
	return compositeValueCodec[MSExtForwardingInfoForCSE, *MSExtForwardingInfoForCSE]()
}

// MSExtCallBarringInfoForCSECodec binds MAP-MS-DataTypes.Ext-CallBarringInfoFor-CSE.
func MSExtCallBarringInfoForCSECodec() ValueCodec[MSExtCallBarringInfoForCSE] {
	return compositeValueCodec[MSExtCallBarringInfoForCSE, *MSExtCallBarringInfoForCSE]()
}

// MSUpdateVcsgLocationArgCodec binds MAP-MS-DataTypes.UpdateVcsgLocationArg.
func MSUpdateVcsgLocationArgCodec() ValueCodec[MSUpdateVcsgLocationArg] {
	return compositeValueCodec[MSUpdateVcsgLocationArg, *MSUpdateVcsgLocationArg]()
}

// MSUpdateVcsgLocationResCodec binds MAP-MS-DataTypes.UpdateVcsgLocationRes.
func MSUpdateVcsgLocationResCodec() ValueCodec[MSUpdateVcsgLocationRes] {
	return compositeValueCodec[MSUpdateVcsgLocationRes, *MSUpdateVcsgLocationRes]()
}

// MSCancelVcsgLocationArgCodec binds MAP-MS-DataTypes.CancelVcsgLocationArg.
func MSCancelVcsgLocationArgCodec() ValueCodec[MSCancelVcsgLocationArg] {
	return compositeValueCodec[MSCancelVcsgLocationArg, *MSCancelVcsgLocationArg]()
}

// MSCancelVcsgLocationResCodec binds MAP-MS-DataTypes.CancelVcsgLocationRes.
func MSCancelVcsgLocationResCodec() ValueCodec[MSCancelVcsgLocationRes] {
	return compositeValueCodec[MSCancelVcsgLocationRes, *MSCancelVcsgLocationRes]()
}
