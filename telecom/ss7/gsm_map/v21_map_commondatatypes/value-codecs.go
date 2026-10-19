// Code generated from ASN.1. DO NOT EDIT.

package v21_map_commondatatypes

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
