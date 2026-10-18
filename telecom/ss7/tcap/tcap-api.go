// Code generated from ASN.1. DO NOT EDIT.

package tcap

import (
	"bytes"
	"errors"
	"fmt"
	rt "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	ber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"math/big"
	"reflect"
)

// TransactionPrefix holds only leading TIDs validated before a failure.
type TransactionPrefix struct {
	Otid *OrigTransactionID
	Dtid *DestTransactionID
}

// DecodeError leaves the receiver untouched and retains the located cause.
type DecodeError struct {
	Path   string
	Prefix TransactionPrefix
	Cause  error
}

func (err *DecodeError) Error() string { return fmt.Sprintf("decoding %s: %v", err.Path, err.Cause) }
func (err *DecodeError) Unwrap() error { return err.Cause }

func locateTCAPDecodeError(cause error, data []byte) error {
	var previous *DecodeError
	if errors.As(cause, &previous) {
		return cause
	}
	result := &DecodeError{Path: "TCMessage", Cause: cause}
	var path interface{ ASN1BERPath() string }
	if errors.As(cause, &path) {
		result.Path = path.ASN1BERPath()
	}
	var validation *ber.ValidationError
	if errors.As(cause, &validation) {
		result.Path = validation.Path
	}
	var location *ber.ElementError
	if !errors.As(cause, &location) || location.Offset() <= 0 {
		return result
	}
	boundary := location.Offset()
	if boundary > len(data) {
		return result
	}
	identifier, tagBytes, err := ber.DecodeTag(data)
	if err != nil || identifier.Class != 1 || !identifier.Constructed {
		return result
	}
	_, _, lengthBytes, err := ber.DecodeLength(data[tagBytes:])
	if err != nil {
		return result
	}
	offset := tagBytes + lengthBytes
	// This bounded prefix check visits at most the two leading TIDs, never a
	// component or dialogue. Q.773 (06/1997) §§3.1,4.2.1.3; Q.774 §3.3.4/Table 7.
	for index := 0; index < 2 && offset < boundary; index++ {
		field, n, err := ber.DecodeTag(data[offset:boundary])
		if err != nil || field.Class != 1 || field.Constructed {
			break
		}
		length, indefinite, m, err := ber.DecodeLength(data[offset+n : boundary])
		if err != nil || indefinite || length < 1 || length > 4 {
			break
		}
		start := offset + n + m
		if start > boundary || length > boundary-start {
			break
		}
		validOtid := field.Number == 8 && (identifier.Number == 2 && index == 0 || identifier.Number == 5 && index == 0)
		validDtid := field.Number == 9 && (identifier.Number == 4 && index == 0 || identifier.Number == 7 && index == 0 || identifier.Number == 5 && index == 1)
		if validOtid {
			id := OrigTransactionID(bytes.Clone(data[start : start+length]))
			result.Prefix.Otid = &id
		} else if validDtid {
			id := DestTransactionID(bytes.Clone(data[start : start+length]))
			result.Prefix.Dtid = &id
		} else {
			break
		}
		offset = start + length
	}
	if len(location.ChildIndexes()) == 1 {
		field, _, fieldErr := ber.DecodeTag(data[boundary:])
		if fieldErr == nil && field.Class == 1 {
			branch := ""
			switch identifier.Number {
			case 1:
				branch = "unidirectional"
			case 2:
				branch = "begin"
			case 4:
				branch = "end"
			case 5:
				branch = "continue"
			case 7:
				branch = "abort"
			}
			component := ""
			switch field.Number {
			case 8:
				component = "otid"
			case 9:
				component = "dtid"
			case 11:
				component = "dialoguePortion"
			case 12:
				component = "components"
			}
			if branch != "" && component != "" {
				result.Path = branch + "." + component
			}
		}
	}
	return result
}

func checkTCAPOpaqueReplay(data []byte, opts ...ber.EncodeOption) error {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return err
	}
	if err := ber.CheckBEROpaqueReplay(opts...); err == nil {
		return nil
	}
	return validateCanonicalPayload(data)
}

// Structural checks precede replay so inactive CHOICE fields cannot hide behind
// a cached selected value. Traversal follows generated source fields directly.
func validateTCAPStructureValue(value any) error {
	if typed, ok := value.(interface{ validateTCAPStructure() error }); ok {
		return typed.validateTCAPStructure()
	}
	return nil
}
func hasTCAPPresenceEditValue(value any) bool {
	if typed, ok := value.(interface{ hasTCAPPresenceEdit() bool }); ok {
		return typed.hasTCAPPresenceEdit()
	}
	return false
}

// Equal methods compare source fields without walking reflection metadata.
// DEFAULT pointers remain observable independently of their effective value.
func equalTCAPValue(left, right any) bool {
	if typed, ok := left.(interface{ equalTCAPValue(any) bool }); ok {
		return typed.equalTCAPValue(right)
	}
	switch a := left.(type) {
	case big.Int:
		b, ok := right.(big.Int)
		return ok && a.Cmp(&b) == 0
	case []byte:
		b, ok := right.([]byte)
		return ok && bytes.Equal(a, b)
	case OrigTransactionID:
		b, ok := right.(OrigTransactionID)
		return ok && bytes.Equal(a, b)
	case DestTransactionID:
		b, ok := right.(DestTransactionID)
		return ok && bytes.Equal(a, b)
	case rt.BitString:
		b, ok := right.(rt.BitString)
		return ok && a.BitLength == b.BitLength && bytes.Equal(a.Bytes, b.Bytes)
	case rt.RawValue:
		b, ok := right.(rt.RawValue)
		return ok && a.Class == b.Class && a.Tag == b.Tag && a.Constructed == b.Constructed && bytes.Equal(a.Bytes, b.Bytes)
	case rt.External:
		b, ok := right.(rt.External)
		if !ok {
			return false
		}
		if !a.DirectReference.Equal(b.DirectReference) || a.Encoding != b.Encoding || (a.IndirectReference == nil) != (b.IndirectReference == nil) || (a.DataValueDescriptor == nil) != (b.DataValueDescriptor == nil) {
			return false
		}
		if a.IndirectReference != nil && a.IndirectReference.Cmp(b.IndirectReference) != 0 {
			return false
		}
		if a.DataValueDescriptor != nil && *a.DataValueDescriptor != *b.DataValueDescriptor {
			return false
		}
		return equalTCAPValue(a.SingleASN1Type, b.SingleASN1Type) && bytes.Equal(a.OctetAligned, b.OctetAligned) && equalTCAPValue(a.Arbitrary, b.Arbitrary)
	case int:
		b, ok := right.(int)
		return ok && a == b
	case int64:
		b, ok := right.(int64)
		return ok && a == b
	case uint64:
		b, ok := right.(uint64)
		return ok && a == b
	case bool:
		b, ok := right.(bool)
		return ok && a == b
	case string:
		b, ok := right.(string)
		return ok && a == b
	case struct{}:
		_, ok := right.(struct{})
		return ok
	case rt.ObjectIdentifier:
		b, ok := right.(rt.ObjectIdentifier)
		return ok && a.Equal(b)
	default:
		return false
	}
}
func tcapReplayNode(value any, node *ber.ReplayNode) *ber.ReplayNode {
	if hasTCAPPresenceEditValue(value) {
		return nil
	}
	return node
}
func (value *DialoguePortion) validateTCAPStructure() error {
	if value == nil {
		return nil
	}
	if value.dialogue != nil {
		if err := value.dialogue.validateTCAPStructure(); err != nil {
			return err
		}
	}
	if value.unidialogue != nil {
		if err := value.unidialogue.validateTCAPStructure(); err != nil {
			return err
		}
	}
	return nil
}
func normalizeTCAPBits(data []byte, unused int) []byte {
	if unused <= 0 || unused > 7 || len(data) == 0 {
		return data
	}
	copied := bytes.Clone(data)
	copied[len(copied)-1] &= byte(0xff << uint(unused))
	return copied
}
func encodeTCAPBitString(data []byte, unused int) ([]byte, error) {
	return ber.EncodeBitString(normalizeTCAPBits(data, unused), unused)
}
func encodeTCAPNamedBitStringDER(data []byte, length int) ([]byte, error) {
	if err := ber.ValidateBitStringLength(data, length); err != nil {
		return nil, err
	}
	return ber.EncodeDERNamedBitString(normalizeTCAPBits(data, ber.UnusedBitCount(length)), length)
}
func encodeTCAPExternal(value rt.External, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if ber.BERReplayEnabled(opts) {
		if original := value.UnchangedBER(); original != nil {
			return original, nil
		}
	}
	if value.Encoding == rt.ExternalArbitrary {
		value.Arbitrary.Bytes = normalizeTCAPBits(value.Arbitrary.Bytes, ber.UnusedBitCount(value.Arbitrary.BitLength))
	}
	// Internal comparison is BER, even though received-form shortcuts are off.
	// Explicit WithoutBERReplay still requires canonical opaque contents.
	// X.690 (02/2021) §§8.1.3, 8.18.9; Q.773 (06/1997) §4.1.1.
	if ber.CheckBEROpaqueReplay(opts...) != nil {
		return encodeTCAPExternalDER(value)
	}
	return ber.EncodeExternal(value, opts...)
}
func encodeTCAPExternalDER(value rt.External) ([]byte, error) {
	if value.Encoding == rt.ExternalArbitrary {
		value.Arbitrary.Bytes = normalizeTCAPBits(value.Arbitrary.Bytes, ber.UnusedBitCount(value.Arbitrary.BitLength))
	}
	return ber.EncodeExternalDER(value)
}

// Q.773 (06/1997) Annex A and 4.2.1.3: transaction identifiers retain octets.
func NewOrigTransactionID(value []byte) (OrigTransactionID, error) {
	if len(value) < 1 || len(value) > 4 {
		return nil, fmt.Errorf("transaction ID length must be 1..4")
	}
	return OrigTransactionID(bytes.Clone(value)), nil
}
func NewDestTransactionID(value []byte) (DestTransactionID, error) {
	if len(value) < 1 || len(value) > 4 {
		return nil, fmt.Errorf("transaction ID length must be 1..4")
	}
	return DestTransactionID(bytes.Clone(value)), nil
}
func NewTCInvokeIdSetPresentInt64(value int64) TCInvokeIdSet {
	return NewTCInvokeIdSetPresent(big.NewInt(value))
}
func NewInvokeIdPresentInt64(value int64) InvokeId { return NewInvokeIdPresent(big.NewInt(value)) }
func NewInvokeLinkedIdPresentInt64(value int64) InvokeLinkedId {
	return NewInvokeLinkedIdPresent(big.NewInt(value))
}

// ComponentValidator supplies the wrapper's invocation/context constraints.
// X.880 (07/1994) 9.4.1; contextual CONSTRAINED BY conditions need that state.
type ComponentValidator interface {
	ValidateComponent(index int, value Component) error
}

func (value *TCMessage) ValidateComponents(context ComponentValidator) error {
	if nilComponentValidator(context) {
		return fmt.Errorf("nil component validator")
	}
	if err := value.Validate(); err != nil {
		return err
	}
	var portion *ComponentPortion
	switch value.Choice {
	case TCMessageChoiceBegin:
		portion = value.Begin.Components
	case TCMessageChoiceContinue:
		portion = value.Continue.Components
	case TCMessageChoiceEnd:
		portion = value.End.Components
	case TCMessageChoiceUnidirectional:
		portion = &value.Unidirectional.Components
	}
	if portion != nil {
		for i, component := range portion.Values {
			if err := context.ValidateComponent(i, component); err != nil {
				return err
			}
		}
	}
	return nil
}
func nilComponentValidator(value ComponentValidator) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// newProtocolVersion builds source named-bit positions, with bounded storage.
// X.680 (02/2021) 22.7; Q.773 (06/1997) 3.2.1-3.2.2.
func newProtocolVersion(set ...int) (rt.BitString, error) {
	length := 0
	for _, bit := range set {
		if bit < 0 || bit >= 128*1024*1024 {
			return rt.BitString{}, fmt.Errorf("protocol-version bit position outside supported storage")
		}
		if bit+1 > length {
			length = bit + 1
		}
	}
	result := rt.BitString{Bytes: make([]byte, (length+7)/8), BitLength: length}
	for _, bit := range set {
		result.Bytes[bit/8] |= byte(0x80 >> uint(bit%8))
	}
	return result, nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *ReturnResult) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil ReturnResult")
	}
	if value.InvokeId.Choice != InvokeIdChoicePresent {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "Remote-Operations-Generic-ROS-PDUs.ReturnResult"), "invokeId", "Q.773 §4.2.2.2: component-id-present", "NULL")
	}
	return nil
}
func (value *ReturnResult) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil ReturnResult")
	}
	if value.InvokeId.Choice != InvokeIdChoicePresent {
		return ber.CheckDecodedValue(opts, "invokeId", "Q.773 §4.2.2.2: component-id-present", "NULL")
	}
	return nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *ReturnError) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil ReturnError")
	}
	if value.InvokeId.Choice != InvokeIdChoicePresent {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "Remote-Operations-Generic-ROS-PDUs.ReturnError"), "invokeId", "Q.773 §4.2.2.2: component-id-present", "NULL")
	}
	return nil
}
func (value *ReturnError) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil ReturnError")
	}
	if value.InvokeId.Choice != InvokeIdChoicePresent {
		return ber.CheckDecodedValue(opts, "invokeId", "Q.773 §4.2.2.2: component-id-present", "NULL")
	}
	return nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *InvokeLinkedId) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil InvokeLinkedId")
	}
	if value.Choice != InvokeLinkedIdChoicePresent {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "Remote-Operations-Generic-ROS-PDUs.Invoke.linkedId"), "", "Q.773 §4.2.2.2: component-id-linked-present", "NULL")
	}
	return nil
}
func (value *InvokeLinkedId) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil InvokeLinkedId")
	}
	if value.Choice != InvokeLinkedIdChoicePresent {
		return ber.CheckDecodedValue(opts, "", "Q.773 §4.2.2.2: component-id-linked-present", "NULL")
	}
	return nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *Unidirectional) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Unidirectional")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() != Unstructured {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.Unidirectional"), "dialoguePortion", "Q.773 §4.2.3: unidirectional-unidialogue-syntax", "dialogue does not identify unidialogue-as/AUDT (Q.771 2.3.1.2.1)")
	}
	return nil
}
func (value *Unidirectional) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Unidirectional")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() != Unstructured {
		return ber.CheckDecodedValue(opts, "dialoguePortion", "Q.773 §4.2.3: unidirectional-unidialogue-syntax", "dialogue does not identify unidialogue-as/AUDT (Q.771 2.3.1.2.1)")
	}
	return nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *Begin) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Begin")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() == Unstructured {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.Begin"), "dialoguePortion", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}
func (value *Begin) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Begin")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() == Unstructured {
		return ber.CheckDecodedValue(opts, "dialoguePortion", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *Continue) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Continue")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() == Unstructured {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.Continue"), "dialoguePortion", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}
func (value *Continue) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Continue")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() == Unstructured {
		return ber.CheckDecodedValue(opts, "dialoguePortion", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *End) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil End")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() == Unstructured {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.End"), "dialoguePortion", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}
func (value *End) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil End")
	}
	if value.DialoguePortion != nil && value.DialoguePortion.ContentKind() == Unstructured {
		return ber.CheckDecodedValue(opts, "dialoguePortion", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}

// Q.773 (06/1997) §§4.2.2.2, 4.2.3; Q.771 (06/1997) §2.3.1.2.1 supplement the Annex A type.
func (value *Abort) checkTCAPEncodedRules(opts []ber.EncodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Abort")
	}
	if value.Reason != nil && value.Reason.Choice == AbortReasonChoiceUAbortCause && value.Reason.UAbortCause != nil && value.Reason.UAbortCause.ContentKind() == Unstructured {
		return ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.Abort"), "reason.uAbortCause", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}
func (value *Abort) checkTCAPDecodedRules(opts []ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil Abort")
	}
	if value.Reason != nil && value.Reason.Choice == AbortReasonChoiceUAbortCause && value.Reason.UAbortCause != nil && value.Reason.UAbortCause.ContentKind() == Unstructured {
		return ber.CheckDecodedValue(opts, "reason.uAbortCause", "Q.773 §4.2.3: structured-no-unidialogue-syntax", "unidialogue-as/AUDT is restricted to Unidirectional (Q.771 2.3.1.2.1)")
	}
	return nil
}
func NewAARQApduProtocolVersion(set ...int) (rt.BitString, error) { return newProtocolVersion(set...) }
func AARQApduProtocolVersionDefault() rt.BitString {
	return rt.BitString{Bytes: []byte{0x80}, BitLength: 1}
}
func (value *AARQApdu) EffectiveProtocolVersion() rt.BitString {
	if value == nil || value.ProtocolVersion == nil {
		return AARQApduProtocolVersionDefault()
	}
	return rt.BitString{Bytes: bytes.Clone(value.ProtocolVersion.Bytes), BitLength: value.ProtocolVersion.BitLength}
}
func NewAAREApduProtocolVersion(set ...int) (rt.BitString, error) { return newProtocolVersion(set...) }
func AAREApduProtocolVersionDefault() rt.BitString {
	return rt.BitString{Bytes: []byte{0x80}, BitLength: 1}
}
func (value *AAREApdu) EffectiveProtocolVersion() rt.BitString {
	if value == nil || value.ProtocolVersion == nil {
		return AAREApduProtocolVersionDefault()
	}
	return rt.BitString{Bytes: bytes.Clone(value.ProtocolVersion.Bytes), BitLength: value.ProtocolVersion.BitLength}
}
func NewAUDTApduProtocolVersion(set ...int) (rt.BitString, error) { return newProtocolVersion(set...) }
func AUDTApduProtocolVersionDefault() rt.BitString {
	return rt.BitString{Bytes: []byte{0x80}, BitLength: 1}
}
func (value *AUDTApdu) EffectiveProtocolVersion() rt.BitString {
	if value == nil || value.ProtocolVersion == nil {
		return AUDTApduProtocolVersionDefault()
	}
	return rt.BitString{Bytes: bytes.Clone(value.ProtocolVersion.Bytes), BitLength: value.ProtocolVersion.BitLength}
}
func (value *ComponentPortion) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := value.validateTCAPStructure(); err != nil {
		return nil, err
	}
	return tcapMarshalBERComponentPortion(value, opts...)
}
func (value *ComponentPortion) MarshalDER() ([]byte, error) {
	if err := value.validateTCAPStructure(); err != nil {
		return nil, err
	}
	return tcapMarshalDERComponentPortion(value)
}
func (value *ComponentPortion) UnmarshalBER(data []byte, opts ...ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil ComponentPortion destination")
	}
	decoded, err := tcapUnmarshalBERComponentPortion(data, opts...)
	if err != nil {
		return err
	}
	*value = *decoded
	return nil
}
func (value *UserInformation) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := value.validateTCAPStructure(); err != nil {
		return nil, err
	}
	return tcapMarshalBERUserInformation(value, opts...)
}
func (value *UserInformation) MarshalDER() ([]byte, error) {
	if err := value.validateTCAPStructure(); err != nil {
		return nil, err
	}
	return tcapMarshalDERUserInformation(value)
}
func (value *UserInformation) UnmarshalBER(data []byte, opts ...ber.DecodeOption) error {
	if value == nil {
		return fmt.Errorf("nil UserInformation destination")
	}
	decoded, err := tcapUnmarshalBERUserInformation(data, opts...)
	if err != nil {
		return err
	}
	*value = *decoded
	return nil
}
func (value *TCMessage) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *Begin) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *Continue) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *End) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *Abort) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *Unidirectional) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *ComponentPortion) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *Component) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *ROS) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *Invoke) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *ReturnResult) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *ReturnResultResult) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *ReturnError) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *Reject) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *RejectProblemChoice) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *InvokeId) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *TCInvokeIdSet) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *InvokeLinkedId) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *AbortReason) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *DialoguePortion) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *UserInformation) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *DialoguePDU) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *UniDialoguePDU) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *AARQApdu) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *AAREApdu) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *ABRTApdu) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *AUDTApdu) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *RLRQApdu) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
func (value *RLREApdu) Validate(opts ...ber.EncodeOption) error {
	_, err := value.MarshalBER(opts...)
	return err
}
