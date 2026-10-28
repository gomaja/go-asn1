// Code generated from ASN.1 module "Remote-Operations-Generic-ROS-PDUs". DO NOT EDIT.

package ros

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

// ROS choice constants.
const (
	ROSChoiceInvoke       = 1
	ROSChoiceReturnResult = 2
	ROSChoiceReturnError  = 3
	ROSChoiceReject       = 4
)

// ROS represents the ASN.1 CHOICE type ROS.
type ROS struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Invoke         *Invoke         `json:"Invoke,omitempty"`
	ReturnResult   *ReturnResult   `json:"ReturnResult,omitempty"`
	ReturnError    *ReturnError    `json:"ReturnError,omitempty"`
	Reject         *Reject         `json:"Reject,omitempty"`
}

// NewROSInvoke creates a ROS with the invoke alternative.
func NewROSInvoke(v Invoke) ROS {
	return ROS{
		Choice: ROSChoiceInvoke,
		Invoke: &v,
	}
}

// NewROSReturnResult creates a ROS with the returnResult alternative.
func NewROSReturnResult(v ReturnResult) ROS {
	return ROS{
		Choice:       ROSChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewROSReturnError creates a ROS with the returnError alternative.
func NewROSReturnError(v ReturnError) ROS {
	return ROS{
		Choice:      ROSChoiceReturnError,
		ReturnError: &v,
	}
}

// NewROSReject creates a ROS with the reject alternative.
func NewROSReject(v Reject) ROS {
	return ROS{
		Choice: ROSChoiceReject,
		Reject: &v,
	}
}

// Invoke represents the ASN.1 type Invoke (SEQUENCE).
type Invoke struct {
	InvokeId InvokeId        `asn1:""`
	LinkedId *InvokeLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode   Code            `asn1:""`
	// Argument carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	Argument       *runtime.RawValue `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// ReturnResult represents the ASN.1 type ReturnResult (SEQUENCE).
type ReturnResult struct {
	InvokeId       InvokeId            `asn1:""`
	Result         *ReturnResultResult `asn1:",optional" json:"Result,omitempty"`
	berReplayNode_ *ber.ReplayNode     `asn1:"-" json:"-"`
}

// ReturnError represents the ASN.1 type ReturnError (SEQUENCE).
type ReturnError struct {
	InvokeId InvokeId `asn1:""`
	Errcode  Code     `asn1:""`
	// Parameter carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	Parameter      *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// Reject represents the ASN.1 type Reject (SEQUENCE).
type Reject struct {
	InvokeId       InvokeId                `asn1:""`
	Problem        OperationsRejectProblem `asn1:""`
	berReplayNode_ *ber.ReplayNode         `asn1:"-" json:"-"`
}

// GeneralProblem represents the arbitrary-width ASN.1 INTEGER type GeneralProblem with named numbers.
type GeneralProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	GeneralProblemUnrecognizedPDUDecimal    = "0"
	GeneralProblemUnrecognizedPDU           = 0
	GeneralProblemMistypedPDUDecimal        = "1"
	GeneralProblemMistypedPDU               = 1
	GeneralProblemBadlyStructuredPDUDecimal = "2"
	GeneralProblemBadlyStructuredPDU        = 2
)

// NewGeneralProblem returns an immutable GeneralProblem containing value.
func NewGeneralProblem(value *big.Int) GeneralProblem {
	return GeneralProblem{value: runtime.CloneBigInt(value)}
}

// NewGeneralProblemInt64 returns a GeneralProblem containing value.
func NewGeneralProblemInt64(value int64) GeneralProblem {
	return NewGeneralProblem(big.NewInt(value))
}

// GeneralProblemUnrecognizedPDUValue returns the named value unrecognizedPDU.
func GeneralProblemUnrecognizedPDUValue() GeneralProblem {
	return NewGeneralProblem(runtime.MustParseBigIntDecimal(GeneralProblemUnrecognizedPDUDecimal))
}

// GeneralProblemMistypedPDUValue returns the named value mistypedPDU.
func GeneralProblemMistypedPDUValue() GeneralProblem {
	return NewGeneralProblem(runtime.MustParseBigIntDecimal(GeneralProblemMistypedPDUDecimal))
}

// GeneralProblemBadlyStructuredPDUValue returns the named value badlyStructuredPDU.
func GeneralProblemBadlyStructuredPDUValue() GeneralProblem {
	return NewGeneralProblem(runtime.MustParseBigIntDecimal(GeneralProblemBadlyStructuredPDUDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v GeneralProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v GeneralProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v GeneralProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case GeneralProblemUnrecognizedPDUDecimal:
		return "unrecognizedPDU", true
	case GeneralProblemMistypedPDUDecimal:
		return "mistypedPDU", true
	case GeneralProblemBadlyStructuredPDUDecimal:
		return "badlyStructuredPDU", true
	default:
		return "", false
	}
}

// String returns the ASN.1 named label, or the decimal value when unnamed.
func (v GeneralProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v GeneralProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *GeneralProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GeneralProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewGeneralProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v GeneralProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *GeneralProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GeneralProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewGeneralProblem(value)
	return nil
}

// InvokeProblem represents the arbitrary-width ASN.1 INTEGER type InvokeProblem with named numbers.
type InvokeProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	InvokeProblemDuplicateInvocationDecimal       = "0"
	InvokeProblemDuplicateInvocation              = 0
	InvokeProblemUnrecognizedOperationDecimal     = "1"
	InvokeProblemUnrecognizedOperation            = 1
	InvokeProblemMistypedArgumentDecimal          = "2"
	InvokeProblemMistypedArgument                 = 2
	InvokeProblemResourceLimitationDecimal        = "3"
	InvokeProblemResourceLimitation               = 3
	InvokeProblemReleaseInProgressDecimal         = "4"
	InvokeProblemReleaseInProgress                = 4
	InvokeProblemUnrecognizedLinkedIdDecimal      = "5"
	InvokeProblemUnrecognizedLinkedId             = 5
	InvokeProblemLinkedResponseUnexpectedDecimal  = "6"
	InvokeProblemLinkedResponseUnexpected         = 6
	InvokeProblemUnexpectedLinkedOperationDecimal = "7"
	InvokeProblemUnexpectedLinkedOperation        = 7
)

// NewInvokeProblem returns an immutable InvokeProblem containing value.
func NewInvokeProblem(value *big.Int) InvokeProblem {
	return InvokeProblem{value: runtime.CloneBigInt(value)}
}

// NewInvokeProblemInt64 returns a InvokeProblem containing value.
func NewInvokeProblemInt64(value int64) InvokeProblem {
	return NewInvokeProblem(big.NewInt(value))
}

// InvokeProblemDuplicateInvocationValue returns the named value duplicateInvocation.
func InvokeProblemDuplicateInvocationValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemDuplicateInvocationDecimal))
}

// InvokeProblemUnrecognizedOperationValue returns the named value unrecognizedOperation.
func InvokeProblemUnrecognizedOperationValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemUnrecognizedOperationDecimal))
}

// InvokeProblemMistypedArgumentValue returns the named value mistypedArgument.
func InvokeProblemMistypedArgumentValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemMistypedArgumentDecimal))
}

// InvokeProblemResourceLimitationValue returns the named value resourceLimitation.
func InvokeProblemResourceLimitationValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemResourceLimitationDecimal))
}

// InvokeProblemReleaseInProgressValue returns the named value releaseInProgress.
func InvokeProblemReleaseInProgressValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemReleaseInProgressDecimal))
}

// InvokeProblemUnrecognizedLinkedIdValue returns the named value unrecognizedLinkedId.
func InvokeProblemUnrecognizedLinkedIdValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemUnrecognizedLinkedIdDecimal))
}

// InvokeProblemLinkedResponseUnexpectedValue returns the named value linkedResponseUnexpected.
func InvokeProblemLinkedResponseUnexpectedValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemLinkedResponseUnexpectedDecimal))
}

// InvokeProblemUnexpectedLinkedOperationValue returns the named value unexpectedLinkedOperation.
func InvokeProblemUnexpectedLinkedOperationValue() InvokeProblem {
	return NewInvokeProblem(runtime.MustParseBigIntDecimal(InvokeProblemUnexpectedLinkedOperationDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v InvokeProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v InvokeProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v InvokeProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case InvokeProblemDuplicateInvocationDecimal:
		return "duplicateInvocation", true
	case InvokeProblemUnrecognizedOperationDecimal:
		return "unrecognizedOperation", true
	case InvokeProblemMistypedArgumentDecimal:
		return "mistypedArgument", true
	case InvokeProblemResourceLimitationDecimal:
		return "resourceLimitation", true
	case InvokeProblemReleaseInProgressDecimal:
		return "releaseInProgress", true
	case InvokeProblemUnrecognizedLinkedIdDecimal:
		return "unrecognizedLinkedId", true
	case InvokeProblemLinkedResponseUnexpectedDecimal:
		return "linkedResponseUnexpected", true
	case InvokeProblemUnexpectedLinkedOperationDecimal:
		return "unexpectedLinkedOperation", true
	default:
		return "", false
	}
}

// String returns the ASN.1 named label, or the decimal value when unnamed.
func (v InvokeProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v InvokeProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *InvokeProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal InvokeProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewInvokeProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v InvokeProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *InvokeProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal InvokeProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewInvokeProblem(value)
	return nil
}

// ReturnResultProblem represents the arbitrary-width ASN.1 INTEGER type ReturnResultProblem with named numbers.
type ReturnResultProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ReturnResultProblemUnrecognizedInvocationDecimal   = "0"
	ReturnResultProblemUnrecognizedInvocation          = 0
	ReturnResultProblemResultResponseUnexpectedDecimal = "1"
	ReturnResultProblemResultResponseUnexpected        = 1
	ReturnResultProblemMistypedResultDecimal           = "2"
	ReturnResultProblemMistypedResult                  = 2
)

// NewReturnResultProblem returns an immutable ReturnResultProblem containing value.
func NewReturnResultProblem(value *big.Int) ReturnResultProblem {
	return ReturnResultProblem{value: runtime.CloneBigInt(value)}
}

// NewReturnResultProblemInt64 returns a ReturnResultProblem containing value.
func NewReturnResultProblemInt64(value int64) ReturnResultProblem {
	return NewReturnResultProblem(big.NewInt(value))
}

// ReturnResultProblemUnrecognizedInvocationValue returns the named value unrecognizedInvocation.
func ReturnResultProblemUnrecognizedInvocationValue() ReturnResultProblem {
	return NewReturnResultProblem(runtime.MustParseBigIntDecimal(ReturnResultProblemUnrecognizedInvocationDecimal))
}

// ReturnResultProblemResultResponseUnexpectedValue returns the named value resultResponseUnexpected.
func ReturnResultProblemResultResponseUnexpectedValue() ReturnResultProblem {
	return NewReturnResultProblem(runtime.MustParseBigIntDecimal(ReturnResultProblemResultResponseUnexpectedDecimal))
}

// ReturnResultProblemMistypedResultValue returns the named value mistypedResult.
func ReturnResultProblemMistypedResultValue() ReturnResultProblem {
	return NewReturnResultProblem(runtime.MustParseBigIntDecimal(ReturnResultProblemMistypedResultDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ReturnResultProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ReturnResultProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ReturnResultProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case ReturnResultProblemUnrecognizedInvocationDecimal:
		return "unrecognizedInvocation", true
	case ReturnResultProblemResultResponseUnexpectedDecimal:
		return "resultResponseUnexpected", true
	case ReturnResultProblemMistypedResultDecimal:
		return "mistypedResult", true
	default:
		return "", false
	}
}

// String returns the ASN.1 named label, or the decimal value when unnamed.
func (v ReturnResultProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ReturnResultProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ReturnResultProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReturnResultProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewReturnResultProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ReturnResultProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ReturnResultProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReturnResultProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewReturnResultProblem(value)
	return nil
}

// ReturnErrorProblem represents the arbitrary-width ASN.1 INTEGER type ReturnErrorProblem with named numbers.
type ReturnErrorProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ReturnErrorProblemUnrecognizedInvocationDecimal  = "0"
	ReturnErrorProblemUnrecognizedInvocation         = 0
	ReturnErrorProblemErrorResponseUnexpectedDecimal = "1"
	ReturnErrorProblemErrorResponseUnexpected        = 1
	ReturnErrorProblemUnrecognizedErrorDecimal       = "2"
	ReturnErrorProblemUnrecognizedError              = 2
	ReturnErrorProblemUnexpectedErrorDecimal         = "3"
	ReturnErrorProblemUnexpectedError                = 3
	ReturnErrorProblemMistypedParameterDecimal       = "4"
	ReturnErrorProblemMistypedParameter              = 4
)

// NewReturnErrorProblem returns an immutable ReturnErrorProblem containing value.
func NewReturnErrorProblem(value *big.Int) ReturnErrorProblem {
	return ReturnErrorProblem{value: runtime.CloneBigInt(value)}
}

// NewReturnErrorProblemInt64 returns a ReturnErrorProblem containing value.
func NewReturnErrorProblemInt64(value int64) ReturnErrorProblem {
	return NewReturnErrorProblem(big.NewInt(value))
}

// ReturnErrorProblemUnrecognizedInvocationValue returns the named value unrecognizedInvocation.
func ReturnErrorProblemUnrecognizedInvocationValue() ReturnErrorProblem {
	return NewReturnErrorProblem(runtime.MustParseBigIntDecimal(ReturnErrorProblemUnrecognizedInvocationDecimal))
}

// ReturnErrorProblemErrorResponseUnexpectedValue returns the named value errorResponseUnexpected.
func ReturnErrorProblemErrorResponseUnexpectedValue() ReturnErrorProblem {
	return NewReturnErrorProblem(runtime.MustParseBigIntDecimal(ReturnErrorProblemErrorResponseUnexpectedDecimal))
}

// ReturnErrorProblemUnrecognizedErrorValue returns the named value unrecognizedError.
func ReturnErrorProblemUnrecognizedErrorValue() ReturnErrorProblem {
	return NewReturnErrorProblem(runtime.MustParseBigIntDecimal(ReturnErrorProblemUnrecognizedErrorDecimal))
}

// ReturnErrorProblemUnexpectedErrorValue returns the named value unexpectedError.
func ReturnErrorProblemUnexpectedErrorValue() ReturnErrorProblem {
	return NewReturnErrorProblem(runtime.MustParseBigIntDecimal(ReturnErrorProblemUnexpectedErrorDecimal))
}

// ReturnErrorProblemMistypedParameterValue returns the named value mistypedParameter.
func ReturnErrorProblemMistypedParameterValue() ReturnErrorProblem {
	return NewReturnErrorProblem(runtime.MustParseBigIntDecimal(ReturnErrorProblemMistypedParameterDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ReturnErrorProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ReturnErrorProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ReturnErrorProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case ReturnErrorProblemUnrecognizedInvocationDecimal:
		return "unrecognizedInvocation", true
	case ReturnErrorProblemErrorResponseUnexpectedDecimal:
		return "errorResponseUnexpected", true
	case ReturnErrorProblemUnrecognizedErrorDecimal:
		return "unrecognizedError", true
	case ReturnErrorProblemUnexpectedErrorDecimal:
		return "unexpectedError", true
	case ReturnErrorProblemMistypedParameterDecimal:
		return "mistypedParameter", true
	default:
		return "", false
	}
}

// String returns the ASN.1 named label, or the decimal value when unnamed.
func (v ReturnErrorProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ReturnErrorProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ReturnErrorProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReturnErrorProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewReturnErrorProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ReturnErrorProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ReturnErrorProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReturnErrorProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewReturnErrorProblem(value)
	return nil
}

// RejectProblem represents the arbitrary-width ASN.1 INTEGER type RejectProblem with named numbers.
type RejectProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	RejectProblemGeneralUnrecognizedPDUDecimal               = "0"
	RejectProblemGeneralUnrecognizedPDU                      = 0
	RejectProblemGeneralMistypedPDUDecimal                   = "1"
	RejectProblemGeneralMistypedPDU                          = 1
	RejectProblemGeneralBadlyStructuredPDUDecimal            = "2"
	RejectProblemGeneralBadlyStructuredPDU                   = 2
	RejectProblemInvokeDuplicateInvocationDecimal            = "10"
	RejectProblemInvokeDuplicateInvocation                   = 10
	RejectProblemInvokeUnrecognizedOperationDecimal          = "11"
	RejectProblemInvokeUnrecognizedOperation                 = 11
	RejectProblemInvokeMistypedArgumentDecimal               = "12"
	RejectProblemInvokeMistypedArgument                      = 12
	RejectProblemInvokeResourceLimitationDecimal             = "13"
	RejectProblemInvokeResourceLimitation                    = 13
	RejectProblemInvokeReleaseInProgressDecimal              = "14"
	RejectProblemInvokeReleaseInProgress                     = 14
	RejectProblemInvokeUnrecognizedLinkedIdDecimal           = "15"
	RejectProblemInvokeUnrecognizedLinkedId                  = 15
	RejectProblemInvokeLinkedResponseUnexpectedDecimal       = "16"
	RejectProblemInvokeLinkedResponseUnexpected              = 16
	RejectProblemInvokeUnexpectedLinkedOperationDecimal      = "17"
	RejectProblemInvokeUnexpectedLinkedOperation             = 17
	RejectProblemReturnResultUnrecognizedInvocationDecimal   = "20"
	RejectProblemReturnResultUnrecognizedInvocation          = 20
	RejectProblemReturnResultResultResponseUnexpectedDecimal = "21"
	RejectProblemReturnResultResultResponseUnexpected        = 21
	RejectProblemReturnResultMistypedResultDecimal           = "22"
	RejectProblemReturnResultMistypedResult                  = 22
	RejectProblemReturnErrorUnrecognizedInvocationDecimal    = "30"
	RejectProblemReturnErrorUnrecognizedInvocation           = 30
	RejectProblemReturnErrorErrorResponseUnexpectedDecimal   = "31"
	RejectProblemReturnErrorErrorResponseUnexpected          = 31
	RejectProblemReturnErrorUnrecognizedErrorDecimal         = "32"
	RejectProblemReturnErrorUnrecognizedError                = 32
	RejectProblemReturnErrorUnexpectedErrorDecimal           = "33"
	RejectProblemReturnErrorUnexpectedError                  = 33
	RejectProblemReturnErrorMistypedParameterDecimal         = "34"
	RejectProblemReturnErrorMistypedParameter                = 34
)

// NewRejectProblem returns an immutable RejectProblem containing value.
func NewRejectProblem(value *big.Int) RejectProblem {
	return RejectProblem{value: runtime.CloneBigInt(value)}
}

// NewRejectProblemInt64 returns a RejectProblem containing value.
func NewRejectProblemInt64(value int64) RejectProblem {
	return NewRejectProblem(big.NewInt(value))
}

// RejectProblemGeneralUnrecognizedPDUValue returns the named value general-unrecognizedPDU.
func RejectProblemGeneralUnrecognizedPDUValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemGeneralUnrecognizedPDUDecimal))
}

// RejectProblemGeneralMistypedPDUValue returns the named value general-mistypedPDU.
func RejectProblemGeneralMistypedPDUValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemGeneralMistypedPDUDecimal))
}

// RejectProblemGeneralBadlyStructuredPDUValue returns the named value general-badlyStructuredPDU.
func RejectProblemGeneralBadlyStructuredPDUValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemGeneralBadlyStructuredPDUDecimal))
}

// RejectProblemInvokeDuplicateInvocationValue returns the named value invoke-duplicateInvocation.
func RejectProblemInvokeDuplicateInvocationValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeDuplicateInvocationDecimal))
}

// RejectProblemInvokeUnrecognizedOperationValue returns the named value invoke-unrecognizedOperation.
func RejectProblemInvokeUnrecognizedOperationValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeUnrecognizedOperationDecimal))
}

// RejectProblemInvokeMistypedArgumentValue returns the named value invoke-mistypedArgument.
func RejectProblemInvokeMistypedArgumentValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeMistypedArgumentDecimal))
}

// RejectProblemInvokeResourceLimitationValue returns the named value invoke-resourceLimitation.
func RejectProblemInvokeResourceLimitationValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeResourceLimitationDecimal))
}

// RejectProblemInvokeReleaseInProgressValue returns the named value invoke-releaseInProgress.
func RejectProblemInvokeReleaseInProgressValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeReleaseInProgressDecimal))
}

// RejectProblemInvokeUnrecognizedLinkedIdValue returns the named value invoke-unrecognizedLinkedId.
func RejectProblemInvokeUnrecognizedLinkedIdValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeUnrecognizedLinkedIdDecimal))
}

// RejectProblemInvokeLinkedResponseUnexpectedValue returns the named value invoke-linkedResponseUnexpected.
func RejectProblemInvokeLinkedResponseUnexpectedValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeLinkedResponseUnexpectedDecimal))
}

// RejectProblemInvokeUnexpectedLinkedOperationValue returns the named value invoke-unexpectedLinkedOperation.
func RejectProblemInvokeUnexpectedLinkedOperationValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemInvokeUnexpectedLinkedOperationDecimal))
}

// RejectProblemReturnResultUnrecognizedInvocationValue returns the named value returnResult-unrecognizedInvocation.
func RejectProblemReturnResultUnrecognizedInvocationValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnResultUnrecognizedInvocationDecimal))
}

// RejectProblemReturnResultResultResponseUnexpectedValue returns the named value returnResult-resultResponseUnexpected.
func RejectProblemReturnResultResultResponseUnexpectedValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnResultResultResponseUnexpectedDecimal))
}

// RejectProblemReturnResultMistypedResultValue returns the named value returnResult-mistypedResult.
func RejectProblemReturnResultMistypedResultValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnResultMistypedResultDecimal))
}

// RejectProblemReturnErrorUnrecognizedInvocationValue returns the named value returnError-unrecognizedInvocation.
func RejectProblemReturnErrorUnrecognizedInvocationValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnErrorUnrecognizedInvocationDecimal))
}

// RejectProblemReturnErrorErrorResponseUnexpectedValue returns the named value returnError-errorResponseUnexpected.
func RejectProblemReturnErrorErrorResponseUnexpectedValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnErrorErrorResponseUnexpectedDecimal))
}

// RejectProblemReturnErrorUnrecognizedErrorValue returns the named value returnError-unrecognizedError.
func RejectProblemReturnErrorUnrecognizedErrorValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnErrorUnrecognizedErrorDecimal))
}

// RejectProblemReturnErrorUnexpectedErrorValue returns the named value returnError-unexpectedError.
func RejectProblemReturnErrorUnexpectedErrorValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnErrorUnexpectedErrorDecimal))
}

// RejectProblemReturnErrorMistypedParameterValue returns the named value returnError-mistypedParameter.
func RejectProblemReturnErrorMistypedParameterValue() RejectProblem {
	return NewRejectProblem(runtime.MustParseBigIntDecimal(RejectProblemReturnErrorMistypedParameterDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v RejectProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v RejectProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v RejectProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case RejectProblemGeneralUnrecognizedPDUDecimal:
		return "general-unrecognizedPDU", true
	case RejectProblemGeneralMistypedPDUDecimal:
		return "general-mistypedPDU", true
	case RejectProblemGeneralBadlyStructuredPDUDecimal:
		return "general-badlyStructuredPDU", true
	case RejectProblemInvokeDuplicateInvocationDecimal:
		return "invoke-duplicateInvocation", true
	case RejectProblemInvokeUnrecognizedOperationDecimal:
		return "invoke-unrecognizedOperation", true
	case RejectProblemInvokeMistypedArgumentDecimal:
		return "invoke-mistypedArgument", true
	case RejectProblemInvokeResourceLimitationDecimal:
		return "invoke-resourceLimitation", true
	case RejectProblemInvokeReleaseInProgressDecimal:
		return "invoke-releaseInProgress", true
	case RejectProblemInvokeUnrecognizedLinkedIdDecimal:
		return "invoke-unrecognizedLinkedId", true
	case RejectProblemInvokeLinkedResponseUnexpectedDecimal:
		return "invoke-linkedResponseUnexpected", true
	case RejectProblemInvokeUnexpectedLinkedOperationDecimal:
		return "invoke-unexpectedLinkedOperation", true
	case RejectProblemReturnResultUnrecognizedInvocationDecimal:
		return "returnResult-unrecognizedInvocation", true
	case RejectProblemReturnResultResultResponseUnexpectedDecimal:
		return "returnResult-resultResponseUnexpected", true
	case RejectProblemReturnResultMistypedResultDecimal:
		return "returnResult-mistypedResult", true
	case RejectProblemReturnErrorUnrecognizedInvocationDecimal:
		return "returnError-unrecognizedInvocation", true
	case RejectProblemReturnErrorErrorResponseUnexpectedDecimal:
		return "returnError-errorResponseUnexpected", true
	case RejectProblemReturnErrorUnrecognizedErrorDecimal:
		return "returnError-unrecognizedError", true
	case RejectProblemReturnErrorUnexpectedErrorDecimal:
		return "returnError-unexpectedError", true
	case RejectProblemReturnErrorMistypedParameterDecimal:
		return "returnError-mistypedParameter", true
	default:
		return "", false
	}
}

// String returns the ASN.1 named label, or the decimal value when unnamed.
func (v RejectProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v RejectProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *RejectProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal RejectProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewRejectProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v RejectProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *RejectProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal RejectProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewRejectProblem(value)
	return nil
}

// InvokeId choice constants.
const (
	InvokeIdChoicePresent = 1
	InvokeIdChoiceAbsent  = 2
)

// InvokeId represents the ASN.1 CHOICE type InvokeId.
type InvokeId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Present        *big.Int        `json:"Present,omitempty"`
	Absent         *struct{}       `json:"Absent,omitempty"`
}

// NewInvokeIdPresent creates a InvokeId with the present alternative.
func NewInvokeIdPresent(v *big.Int) InvokeId {
	return InvokeId{
		Choice:  InvokeIdChoicePresent,
		Present: v,
	}
}

// NewInvokeIdAbsent creates a InvokeId with the absent alternative.
func NewInvokeIdAbsent(v struct{}) InvokeId {
	return InvokeId{
		Choice: InvokeIdChoiceAbsent,
		Absent: &v,
	}
}

// Bind choice constants.
const (
	BindChoiceBindInvoke = 1
	BindChoiceBindResult = 2
	BindChoiceBindError  = 3
)

// Bind represents the ASN.1 CHOICE type Bind.
type Bind struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode   `json:"-"`
	BindInvoke     *runtime.RawValue `json:"BindInvoke,omitempty" asn1c:"raw-preserve"`
	BindResult     *runtime.RawValue `json:"BindResult,omitempty" asn1c:"raw-preserve"`
	BindError      *runtime.RawValue `json:"BindError,omitempty" asn1c:"raw-preserve"`
}

// NewBindBindInvoke creates a Bind with the bind-invoke alternative.
func NewBindBindInvoke(v runtime.RawValue) Bind {
	return Bind{
		Choice:     BindChoiceBindInvoke,
		BindInvoke: &v,
	}
}

// NewBindBindResult creates a Bind with the bind-result alternative.
func NewBindBindResult(v runtime.RawValue) Bind {
	return Bind{
		Choice:     BindChoiceBindResult,
		BindResult: &v,
	}
}

// NewBindBindError creates a Bind with the bind-error alternative.
func NewBindBindError(v runtime.RawValue) Bind {
	return Bind{
		Choice:    BindChoiceBindError,
		BindError: &v,
	}
}

// Unbind choice constants.
const (
	UnbindChoiceUnbindInvoke = 1
	UnbindChoiceUnbindResult = 2
	UnbindChoiceUnbindError  = 3
)

// Unbind represents the ASN.1 CHOICE type Unbind.
type Unbind struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode   `json:"-"`
	UnbindInvoke   *runtime.RawValue `json:"UnbindInvoke,omitempty" asn1c:"raw-preserve"`
	UnbindResult   *runtime.RawValue `json:"UnbindResult,omitempty" asn1c:"raw-preserve"`
	UnbindError    *runtime.RawValue `json:"UnbindError,omitempty" asn1c:"raw-preserve"`
}

// NewUnbindUnbindInvoke creates a Unbind with the unbind-invoke alternative.
func NewUnbindUnbindInvoke(v runtime.RawValue) Unbind {
	return Unbind{
		Choice:       UnbindChoiceUnbindInvoke,
		UnbindInvoke: &v,
	}
}

// NewUnbindUnbindResult creates a Unbind with the unbind-result alternative.
func NewUnbindUnbindResult(v runtime.RawValue) Unbind {
	return Unbind{
		Choice:       UnbindChoiceUnbindResult,
		UnbindResult: &v,
	}
}

// NewUnbindUnbindError creates a Unbind with the unbind-error alternative.
func NewUnbindUnbindError(v runtime.RawValue) Unbind {
	return Unbind{
		Choice:      UnbindChoiceUnbindError,
		UnbindError: &v,
	}
}

// ROSInvokeLinkedId choice constants.
const (
	ROSInvokeLinkedIdChoicePresent = 1
	ROSInvokeLinkedIdChoiceAbsent  = 2
)

// ROSInvokeLinkedId represents the ASN.1 CHOICE type ROS-invoke-linkedId.
type ROSInvokeLinkedId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Present        *big.Int        `json:"Present,omitempty"`
	Absent         *struct{}       `json:"Absent,omitempty"`
}

// NewROSInvokeLinkedIdPresent creates a ROSInvokeLinkedId with the present alternative.
func NewROSInvokeLinkedIdPresent(v *big.Int) ROSInvokeLinkedId {
	return ROSInvokeLinkedId{
		Choice:  ROSInvokeLinkedIdChoicePresent,
		Present: v,
	}
}

// NewROSInvokeLinkedIdAbsent creates a ROSInvokeLinkedId with the absent alternative.
func NewROSInvokeLinkedIdAbsent(v struct{}) ROSInvokeLinkedId {
	return ROSInvokeLinkedId{
		Choice: ROSInvokeLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ROSReturnResultResult represents the ASN.1 type ROS-returnResult-result (SEQUENCE).
type ROSReturnResultResult struct {
	Opcode Code `asn1:""`
	// Result carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	Result         runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode  `asn1:"-" json:"-"`
}

// InvokeLinkedId choice constants.
const (
	InvokeLinkedIdChoicePresent = 1
	InvokeLinkedIdChoiceAbsent  = 2
)

// InvokeLinkedId represents the ASN.1 CHOICE type Invoke-linkedId.
type InvokeLinkedId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Present        *big.Int        `json:"Present,omitempty"`
	Absent         *struct{}       `json:"Absent,omitempty"`
}

// NewInvokeLinkedIdPresent creates a InvokeLinkedId with the present alternative.
func NewInvokeLinkedIdPresent(v *big.Int) InvokeLinkedId {
	return InvokeLinkedId{
		Choice:  InvokeLinkedIdChoicePresent,
		Present: v,
	}
}

// NewInvokeLinkedIdAbsent creates a InvokeLinkedId with the absent alternative.
func NewInvokeLinkedIdAbsent(v struct{}) InvokeLinkedId {
	return InvokeLinkedId{
		Choice: InvokeLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ReturnResultResult represents the ASN.1 type ReturnResult-result (SEQUENCE).
type ReturnResultResult struct {
	Opcode Code `asn1:""`
	// Result carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	Result         runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode  `asn1:"-" json:"-"`
}

// OperationsRejectProblem choice constants.
const (
	OperationsRejectProblemChoiceGeneral      = 1
	OperationsRejectProblemChoiceInvoke       = 2
	OperationsRejectProblemChoiceReturnResult = 3
	OperationsRejectProblemChoiceReturnError  = 4
)

// OperationsRejectProblem represents the ASN.1 CHOICE type Reject-problem.
type OperationsRejectProblem struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode      `json:"-"`
	General        *GeneralProblem      `json:"General,omitempty"`
	Invoke         *InvokeProblem       `json:"Invoke,omitempty"`
	ReturnResult   *ReturnResultProblem `json:"ReturnResult,omitempty"`
	ReturnError    *ReturnErrorProblem  `json:"ReturnError,omitempty"`
}

// NewOperationsRejectProblemGeneral creates a OperationsRejectProblem with the general alternative.
func NewOperationsRejectProblemGeneral(v GeneralProblem) OperationsRejectProblem {
	return OperationsRejectProblem{
		Choice:  OperationsRejectProblemChoiceGeneral,
		General: &v,
	}
}

// NewOperationsRejectProblemInvoke creates a OperationsRejectProblem with the invoke alternative.
func NewOperationsRejectProblemInvoke(v InvokeProblem) OperationsRejectProblem {
	return OperationsRejectProblem{
		Choice: OperationsRejectProblemChoiceInvoke,
		Invoke: &v,
	}
}

// NewOperationsRejectProblemReturnResult creates a OperationsRejectProblem with the returnResult alternative.
func NewOperationsRejectProblemReturnResult(v ReturnResultProblem) OperationsRejectProblem {
	return OperationsRejectProblem{
		Choice:       OperationsRejectProblemChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewOperationsRejectProblemReturnError creates a OperationsRejectProblem with the returnError alternative.
func NewOperationsRejectProblemReturnError(v ReturnErrorProblem) OperationsRejectProblem {
	return OperationsRejectProblem{
		Choice:      OperationsRejectProblemChoiceReturnError,
		ReturnError: &v,
	}
}

// MarshalBER encodes ROS to BER format.
func (v *ROS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROS receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROS).MarshalBER, (*ROS).marshalBER, 1)

}
func (v *ROS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ROSChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROS: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ROSChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ROSChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROS: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROS", v.Choice)
	}
}

// MarshalDER encodes ROS to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROS) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROS receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ROSChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROS: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case ROSChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case ROSChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case ROSChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROS: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ROSChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case ROSChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case ROSChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case ROSChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROS as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROS) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROS from BER/DER format.
func (destination *ROS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROS destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROS)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ROS", "child", (*ROS).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROS).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROS{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROS CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROS", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROS.invoke", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROS.returnResult", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROS.returnError", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROS.reject", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for ROS CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes Invoke to BER format.
func (v *Invoke) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: Invoke receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*Invoke).MarshalBER, (*Invoke).marshalBER, 1)

}
func (v *Invoke) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if !((v.LinkedId == nil) || (v.LinkedId != nil)) {
		return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_invokeid)
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_linkedid)
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_opcode)
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		if rawErr := ber.ValidateRawValueIdentifier(*v.Argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		enc_argument := v.Argument.Bytes
		if err := checkOpaqueElement(enc_argument, opts, "argument", -1, "Remote-Operations-Generic-ROS-PDUs.Invoke.argument", nil); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *Invoke) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes Invoke to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *Invoke) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Invoke receiver is nil", ber.ErrInvalidValue)
	}
	if !((v.LinkedId == nil) || (v.LinkedId != nil)) {
		return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		if rawErr := ber.ValidateRawValueIdentifier(*v.Argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, invalidDEROpaqueElement(enc_argument, "argument", "Remote-Operations-Generic-ROS-PDUs.Invoke.argument")
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Invoke as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *Invoke) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes Invoke from BER/DER format.
func (destination *Invoke) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: Invoke destination is nil", ber.ErrInvalidValue)
	}
	v := new(Invoke)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.Invoke", "child", (*Invoke).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Invoke{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*Invoke).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding Invoke SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Invoke", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field invokeId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (InvokeId)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (InvokeLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid InvokeLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field opcode", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		rawTag_argument, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Class: int(rawTag_argument.Class), Tag: rawTag_argument.Number, Constructed: rawTag_argument.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_argument]...)}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Invoke", Cause: ber.ErrUnexpectedElement}
	}
	if !((v.LinkedId == nil) || (v.LinkedId != nil)) {
		return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
	}
	return nil
}

// MarshalBER encodes ReturnResult to BER format.
func (v *ReturnResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReturnResult).MarshalBER, (*ReturnResult).marshalBER, 1)

}
func (v *ReturnResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_invokeid)
	children = append(children, enc_invokeid...)
	if v.Result != nil {
		enc_result, err := v.Result.MarshalBER(ber.ChildEncodeOptions(opts, "result")...)
		if err != nil {
			return nil, qualifyBERError(err, "result", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_result)
		children = append(children, enc_result...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReturnResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReturnResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReturnResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.Result != nil {
		enc_result, err := v.Result.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "result", "encoding", true)
		}
		children = append(children, enc_result...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReturnResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReturnResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReturnResult from BER/DER format.
func (destination *ReturnResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReturnResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReturnResult)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ReturnResult", "child", (*ReturnResult).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReturnResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReturnResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReturnResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field invokeId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (InvokeId)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode result
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "result", content[offset:])
				// Decode nested SEQUENCE (ReturnResultResult)
				_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_result != nil {
					return qualifyBERError(tlvErr_result, "result", "decoding", false)
				}
				var dec_result ReturnResultResult
				if offset < 0 || offset >
					len(content) || n_result < 0 || n_result > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_result.UnmarshalBER(content[offset:offset+n_result], ber.ChildDecodeOptions(opts, "result")...); unmErr != nil {
					return qualifyBERError(unmErr, "result", "decoding", false)
				}
				v.Result = &dec_result
				if offset < 0 || offset >
					len(content) || n_result < 0 || n_result > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_result
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ReturnError to BER format.
func (v *ReturnError) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnError receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReturnError).MarshalBER, (*ReturnError).marshalBER, 1)

}
func (v *ReturnError) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_invokeid)
	children = append(children, enc_invokeid...)
	enc_errcode, err := v.Errcode.MarshalBER(ber.ChildEncodeOptions(opts, "errcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "errcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_errcode)
	children = append(children, enc_errcode...)
	if v.Parameter != nil {
		if rawErr := ber.ValidateRawValueIdentifier(*v.Parameter); rawErr != nil {
			return nil, qualifyBERError(rawErr, "parameter", "encoding", false)
		}
		enc_parameter := v.Parameter.Bytes
		if err := checkOpaqueElement(enc_parameter, opts, "parameter", -1, "Remote-Operations-Generic-ROS-PDUs.ReturnError.parameter", nil); err != nil {
			return nil, qualifyBERError(err, "parameter", "encoding", false)
		}
		children = append(children, enc_parameter...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReturnError) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReturnError to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReturnError) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnError receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	enc_errcode, err := v.Errcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "errcode", "encoding", true)
	}
	children = append(children, enc_errcode...)
	if v.Parameter != nil {
		if rawErr := ber.ValidateRawValueIdentifier(*v.Parameter); rawErr != nil {
			return nil, qualifyBERError(rawErr, "parameter", "encoding", true)
		}
		enc_parameter := v.Parameter.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_parameter); rawErr != nil {
			return nil, invalidDEROpaqueElement(enc_parameter, "parameter", "Remote-Operations-Generic-ROS-PDUs.ReturnError.parameter")
		}
		children = append(children, enc_parameter...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReturnError as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReturnError) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReturnError from BER/DER format.
func (destination *ReturnError) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReturnError destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReturnError)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ReturnError", "child", (*ReturnError).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReturnError{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReturnError).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReturnError SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field invokeId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (InvokeId)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode errcode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field errcode", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "errcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_errcode, _, tlvErr_errcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_errcode != nil {
			return qualifyBERError(tlvErr_errcode, "errcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_errcode < 0 || n_errcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Errcode.UnmarshalBER(content[offset:offset+n_errcode], ber.ChildDecodeOptions(opts, "errcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "errcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_errcode < 0 || n_errcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_errcode
	}
	// Decode parameter
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "parameter", content[offset:])
		rawTag_parameter, n_parameter, _, tlvErr_parameter := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_parameter != nil {
			return qualifyBERError(tlvErr_parameter, "parameter", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "parameter", content[offset:], n_parameter)
		if offset < 0 || offset >
			len(content) || n_parameter < 0 || n_parameter > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_parameter := runtime.RawValue{Class: int(rawTag_parameter.Class), Tag: rawTag_parameter.Number, Constructed: rawTag_parameter.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_parameter]...)}
		v.Parameter = &tmp_parameter
		if offset < 0 || offset >
			len(content) || n_parameter < 0 || n_parameter > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_parameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnError", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes Reject to BER format.
func (v *Reject) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: Reject receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*Reject).MarshalBER, (*Reject).marshalBER, 1)

}
func (v *Reject) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_invokeid)
	children = append(children, enc_invokeid...)
	enc_problem, err := v.Problem.MarshalBER(ber.ChildEncodeOptions(opts, "problem")...)
	if err != nil {
		return nil, qualifyBERError(err, "problem", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_problem)
	children = append(children, enc_problem...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *Reject) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes Reject to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *Reject) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Reject receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	enc_problem, err := v.Problem.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "problem", "encoding", true)
	}
	children = append(children, enc_problem...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Reject as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *Reject) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes Reject from BER/DER format.
func (destination *Reject) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: Reject destination is nil", ber.ErrInvalidValue)
	}
	v := new(Reject)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.Reject", "child", (*Reject).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Reject{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*Reject).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding Reject SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Reject", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field invokeId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (InvokeId)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode problem
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field problem", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "problem", content[offset:])
		// Decode nested CHOICE (OperationsRejectProblem)
		_, n_problem, _, tlvErr_problem := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_problem != nil {
			return qualifyBERError(tlvErr_problem, "problem", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_problem < 0 || n_problem > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Problem.UnmarshalBER(content[offset:offset+n_problem], ber.ChildDecodeOptions(opts, "problem")...); unmErr != nil {
			return qualifyBERError(unmErr, "problem", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_problem < 0 || n_problem > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_problem
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Reject", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBERGeneralProblem encodes a typed standalone GeneralProblem, preserving unchanged received BER.
func MarshalBERGeneralProblem(value *BERValue[GeneralProblem], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required GeneralProblem is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERGeneralProblem, marshalBERGeneralProblem, 0, UnmarshalBERGeneralProblem)

}
func marshalBERGeneralProblem(value *BERValue[GeneralProblem], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value GeneralProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding GeneralProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERGeneralProblem encodes a typed standalone GeneralProblem using DER.
func MarshalDERGeneralProblem(value *BERValue[GeneralProblem]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required GeneralProblem is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value GeneralProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding GeneralProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERGeneralProblem decodes one complete typed standalone GeneralProblem from BER/DER.
func UnmarshalBERGeneralProblem(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[GeneralProblem], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.GeneralProblem", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERGeneralProblem(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value GeneralProblem }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "GeneralProblem", content[offset:])
		val_value, n, err := ber.DecodeBigInt(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding GeneralProblem", qualifyBERError(err, "", "decoding", false))
		}
		var named_value GeneralProblem
		if namedErr := named_value.UnmarshalText([]byte(val_value.String())); namedErr != nil {
			return fmt.Errorf("%s: %w", "decoding GeneralProblem", qualifyBERError(namedErr, "", "decoding", false))
		}
		v.Value = named_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[GeneralProblem]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERGeneralProblem); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERInvokeProblem encodes a typed standalone InvokeProblem, preserving unchanged received BER.
func MarshalBERInvokeProblem(value *BERValue[InvokeProblem], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required InvokeProblem is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERInvokeProblem, marshalBERInvokeProblem, 0, UnmarshalBERInvokeProblem)

}
func marshalBERInvokeProblem(value *BERValue[InvokeProblem], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value InvokeProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding InvokeProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERInvokeProblem encodes a typed standalone InvokeProblem using DER.
func MarshalDERInvokeProblem(value *BERValue[InvokeProblem]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required InvokeProblem is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value InvokeProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding InvokeProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERInvokeProblem decodes one complete typed standalone InvokeProblem from BER/DER.
func UnmarshalBERInvokeProblem(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[InvokeProblem], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.InvokeProblem", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERInvokeProblem(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value InvokeProblem }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "InvokeProblem", content[offset:])
		val_value, n, err := ber.DecodeBigInt(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding InvokeProblem", qualifyBERError(err, "", "decoding", false))
		}
		var named_value InvokeProblem
		if namedErr := named_value.UnmarshalText([]byte(val_value.String())); namedErr != nil {
			return fmt.Errorf("%s: %w", "decoding InvokeProblem", qualifyBERError(namedErr, "", "decoding", false))
		}
		v.Value = named_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[InvokeProblem]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERInvokeProblem); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERReturnResultProblem encodes a typed standalone ReturnResultProblem, preserving unchanged received BER.
func MarshalBERReturnResultProblem(value *BERValue[ReturnResultProblem], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required ReturnResultProblem is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERReturnResultProblem, marshalBERReturnResultProblem, 0, UnmarshalBERReturnResultProblem)

}
func marshalBERReturnResultProblem(value *BERValue[ReturnResultProblem], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value ReturnResultProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReturnResultProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERReturnResultProblem encodes a typed standalone ReturnResultProblem using DER.
func MarshalDERReturnResultProblem(value *BERValue[ReturnResultProblem]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required ReturnResultProblem is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value ReturnResultProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReturnResultProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERReturnResultProblem decodes one complete typed standalone ReturnResultProblem from BER/DER.
func UnmarshalBERReturnResultProblem(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[ReturnResultProblem], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ReturnResultProblem", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERReturnResultProblem(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value ReturnResultProblem }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "ReturnResultProblem", content[offset:])
		val_value, n, err := ber.DecodeBigInt(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding ReturnResultProblem", qualifyBERError(err, "", "decoding", false))
		}
		var named_value ReturnResultProblem
		if namedErr := named_value.UnmarshalText([]byte(val_value.String())); namedErr != nil {
			return fmt.Errorf("%s: %w", "decoding ReturnResultProblem", qualifyBERError(namedErr, "", "decoding", false))
		}
		v.Value = named_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[ReturnResultProblem]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERReturnResultProblem); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERReturnErrorProblem encodes a typed standalone ReturnErrorProblem, preserving unchanged received BER.
func MarshalBERReturnErrorProblem(value *BERValue[ReturnErrorProblem], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required ReturnErrorProblem is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERReturnErrorProblem, marshalBERReturnErrorProblem, 0, UnmarshalBERReturnErrorProblem)

}
func marshalBERReturnErrorProblem(value *BERValue[ReturnErrorProblem], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value ReturnErrorProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReturnErrorProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERReturnErrorProblem encodes a typed standalone ReturnErrorProblem using DER.
func MarshalDERReturnErrorProblem(value *BERValue[ReturnErrorProblem]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required ReturnErrorProblem is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value ReturnErrorProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReturnErrorProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERReturnErrorProblem decodes one complete typed standalone ReturnErrorProblem from BER/DER.
func UnmarshalBERReturnErrorProblem(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[ReturnErrorProblem], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ReturnErrorProblem", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERReturnErrorProblem(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value ReturnErrorProblem }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "ReturnErrorProblem", content[offset:])
		val_value, n, err := ber.DecodeBigInt(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding ReturnErrorProblem", qualifyBERError(err, "", "decoding", false))
		}
		var named_value ReturnErrorProblem
		if namedErr := named_value.UnmarshalText([]byte(val_value.String())); namedErr != nil {
			return fmt.Errorf("%s: %w", "decoding ReturnErrorProblem", qualifyBERError(namedErr, "", "decoding", false))
		}
		v.Value = named_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[ReturnErrorProblem]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERReturnErrorProblem); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERRejectProblem encodes a typed standalone RejectProblem, preserving unchanged received BER.
func MarshalBERRejectProblem(value *BERValue[RejectProblem], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required RejectProblem is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERRejectProblem, marshalBERRejectProblem, 0, UnmarshalBERRejectProblem)

}
func marshalBERRejectProblem(value *BERValue[RejectProblem], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value RejectProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RejectProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERRejectProblem encodes a typed standalone RejectProblem using DER.
func MarshalDERRejectProblem(value *BERValue[RejectProblem]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required RejectProblem is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value RejectProblem }{Value: value.Value}
	_ = v
	var children []byte
	enc_value, encodeErr_enc_value := ber.EncodeBigInt((v.Value).BigInt())
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RejectProblem", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERRejectProblem decodes one complete typed standalone RejectProblem from BER/DER.
func UnmarshalBERRejectProblem(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[RejectProblem], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.RejectProblem", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERRejectProblem(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value RejectProblem }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "RejectProblem", content[offset:])
		val_value, n, err := ber.DecodeBigInt(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding RejectProblem", qualifyBERError(err, "", "decoding", false))
		}
		var named_value RejectProblem
		if namedErr := named_value.UnmarshalText([]byte(val_value.String())); namedErr != nil {
			return fmt.Errorf("%s: %w", "decoding RejectProblem", qualifyBERError(namedErr, "", "decoding", false))
		}
		v.Value = named_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[RejectProblem]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERRejectProblem); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes InvokeId to BER format.
func (v *InvokeId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InvokeId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InvokeId).MarshalBER, (*InvokeId).marshalBER, 1)

}
func (v *InvokeId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *InvokeId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case InvokeIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice InvokeId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		return enc_0, nil
	case InvokeIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InvokeId", v.Choice)
	}
}

// MarshalDER encodes InvokeId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InvokeId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InvokeId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case InvokeIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case InvokeIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding InvokeId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *InvokeId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InvokeId from BER/DER format.
func (destination *InvokeId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InvokeId destination is nil", ber.ErrInvalidValue)
	}
	v := new(InvokeId)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.InvokeId", "child", (*InvokeId).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InvokeId).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InvokeId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for InvokeId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InvokeId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding InvokeId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InvokeId", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InvokeId.present", "decoding", false)
	}
	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InvokeId.absent", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = InvokeIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = InvokeIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, nullErr := ber.DecodeNull(choiceData, opts...)
		if nullErr != nil {
			return qualifyBERError(nullErr, "absent", "decoding", false)
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for InvokeId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes Bind to BER format.
func (v *Bind) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: Bind receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*Bind).MarshalBER, (*Bind).marshalBER, 1)

}
func (v *Bind) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *Bind) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BindChoiceBindInvoke:
		if v.BindInvoke == nil {
			return nil, fmt.Errorf("%w: choice Bind: bind-invoke is nil", ber.ErrInvalidValue)
		}
		if rawErr := ber.ValidateRawValueIdentifier(*v.BindInvoke); rawErr != nil {
			return nil, qualifyBERError(rawErr, "bind-invoke", "encoding", false)
		}
		enc_0 := v.BindInvoke.Bytes
		if err := checkOpaqueElement(enc_0, opts, "bind-invoke", -1, "Remote-Operations-Generic-ROS-PDUs.Bind.bind-invoke", nil); err != nil {
			return nil, qualifyBERError(err, "bind-invoke", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "bind-invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BindChoiceBindResult:
		if v.BindResult == nil {
			return nil, fmt.Errorf("%w: choice Bind: bind-result is nil", ber.ErrInvalidValue)
		}
		if rawErr := ber.ValidateRawValueIdentifier(*v.BindResult); rawErr != nil {
			return nil, qualifyBERError(rawErr, "bind-result", "encoding", false)
		}
		enc_1 := v.BindResult.Bytes
		if err := checkOpaqueElement(enc_1, opts, "bind-result", -1, "Remote-Operations-Generic-ROS-PDUs.Bind.bind-result", nil); err != nil {
			return nil, qualifyBERError(err, "bind-result", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "bind-result", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case BindChoiceBindError:
		if v.BindError == nil {
			return nil, fmt.Errorf("%w: choice Bind: bind-error is nil", ber.ErrInvalidValue)
		}
		if rawErr := ber.ValidateRawValueIdentifier(*v.BindError); rawErr != nil {
			return nil, qualifyBERError(rawErr, "bind-error", "encoding", false)
		}
		enc_2 := v.BindError.Bytes
		if err := checkOpaqueElement(enc_2, opts, "bind-error", -1, "Remote-Operations-Generic-ROS-PDUs.Bind.bind-error", nil); err != nil {
			return nil, qualifyBERError(err, "bind-error", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "bind-error", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Bind", v.Choice)
	}
}

// MarshalDER encodes Bind to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *Bind) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Bind receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case BindChoiceBindInvoke:
			return nil, qualifyBERError(err, "bind-invoke", "encoding", true)
		case BindChoiceBindResult:
			return nil, qualifyBERError(err, "bind-result", "encoding", true)
		case BindChoiceBindError:
			return nil, qualifyBERError(err, "bind-error", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding Bind as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *Bind) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes Bind from BER/DER format.
func (destination *Bind) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: Bind destination is nil", ber.ErrInvalidValue)
	}
	v := new(Bind)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.Bind", "child", (*Bind).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*Bind).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Bind{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Bind CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Bind: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding Bind CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Bind", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
		v.Choice = BindChoiceBindInvoke
		ber.MarkPreflightTarget(opts, "bind-invoke", choiceData)
		ber.MarkPreflightOpaque(opts, "bind-invoke", choiceData, len(choiceData))
		tmpRaw := runtime.RawValue{Class: int(peekTag.Class), Tag: peekTag.Number, Constructed: peekTag.Constructed, Bytes: append([]byte(nil), choiceData...)}
		v.BindInvoke = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
		v.Choice = BindChoiceBindResult
		ber.MarkPreflightTarget(opts, "bind-result", choiceData)
		ber.MarkPreflightOpaque(opts, "bind-result", choiceData, len(choiceData))
		tmpRaw := runtime.RawValue{Class: int(peekTag.Class), Tag: peekTag.Number, Constructed: peekTag.Constructed, Bytes: append([]byte(nil), choiceData...)}
		v.BindResult = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
		v.Choice = BindChoiceBindError
		ber.MarkPreflightTarget(opts, "bind-error", choiceData)
		ber.MarkPreflightOpaque(opts, "bind-error", choiceData, len(choiceData))
		tmpRaw := runtime.RawValue{Class: int(peekTag.Class), Tag: peekTag.Number, Constructed: peekTag.Constructed, Bytes: append([]byte(nil), choiceData...)}
		v.BindError = &tmpRaw
	} else {
		return fmt.Errorf("%w: unknown tag %s for Bind CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes Unbind to BER format.
func (v *Unbind) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: Unbind receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*Unbind).MarshalBER, (*Unbind).marshalBER, 1)

}
func (v *Unbind) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *Unbind) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UnbindChoiceUnbindInvoke:
		if v.UnbindInvoke == nil {
			return nil, fmt.Errorf("%w: choice Unbind: unbind-invoke is nil", ber.ErrInvalidValue)
		}
		if rawErr := ber.ValidateRawValueIdentifier(*v.UnbindInvoke); rawErr != nil {
			return nil, qualifyBERError(rawErr, "unbind-invoke", "encoding", false)
		}
		enc_0 := v.UnbindInvoke.Bytes
		if err := checkOpaqueElement(enc_0, opts, "unbind-invoke", -1, "Remote-Operations-Generic-ROS-PDUs.Unbind.unbind-invoke", nil); err != nil {
			return nil, qualifyBERError(err, "unbind-invoke", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "unbind-invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case UnbindChoiceUnbindResult:
		if v.UnbindResult == nil {
			return nil, fmt.Errorf("%w: choice Unbind: unbind-result is nil", ber.ErrInvalidValue)
		}
		if rawErr := ber.ValidateRawValueIdentifier(*v.UnbindResult); rawErr != nil {
			return nil, qualifyBERError(rawErr, "unbind-result", "encoding", false)
		}
		enc_1 := v.UnbindResult.Bytes
		if err := checkOpaqueElement(enc_1, opts, "unbind-result", -1, "Remote-Operations-Generic-ROS-PDUs.Unbind.unbind-result", nil); err != nil {
			return nil, qualifyBERError(err, "unbind-result", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "unbind-result", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case UnbindChoiceUnbindError:
		if v.UnbindError == nil {
			return nil, fmt.Errorf("%w: choice Unbind: unbind-error is nil", ber.ErrInvalidValue)
		}
		if rawErr := ber.ValidateRawValueIdentifier(*v.UnbindError); rawErr != nil {
			return nil, qualifyBERError(rawErr, "unbind-error", "encoding", false)
		}
		enc_2 := v.UnbindError.Bytes
		if err := checkOpaqueElement(enc_2, opts, "unbind-error", -1, "Remote-Operations-Generic-ROS-PDUs.Unbind.unbind-error", nil); err != nil {
			return nil, qualifyBERError(err, "unbind-error", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "unbind-error", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Unbind", v.Choice)
	}
}

// MarshalDER encodes Unbind to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *Unbind) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Unbind receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case UnbindChoiceUnbindInvoke:
			return nil, qualifyBERError(err, "unbind-invoke", "encoding", true)
		case UnbindChoiceUnbindResult:
			return nil, qualifyBERError(err, "unbind-result", "encoding", true)
		case UnbindChoiceUnbindError:
			return nil, qualifyBERError(err, "unbind-error", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding Unbind as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *Unbind) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes Unbind from BER/DER format.
func (destination *Unbind) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: Unbind destination is nil", ber.ErrInvalidValue)
	}
	v := new(Unbind)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.Unbind", "child", (*Unbind).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*Unbind).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Unbind{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Unbind CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Unbind: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding Unbind CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Unbind", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
		v.Choice = UnbindChoiceUnbindInvoke
		ber.MarkPreflightTarget(opts, "unbind-invoke", choiceData)
		ber.MarkPreflightOpaque(opts, "unbind-invoke", choiceData, len(choiceData))
		tmpRaw := runtime.RawValue{Class: int(peekTag.Class), Tag: peekTag.Number, Constructed: peekTag.Constructed, Bytes: append([]byte(nil), choiceData...)}
		v.UnbindInvoke = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
		v.Choice = UnbindChoiceUnbindResult
		ber.MarkPreflightTarget(opts, "unbind-result", choiceData)
		ber.MarkPreflightOpaque(opts, "unbind-result", choiceData, len(choiceData))
		tmpRaw := runtime.RawValue{Class: int(peekTag.Class), Tag: peekTag.Number, Constructed: peekTag.Constructed, Bytes: append([]byte(nil), choiceData...)}
		v.UnbindResult = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
		v.Choice = UnbindChoiceUnbindError
		ber.MarkPreflightTarget(opts, "unbind-error", choiceData)
		ber.MarkPreflightOpaque(opts, "unbind-error", choiceData, len(choiceData))
		tmpRaw := runtime.RawValue{Class: int(peekTag.Class), Tag: peekTag.Number, Constructed: peekTag.Constructed, Bytes: append([]byte(nil), choiceData...)}
		v.UnbindError = &tmpRaw
	} else {
		return fmt.Errorf("%w: unknown tag %s for Unbind CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSInvokeLinkedId to BER format.
func (v *ROSInvokeLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSInvokeLinkedId).MarshalBER, (*ROSInvokeLinkedId).marshalBER, 1)

}
func (v *ROSInvokeLinkedId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROSInvokeLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ROSInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ROSInvokeLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSInvokeLinkedId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSInvokeLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ROSInvokeLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case ROSInvokeLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROSInvokeLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROSInvokeLinkedId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSInvokeLinkedId from BER/DER format.
func (destination *ROSInvokeLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSInvokeLinkedId destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSInvokeLinkedId)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ROS-invoke-linkedId", "child", (*ROSInvokeLinkedId).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSInvokeLinkedId).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROSInvokeLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSInvokeLinkedId.present", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSInvokeLinkedId.absent", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSInvokeLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ROSInvokeLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("%w: unknown tag %s for ROSInvokeLinkedId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSReturnResultResult to BER format.
func (v *ROSReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSReturnResultResult).MarshalBER, (*ROSReturnResultResult).marshalBER, 1)

}
func (v *ROSReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_opcode)
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	enc_result := v.Result.Bytes
	if err := checkOpaqueElement(enc_result, opts, "result", -1, "Remote-Operations-Generic-ROS-PDUs.ROS-returnResult-result.result", nil); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ROSReturnResultResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ROSReturnResultResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, invalidDEROpaqueElement(enc_result, "result", "Remote-Operations-Generic-ROS-PDUs.ROS-returnResult-result.result")
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ROSReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ROSReturnResultResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSReturnResultResult from BER/DER format.
func (destination *ROSReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSReturnResultResult)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ROS-returnResult-result", "child", (*ROSReturnResultResult).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSReturnResultResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSReturnResultResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ROSReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field opcode", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field result", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		rawTag_result, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Class: int(rawTag_result.Class), Tag: rawTag_result.Number, Constructed: rawTag_result.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_result]...)}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ROSReturnResultResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes InvokeLinkedId to BER format.
func (v *InvokeLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InvokeLinkedId).MarshalBER, (*InvokeLinkedId).marshalBER, 1)

}
func (v *InvokeLinkedId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *InvokeLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case InvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice InvokeLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case InvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes InvokeLinkedId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InvokeLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case InvokeLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case InvokeLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding InvokeLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *InvokeLinkedId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InvokeLinkedId from BER/DER format.
func (destination *InvokeLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InvokeLinkedId destination is nil", ber.ErrInvalidValue)
	}
	v := new(InvokeLinkedId)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.Invoke-linkedId", "child", (*InvokeLinkedId).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InvokeLinkedId).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for InvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding InvokeLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InvokeLinkedId.present", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InvokeLinkedId.absent", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = InvokeLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = InvokeLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("%w: unknown tag %s for InvokeLinkedId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ReturnResultResult to BER format.
func (v *ReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReturnResultResult).MarshalBER, (*ReturnResultResult).marshalBER, 1)

}
func (v *ReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_opcode)
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	enc_result := v.Result.Bytes
	if err := checkOpaqueElement(enc_result, opts, "result", -1, "Remote-Operations-Generic-ROS-PDUs.ReturnResult-result.result", nil); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReturnResultResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReturnResultResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, invalidDEROpaqueElement(enc_result, "result", "Remote-Operations-Generic-ROS-PDUs.ReturnResult-result.result")
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReturnResultResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReturnResultResult from BER/DER format.
func (destination *ReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReturnResultResult)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.ReturnResult-result", "child", (*ReturnResultResult).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReturnResultResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReturnResultResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field opcode", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field result", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		rawTag_result, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Class: int(rawTag_result.Class), Tag: rawTag_result.Number, Constructed: rawTag_result.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_result]...)}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResultResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes OperationsRejectProblem to BER format.
func (v *OperationsRejectProblem) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: OperationsRejectProblem receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*OperationsRejectProblem).MarshalBER, (*OperationsRejectProblem).marshalBER, 1)

}
func (v *OperationsRejectProblem) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *OperationsRejectProblem) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case OperationsRejectProblemChoiceGeneral:
		if v.General == nil {
			return nil, fmt.Errorf("%w: choice OperationsRejectProblem: general is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.General.BigInt())
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "general", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "general", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case OperationsRejectProblemChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice OperationsRejectProblem: invoke is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeBigInt(v.Invoke.BigInt())
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "invoke", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "invoke", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case OperationsRejectProblemChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice OperationsRejectProblem: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeBigInt(v.ReturnResult.BigInt())
		if encodeErr_enc_2 != nil {
			return nil, qualifyBERError(encodeErr_enc_2, "returnResult", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnResult", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case OperationsRejectProblemChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice OperationsRejectProblem: returnError is nil", ber.ErrInvalidValue)
		}
		enc_3, encodeErr_enc_3 := ber.EncodeBigInt(v.ReturnError.BigInt())
		if encodeErr_enc_3 != nil {
			return nil, qualifyBERError(encodeErr_enc_3, "returnError", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "returnError", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for OperationsRejectProblem", v.Choice)
	}
}

// MarshalDER encodes OperationsRejectProblem to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *OperationsRejectProblem) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OperationsRejectProblem receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case OperationsRejectProblemChoiceGeneral:
			return nil, qualifyBERError(err, "general", "encoding", true)
		case OperationsRejectProblemChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case OperationsRejectProblemChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case OperationsRejectProblemChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding OperationsRejectProblem as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *OperationsRejectProblem) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes OperationsRejectProblem from BER/DER format.
func (destination *OperationsRejectProblem) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: OperationsRejectProblem destination is nil", ber.ErrInvalidValue)
	}
	v := new(OperationsRejectProblem)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Generic-ROS-PDUs.Reject-problem", "child", (*OperationsRejectProblem).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*OperationsRejectProblem).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = OperationsRejectProblem{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for OperationsRejectProblem CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for OperationsRejectProblem: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding OperationsRejectProblem CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "OperationsRejectProblem", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "OperationsRejectProblem.general", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "OperationsRejectProblem.invoke", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "OperationsRejectProblem.returnResult", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "OperationsRejectProblem.returnError", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceGeneral
		ber.MarkPreflightTarget(opts, "general", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "general", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "general", "decoding", false)
		}
		var named_general GeneralProblem
		if namedErr := named_general.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return qualifyBERError(namedErr, "general", "decoding", false)
		}
		v.General = &named_general
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "invoke", "decoding", false)
		}
		var named_invoke InvokeProblem
		if namedErr := named_invoke.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return qualifyBERError(namedErr, "invoke", "decoding", false)
		}
		v.Invoke = &named_invoke
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "returnResult", "decoding", false)
		}
		var named_returnresult ReturnResultProblem
		if namedErr := named_returnresult.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return qualifyBERError(namedErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &named_returnresult
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "returnError", "decoding", false)
		}
		var named_returnerror ReturnErrorProblem
		if namedErr := named_returnerror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return qualifyBERError(namedErr, "returnError", "decoding", false)
		}
		v.ReturnError = &named_returnerror
	} else {
		return fmt.Errorf("%w: unknown tag %s for OperationsRejectProblem CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}
