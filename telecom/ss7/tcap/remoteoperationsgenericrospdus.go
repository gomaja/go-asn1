// Code generated from ASN.1 module "Remote-Operations-Generic-ROS-PDUs". DO NOT EDIT.

package tcap

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
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
	InvokeId       TCInvokeIdSet     `asn1:""`
	LinkedId       *InvokeLinkedId   `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode         Code              `asn1:""`
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
	InvokeId       InvokeId          `asn1:""`
	Errcode        Code              `asn1:""`
	Parameter      *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// Reject represents the ASN.1 type Reject (SEQUENCE).
type Reject struct {
	InvokeId       InvokeId            `asn1:""`
	Problem        RejectProblemChoice `asn1:""`
	berReplayNode_ *ber.ReplayNode     `asn1:"-" json:"-"`
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
	Opcode         Code             `asn1:""`
	Result         runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode  `asn1:"-" json:"-"`
}

// RejectProblemChoice choice constants.
const (
	RejectProblemChoiceChoiceGeneral      = 1
	RejectProblemChoiceChoiceInvoke       = 2
	RejectProblemChoiceChoiceReturnResult = 3
	RejectProblemChoiceChoiceReturnError  = 4
)

// RejectProblemChoice represents the ASN.1 CHOICE type RejectProblemChoice.
type RejectProblemChoice struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode      `json:"-"`
	General        *GeneralProblem      `json:"General,omitempty"`
	Invoke         *InvokeProblem       `json:"Invoke,omitempty"`
	ReturnResult   *ReturnResultProblem `json:"ReturnResult,omitempty"`
	ReturnError    *ReturnErrorProblem  `json:"ReturnError,omitempty"`
}

// NewRejectProblemChoiceGeneral creates a RejectProblemChoice with the general alternative.
func NewRejectProblemChoiceGeneral(v GeneralProblem) RejectProblemChoice {
	return RejectProblemChoice{
		Choice:  RejectProblemChoiceChoiceGeneral,
		General: &v,
	}
}

// NewRejectProblemChoiceInvoke creates a RejectProblemChoice with the invoke alternative.
func NewRejectProblemChoiceInvoke(v InvokeProblem) RejectProblemChoice {
	return RejectProblemChoice{
		Choice: RejectProblemChoiceChoiceInvoke,
		Invoke: &v,
	}
}

// NewRejectProblemChoiceReturnResult creates a RejectProblemChoice with the returnResult alternative.
func NewRejectProblemChoiceReturnResult(v ReturnResultProblem) RejectProblemChoice {
	return RejectProblemChoice{
		Choice:       RejectProblemChoiceChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewRejectProblemChoiceReturnError creates a RejectProblemChoice with the returnError alternative.
func NewRejectProblemChoiceReturnError(v ReturnErrorProblem) RejectProblemChoice {
	return RejectProblemChoice{
		Choice:      RejectProblemChoiceChoiceReturnError,
		ReturnError: &v,
	}
}

// MarshalBER encodes ROS to BER format.
func (v *ROS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ROS", "Remote-Operations-Generic-ROS-PDUs", "ROS")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ROS receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == ROSChoiceInvoke || v.Choice == ROSChoiceReturnResult || v.Choice == ROSChoiceReturnError || v.Choice == ROSChoiceReject) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *ROS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROS receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case ROSChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.marshalBER(opts...)
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}
func (v *ROS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
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
func (v *ROS) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROS receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == ROSChoiceInvoke || v.Choice == ROSChoiceReturnResult || v.Choice == ROSChoiceReturnError || v.Choice == ROSChoiceReject {
		encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendDERLinear(encoder)
			return appendErr
		})
		if err != nil {
			return nil, err
		}
		return encoded, nil
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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROS receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ROSChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.MarshalDER()
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}

// UnmarshalBER decodes ROS from BER/DER format.
func (destination *ROS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ROS destination")
	}
	var next ROS
	v := &next

	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ROS", "Remote-Operations-Generic-ROS-PDUs", "ROS")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ROS, replayOpts ...ber.EncodeOption) ([]byte, error) { return base.MarshalBER(replayOpts...) })
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error { var probe ROS; return probe.UnmarshalBER(data, probeOpts...) })
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.ROS", opts)
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
		return fmt.Errorf("unknown tag %s for ROS CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Invoke to BER format.
func (v *Invoke) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Invoke", "Remote-Operations-Generic-ROS-PDUs", "Invoke")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Invoke receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *Invoke) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_argument := v.Argument.Bytes
		if err := checkTCAPOpaqueReplay(

			enc_argument, opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *Invoke) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Invoke receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invokeId")...)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	if v.LinkedId != nil {
		{
			_, err := v.LinkedId.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "linkedId")...)
			if err != nil {
				return nil, qualifyBERError(err, "linkedId", "encoding", true)
			}
		}
	}
	{
		_, err := v.Opcode.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "opcode")...)
		if err != nil {
			return nil, qualifyBERError(err, "opcode", "encoding", true)
		}
	}
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := checkTCAPOpaqueReplay(

			enc_argument, opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", true)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		encoder.Append(enc_argument)
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes Invoke to DER format.
func (v *Invoke) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Invoke receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *Invoke) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Invoke receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	if v.LinkedId != nil {
		{
			_, err := v.LinkedId.appendDERLinear(encoder)
			if err != nil {
				return nil, qualifyBERError(err, "linkedId", "encoding", true)
			}
		}
	}
	{
		_, err := v.Opcode.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "opcode", "encoding", true)
		}
	}
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		encoder.Append(enc_argument)
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes Invoke from BER/DER format.
func (destination *Invoke) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Invoke destination")
	}
	var next Invoke
	v :=
		&next
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Invoke", "Remote-Operations-Generic-ROS-PDUs", "Invoke")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Invoke
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.Invoke", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Invoke{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Invoke, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
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
		return fmt.Errorf("missing required field opcode")
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
		return &ber.DecodeError{Offset: offset, TypeName: "Invoke", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ReturnResult to BER format.
func (v *ReturnResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err
	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ReturnResult", "Remote-Operations-Generic-ROS-PDUs", "ReturnResult")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *ReturnResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invokeId")...)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	if v.Result != nil {
		{
			_, err := v.Result.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "result")...)
			if err != nil {
				return nil, qualifyBERError(err, "result", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes ReturnResult to DER format.
func (v *ReturnResult) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *ReturnResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	if v.Result != nil {
		{
			_, err := v.Result.appendDERLinear(encoder)
			if err != nil {
				return nil, qualifyBERError(err, "result", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes ReturnResult from BER/DER format.
func (destination *ReturnResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ReturnResult destination")
	}
	var next ReturnResult

	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ReturnResult", "Remote-Operations-Generic-ROS-PDUs", "ReturnResult")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ReturnResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.ReturnResult", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReturnResult{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ReturnResult, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
		return fmt.Errorf("missing required field invokeId")
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
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResult", Cause: ber.ErrExtraData}
	}
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr != nil {
		return ruleErr

	}

	return nil
}

// MarshalBER encodes ReturnError to BER format.
func (v *ReturnError) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err
	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ReturnError", "Remote-Operations-Generic-ROS-PDUs", "ReturnError")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnError receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *ReturnError) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_parameter := v.Parameter.Bytes
		if err := checkTCAPOpaqueReplay(

			enc_parameter, opts...); err != nil {
			return nil, qualifyBERError(err, "parameter", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_parameter); rawErr != nil {
			return nil, qualifyBERError(rawErr, "parameter", "encoding", false)
		}
		children = append(children, enc_parameter...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReturnError) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnError receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invokeId")...)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	{
		_, err := v.Errcode.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "errcode")...)
		if err != nil {
			return nil, qualifyBERError(err, "errcode", "encoding", true)
		}
	}
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		if err := checkTCAPOpaqueReplay(

			enc_parameter, opts...); err != nil {
			return nil, qualifyBERError(err, "parameter", "encoding", true)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_parameter); rawErr != nil {
			return nil, qualifyBERError(rawErr, "parameter", "encoding", true)
		}
		encoder.Append(enc_parameter)
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes ReturnError to DER format.
func (v *ReturnError) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnError receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *ReturnError) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnError receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	{
		_, err := v.Errcode.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "errcode", "encoding", true)
		}
	}
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_parameter); rawErr != nil {
			return nil, qualifyBERError(rawErr, "parameter", "encoding", true)
		}
		encoder.Append(enc_parameter)
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes ReturnError from BER/DER format.
func (destination *ReturnError) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ReturnError destination")
	}
	var next ReturnError

	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ReturnError", "Remote-Operations-Generic-ROS-PDUs", "ReturnError")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ReturnError
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.ReturnError", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReturnError{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ReturnError, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
		return fmt.Errorf("missing required field invokeId")
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
		return fmt.Errorf("missing required field errcode")
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
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnError", Cause: ber.ErrExtraData}
	}
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr != nil {
		return ruleErr

	}

	return nil
}

// MarshalBER encodes Reject to BER format.
func (v *Reject) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Reject", "Remote-Operations-Generic-ROS-PDUs", "Reject")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Reject receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *Reject) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	if v == nil {
		return nil, fmt.Errorf("%w: Reject receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invokeId")...)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	{
		_, err := v.Problem.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "problem")...)
		if err != nil {
			return nil, qualifyBERError(err, "problem", "encoding", true)
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes Reject to DER format.
func (v *Reject) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Reject receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *Reject) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Reject receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.InvokeId.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invokeId", "encoding", true)
		}
	}
	{
		_, err := v.Problem.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "problem", "encoding", true)
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes Reject from BER/DER format.
func (destination *Reject) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Reject destination")
	}
	var next Reject
	v :=
		&next
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Reject", "Remote-Operations-Generic-ROS-PDUs", "Reject")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Reject
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.Reject", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Reject{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Reject, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
		return fmt.Errorf("missing required field invokeId")
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
		return fmt.Errorf("missing required field problem")
	}
	{
		ber.MarkPreflightTarget(opts, "problem", content[offset:])
		// Decode nested CHOICE (RejectProblemChoice)
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
		return &ber.DecodeError{Offset: offset, TypeName: "Reject", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes InvokeId to BER format.
func (v *InvokeId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "InvokeId", "Remote-Operations-Generic-ROS-PDUs", "InvokeId")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: InvokeId receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *InvokeId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *InvokeId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

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
		if !(v.Present.Cmp(runtime.MustParseBigIntDecimal("-128")) >= 0 && v.Present.Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeSource(opts, "Remote-Operations-Generic-ROS-PDUs.InvokeId"), "present", "Q.773 §4.2.2.2: component-id-one-octet", ber.ObserveInteger(v.Present)); constraintErr != nil {
				return nil, constraintErr
			}
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
func (v *InvokeId) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

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
		return fmt.Errorf("nil InvokeId destination")
	}
	var next InvokeId

	v := &next
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "InvokeId", "Remote-Operations-Generic-ROS-PDUs", "InvokeId")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *InvokeId, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe InvokeId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.InvokeId", opts)
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
		if !(v.Present.Cmp(runtime.MustParseBigIntDecimal("-128")) >= 0 && v.Present.Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckDecodedValue(opts, "present", "Q.773 §4.2.2.2: component-id-one-octet", ber.ObserveInteger(v.Present)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = InvokeIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, nullErr := ber.DecodeNull(choiceData, opts...)
		if nullErr != nil {
			return qualifyBERError(nullErr, "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for InvokeId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Bind to BER format.
func (v *Bind) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Bind", "Remote-Operations-Generic-ROS-PDUs", "Bind")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Bind receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}

func (v *Bind) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BindChoiceBindInvoke:
		if v.BindInvoke == nil {
			return nil, fmt.Errorf("%w: choice Bind: bind-invoke is nil", ber.ErrInvalidValue)
		}
		enc_0 := v.BindInvoke.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "bind-invoke", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_0); rawErr != nil {
			return nil, qualifyBERError(rawErr, "bind-invoke", "encoding", false)
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
		enc_1 := v.BindResult.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "bind-result", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_1); rawErr != nil {
			return nil, qualifyBERError(rawErr, "bind-result", "encoding", false)
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
		enc_2 := v.BindError.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "bind-error", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_2); rawErr != nil {
			return nil, qualifyBERError(rawErr, "bind-error", "encoding", false)
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
func (v *Bind) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

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

// UnmarshalBER decodes Bind from BER/DER format.
func (destination *Bind) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Bind destination")
	}
	var next Bind
	v := &next

	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Bind", "Remote-Operations-Generic-ROS-PDUs", "Bind")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Bind, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Bind
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.Bind", opts)
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
		return fmt.Errorf("unknown tag %s for Bind CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Unbind to BER format.
func (v *Unbind) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Unbind", "Remote-Operations-Generic-ROS-PDUs", "Unbind")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Unbind receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}

func (v *Unbind) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UnbindChoiceUnbindInvoke:
		if v.UnbindInvoke == nil {
			return nil, fmt.Errorf("%w: choice Unbind: unbind-invoke is nil", ber.ErrInvalidValue)
		}
		enc_0 := v.UnbindInvoke.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "unbind-invoke", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_0); rawErr != nil {
			return nil, qualifyBERError(rawErr, "unbind-invoke", "encoding", false)
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
		enc_1 := v.UnbindResult.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "unbind-result", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_1); rawErr != nil {
			return nil, qualifyBERError(rawErr, "unbind-result", "encoding", false)
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
		enc_2 := v.UnbindError.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "unbind-error", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_2); rawErr != nil {
			return nil, qualifyBERError(rawErr, "unbind-error", "encoding", false)
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
func (v *Unbind) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

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

// UnmarshalBER decodes Unbind from BER/DER format.
func (destination *Unbind) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Unbind destination")
	}
	var next Unbind
	v :=
		&next
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Unbind", "Remote-Operations-Generic-ROS-PDUs", "Unbind")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Unbind, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Unbind
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.Unbind", opts)
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
		return fmt.Errorf("unknown tag %s for Unbind CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes InvokeLinkedId to BER format.
func (v *InvokeLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err
	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "InvokeLinkedId", "Remote-Operations-Generic-ROS-PDUs", "Invoke-linkedId")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: InvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *InvokeLinkedId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *InvokeLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

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
		if !(v.Present.Cmp(runtime.MustParseBigIntDecimal("-128")) >= 0 && v.Present.Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeSource(opts, "Remote-Operations-Generic-ROS-PDUs.Invoke-linkedId"), "present", "Q.773 §4.2.2.2: component-id-one-octet", ber.ObserveInteger(v.Present)); constraintErr != nil {
				return nil, constraintErr
			}
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
func (v *InvokeLinkedId) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

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
		return fmt.Errorf("nil InvokeLinkedId destination")
	}
	var next InvokeLinkedId

	v :=
		&next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "InvokeLinkedId", "Remote-Operations-Generic-ROS-PDUs", "Invoke-linkedId")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *InvokeLinkedId, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe InvokeLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.Invoke-linkedId", opts)
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
		if !(v.Present.Cmp(runtime.MustParseBigIntDecimal("-128")) >= 0 && v.Present.Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckDecodedValue(opts, "present", "Q.773 §4.2.2.2: component-id-one-octet", ber.ObserveInteger(v.Present)); constraintErr != nil {
				return constraintErr
			}
		}
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
		return fmt.Errorf("unknown tag %s for InvokeLinkedId CHOICE", peekTag)
	}
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr != nil {
		return ruleErr

	}

	return nil
}

// MarshalBER encodes ReturnResultResult to BER format.
func (v *ReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ReturnResultResult", "Remote-Operations-Generic-ROS-PDUs", "ReturnResult-result")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *ReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_opcode)
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := checkTCAPOpaqueReplay(

		enc_result, opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReturnResultResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.Opcode.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "opcode")...)
		if err != nil {
			return nil, qualifyBERError(err, "opcode", "encoding", true)
		}
	}
	enc_result := v.Result.Bytes
	if err := checkTCAPOpaqueReplay(

		enc_result, opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", true)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	encoder.Append(enc_result)
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes ReturnResultResult to DER format.
func (v *ReturnResultResult) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *ReturnResultResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	{
		_, err := v.Opcode.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "opcode", "encoding", true)
		}
	}
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	encoder.Append(enc_result)
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes ReturnResultResult from BER/DER format.
func (destination *ReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ReturnResultResult destination")
	}
	var next ReturnResultResult

	v := &next

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ReturnResultResult", "Remote-Operations-Generic-ROS-PDUs", "ReturnResult-result")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.ReturnResult-result", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReturnResultResult{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ReturnResultResult, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
		return fmt.Errorf("missing required field opcode")
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
		return fmt.Errorf("missing required field result")
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
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RejectProblemChoice to BER format.
func (v *RejectProblemChoice) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "RejectProblemChoice", "Remote-Operations-Generic-ROS-PDUs", "RejectProblemChoice")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: RejectProblemChoice receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *RejectProblemChoice) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *RejectProblemChoice) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case RejectProblemChoiceChoiceGeneral:
		if v.General == nil {
			return nil, fmt.Errorf("%w: choice RejectProblemChoice: general is nil", ber.ErrInvalidValue)
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
	case RejectProblemChoiceChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice RejectProblemChoice: invoke is nil", ber.ErrInvalidValue)
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
	case RejectProblemChoiceChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice RejectProblemChoice: returnResult is nil", ber.ErrInvalidValue)
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
	case RejectProblemChoiceChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice RejectProblemChoice: returnError is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for RejectProblemChoice", v.Choice)
	}
}

// MarshalDER encodes RejectProblemChoice to DER format.
func (v *RejectProblemChoice) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: RejectProblemChoice receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case RejectProblemChoiceChoiceGeneral:
			return nil, qualifyBERError(err, "general", "encoding", true)
		case RejectProblemChoiceChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case RejectProblemChoiceChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case RejectProblemChoiceChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding RejectProblemChoice as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *RejectProblemChoice) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RejectProblemChoice from BER/DER format.
func (destination *RejectProblemChoice) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil RejectProblemChoice destination")
	}
	var next RejectProblemChoice

	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "RejectProblemChoice", "Remote-Operations-Generic-ROS-PDUs", "RejectProblemChoice")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *RejectProblemChoice, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RejectProblemChoice
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Generic-ROS-PDUs.RejectProblemChoice", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RejectProblemChoice{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for RejectProblemChoice CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RejectProblemChoice: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding RejectProblemChoice CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RejectProblemChoice", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "RejectProblemChoice.general", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "RejectProblemChoice.invoke", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "RejectProblemChoice.returnResult", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "RejectProblemChoice.returnError", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = RejectProblemChoiceChoiceGeneral
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
		v.Choice = RejectProblemChoiceChoiceInvoke
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
		v.Choice = RejectProblemChoiceChoiceReturnResult
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
		v.Choice = RejectProblemChoiceChoiceReturnError
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
		return fmt.Errorf("unknown tag %s for RejectProblemChoice CHOICE", peekTag)
	}
	return nil
}
func (v *Bind) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil Bind CHOICE")
	}
	count := 0
	if v.BindInvoke != nil {
		count++
	}
	if v.BindResult != nil {
		count++
	}
	if v.BindError != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.BindInvoke == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.BindResult == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.BindError == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *InvokeId) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil InvokeId CHOICE")
	}
	count := 0
	if v.Present != nil {
		count++
	}
	if v.Absent != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Present == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.Absent == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *InvokeLinkedId) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil InvokeLinkedId CHOICE")
	}
	count := 0
	if v.Present != nil {
		count++
	}
	if v.Absent != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Present == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.Absent == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *ROS) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil ROS CHOICE")
	}
	count := 0
	if v.Invoke != nil {
		count++
	}
	if v.ReturnResult != nil {
		count++
	}
	if v.ReturnError != nil {
		count++
	}
	if v.Reject != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Invoke == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.ReturnResult == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.ReturnError == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 4:
		if v.Reject == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *RejectProblemChoice) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil RejectProblemChoice CHOICE")
	}
	count := 0
	if v.General != nil {
		count++
	}
	if v.Invoke != nil {
		count++
	}
	if v.ReturnResult != nil {
		count++
	}
	if v.ReturnError != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.General == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.Invoke == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.ReturnResult == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 4:
		if v.ReturnError == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *Unbind) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil Unbind CHOICE")
	}
	count := 0
	if v.UnbindInvoke != nil {
		count++
	}
	if v.UnbindResult != nil {
		count++
	}
	if v.UnbindError != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.UnbindInvoke == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.UnbindResult == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.UnbindError == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *Bind) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	return nil
}
func (v *Bind) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v Bind) equalTCAPValue(other any) bool {
	right, ok := other.(Bind)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.BindInvoke == nil) != (right.BindInvoke == nil) {
		return false
	}
	if v.BindInvoke != nil && !equalTCAPValue(*v.BindInvoke, *right.BindInvoke) {
		return false
	}
	if (v.BindResult == nil) != (right.BindResult == nil) {
		return false
	}
	if v.BindResult != nil && !equalTCAPValue(*v.BindResult, *right.BindResult) {
		return false
	}
	if (v.BindError == nil) != (right.BindError == nil) {
		return false
	}
	if v.BindError != nil && !equalTCAPValue(*v.BindError, *right.BindError) {
		return false
	}
	return true
}
func (v *GeneralProblem) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *GeneralProblem) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v GeneralProblem) equalTCAPValue(other any) bool {
	right, ok := other.(GeneralProblem)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *Invoke) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.InvokeId); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.LinkedId); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(&v.Opcode); err != nil {
		return err
	}
	return nil
}
func (v *Invoke) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.InvokeId) {
		return true
	}
	if hasTCAPPresenceEditValue(v.LinkedId) {
		return true
	}
	if hasTCAPPresenceEditValue(&v.Opcode) {
		return true
	}
	return false
}
func (v Invoke) equalTCAPValue(other any) bool {
	right, ok := other.(Invoke)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.InvokeId, right.InvokeId) {
		return false
	}
	if (v.LinkedId == nil) != (right.LinkedId == nil) {
		return false
	}
	if v.LinkedId != nil && !equalTCAPValue(*v.LinkedId, *right.LinkedId) {
		return false
	}
	if !equalTCAPValue(v.Opcode, right.Opcode) {
		return false
	}
	if (v.Argument == nil) != (right.Argument == nil) {
		return false
	}
	if v.Argument != nil && !equalTCAPValue(*v.Argument, *right.Argument) {
		return false
	}
	return true
}
func (v *InvokeId) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	return nil
}
func (v *InvokeId) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v InvokeId) equalTCAPValue(other any) bool {
	right, ok := other.(InvokeId)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Present == nil) != (right.Present == nil) {
		return false
	}
	if v.Present != nil && !equalTCAPValue(*v.Present, *right.Present) {
		return false
	}
	if (v.Absent == nil) != (right.Absent == nil) {
		return false
	}
	if v.Absent != nil && !equalTCAPValue(*v.Absent, *right.Absent) {
		return false
	}
	return true
}
func (v *InvokeLinkedId) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	return nil
}
func (v *InvokeLinkedId) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v InvokeLinkedId) equalTCAPValue(other any) bool {
	right, ok := other.(InvokeLinkedId)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Present == nil) != (right.Present == nil) {
		return false
	}
	if v.Present != nil && !equalTCAPValue(*v.Present, *right.Present) {
		return false
	}
	if (v.Absent == nil) != (right.Absent == nil) {
		return false
	}
	if v.Absent != nil && !equalTCAPValue(*v.Absent, *right.Absent) {
		return false
	}
	return true
}
func (v *InvokeProblem) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *InvokeProblem) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v InvokeProblem) equalTCAPValue(other any) bool {
	right, ok := other.(InvokeProblem)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *ROS) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Invoke); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnResult); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnError); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Reject); err != nil {
		return err
	}
	return nil
}
func (v *ROS) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.Invoke) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnResult) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnError) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Reject) {
		return true
	}
	return false
}
func (v ROS) equalTCAPValue(other any) bool {
	right, ok := other.(ROS)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Invoke == nil) != (right.Invoke == nil) {
		return false
	}
	if v.Invoke != nil && !equalTCAPValue(*v.Invoke, *right.Invoke) {
		return false
	}
	if (v.ReturnResult == nil) != (right.ReturnResult == nil) {
		return false
	}
	if v.ReturnResult != nil && !equalTCAPValue(*v.ReturnResult, *right.ReturnResult) {
		return false
	}
	if (v.ReturnError == nil) != (right.ReturnError == nil) {
		return false
	}
	if v.ReturnError != nil && !equalTCAPValue(*v.ReturnError, *right.ReturnError) {
		return false
	}
	if (v.Reject == nil) != (right.Reject == nil) {
		return false
	}
	if v.Reject != nil && !equalTCAPValue(*v.Reject, *right.Reject) {
		return false
	}
	return true
}
func (v *Reject) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.InvokeId); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(&v.Problem); err != nil {
		return err
	}
	return nil
}
func (v *Reject) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.InvokeId) {
		return true
	}
	if hasTCAPPresenceEditValue(&v.Problem) {
		return true
	}
	return false
}
func (v Reject) equalTCAPValue(other any) bool {
	right, ok := other.(Reject)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.InvokeId, right.InvokeId) {
		return false
	}
	if !equalTCAPValue(v.Problem, right.Problem) {
		return false
	}
	return true
}
func (v *RejectProblem) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *RejectProblem) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v RejectProblem) equalTCAPValue(other any) bool {
	right, ok := other.(RejectProblem)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *RejectProblemChoice) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.General); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Invoke); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnResult); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnError); err != nil {
		return err
	}
	return nil
}
func (v *RejectProblemChoice) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.General) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Invoke) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnResult) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnError) {
		return true
	}
	return false
}
func (v RejectProblemChoice) equalTCAPValue(other any) bool {
	right, ok := other.(RejectProblemChoice)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.General == nil) != (right.General == nil) {
		return false
	}
	if v.General != nil && !equalTCAPValue(*v.General, *right.General) {
		return false
	}
	if (v.Invoke == nil) != (right.Invoke == nil) {
		return false
	}
	if v.Invoke != nil && !equalTCAPValue(*v.Invoke, *right.Invoke) {
		return false
	}
	if (v.ReturnResult == nil) != (right.ReturnResult == nil) {
		return false
	}
	if v.ReturnResult != nil && !equalTCAPValue(*v.ReturnResult, *right.ReturnResult) {
		return false
	}
	if (v.ReturnError == nil) != (right.ReturnError == nil) {
		return false
	}
	if v.ReturnError != nil && !equalTCAPValue(*v.ReturnError, *right.ReturnError) {
		return false
	}
	return true
}
func (v *ReturnError) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.InvokeId); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(&v.Errcode); err != nil {
		return err
	}
	return nil
}
func (v *ReturnError) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.InvokeId) {
		return true
	}
	if hasTCAPPresenceEditValue(&v.Errcode) {
		return true
	}
	return false
}
func (v ReturnError) equalTCAPValue(other any) bool {
	right, ok := other.(ReturnError)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.InvokeId, right.InvokeId) {
		return false
	}
	if !equalTCAPValue(v.Errcode, right.Errcode) {
		return false
	}
	if (v.Parameter == nil) != (right.Parameter == nil) {
		return false
	}
	if v.Parameter != nil && !equalTCAPValue(*v.Parameter, *right.Parameter) {
		return false
	}
	return true
}
func (v *ReturnErrorProblem) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *ReturnErrorProblem) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v ReturnErrorProblem) equalTCAPValue(other any) bool {
	right, ok := other.(ReturnErrorProblem)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *ReturnResult) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.InvokeId); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Result); err != nil {
		return err
	}
	return nil
}
func (v *ReturnResult) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.InvokeId) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Result) {
		return true
	}
	return false
}
func (v ReturnResult) equalTCAPValue(other any) bool {
	right, ok := other.(ReturnResult)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.InvokeId, right.InvokeId) {
		return false
	}
	if (v.Result == nil) != (right.Result == nil) {
		return false
	}
	if v.Result != nil && !equalTCAPValue(*v.Result, *right.Result) {
		return false
	}
	return true
}
func (v *ReturnResultProblem) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *ReturnResultProblem) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v ReturnResultProblem) equalTCAPValue(other any) bool {
	right, ok := other.(ReturnResultProblem)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *ReturnResultResult) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.Opcode); err != nil {
		return err
	}
	return nil
}
func (v *ReturnResultResult) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.Opcode) {
		return true
	}
	return false
}
func (v ReturnResultResult) equalTCAPValue(other any) bool {
	right, ok := other.(ReturnResultResult)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Opcode, right.Opcode) {
		return false
	}
	if !equalTCAPValue(v.Result, right.Result) {
		return false
	}
	return true
}
func (v *Unbind) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	return nil
}
func (v *Unbind) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v Unbind) equalTCAPValue(other any) bool {
	right, ok := other.(Unbind)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.UnbindInvoke == nil) != (right.UnbindInvoke == nil) {
		return false
	}
	if v.UnbindInvoke != nil && !equalTCAPValue(*v.UnbindInvoke, *right.UnbindInvoke) {
		return false
	}
	if (v.UnbindResult == nil) != (right.UnbindResult == nil) {
		return false
	}
	if v.UnbindResult != nil && !equalTCAPValue(*v.UnbindResult, *right.UnbindResult) {
		return false
	}
	if (v.UnbindError == nil) != (right.UnbindError == nil) {
		return false
	}
	if v.UnbindError != nil && !equalTCAPValue(*v.UnbindError, *right.UnbindError) {
		return false
	}
	return true
}
