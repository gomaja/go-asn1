// Code generated from ASN.1 module "Remote-Operations-Generic-ROS-PDUs". DO NOT EDIT.

package tcap

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
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
	Choice       int
	Invoke       *Invoke       `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError  `json:"ReturnError,omitempty"`
	Reject       *Reject       `json:"Reject,omitempty"`
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
	InvokeId InvokeId          `asn1:""`
	LinkedId *InvokeLinkedId   `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode   Code              `asn1:""`
	Argument *runtime.RawValue `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
}

// ReturnResult represents the ASN.1 type ReturnResult (SEQUENCE).
type ReturnResult struct {
	InvokeId InvokeId            `asn1:""`
	Result   *ReturnResultResult `asn1:",optional" json:"Result,omitempty"`
}

// ReturnError represents the ASN.1 type ReturnError (SEQUENCE).
type ReturnError struct {
	InvokeId  InvokeId          `asn1:""`
	Errcode   Code              `asn1:""`
	Parameter *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty" asn1c:"raw-preserve"`
}

// Reject represents the ASN.1 type Reject (SEQUENCE).
type Reject struct {
	InvokeId InvokeId                `asn1:""`
	Problem  OperationsRejectProblem `asn1:""`
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
	Choice  int
	Present *big.Int  `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Choice     int
	BindInvoke *runtime.RawValue `json:"BindInvoke,omitempty" asn1c:"raw-preserve"`
	BindResult *runtime.RawValue `json:"BindResult,omitempty" asn1c:"raw-preserve"`
	BindError  *runtime.RawValue `json:"BindError,omitempty" asn1c:"raw-preserve"`
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
	Choice       int
	UnbindInvoke *runtime.RawValue `json:"UnbindInvoke,omitempty" asn1c:"raw-preserve"`
	UnbindResult *runtime.RawValue `json:"UnbindResult,omitempty" asn1c:"raw-preserve"`
	UnbindError  *runtime.RawValue `json:"UnbindError,omitempty" asn1c:"raw-preserve"`
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
	Choice  int
	Present *big.Int  `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Opcode Code             `asn1:""`
	Result runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
}

// InvokeLinkedId choice constants.
const (
	InvokeLinkedIdChoicePresent = 1
	InvokeLinkedIdChoiceAbsent  = 2
)

// InvokeLinkedId represents the ASN.1 CHOICE type Invoke-linkedId.
type InvokeLinkedId struct {
	Choice  int
	Present *big.Int  `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Opcode Code             `asn1:""`
	Result runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
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
	Choice       int
	General      *GeneralProblem      `json:"General,omitempty"`
	Invoke       *InvokeProblem       `json:"Invoke,omitempty"`
	ReturnResult *ReturnResultProblem `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnErrorProblem  `json:"ReturnError,omitempty"`
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
func (v *ROS) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROS: invoke is nil")
		}
		enc_0, err := v.Invoke.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROS: returnResult is nil")
		}
		enc_1, err := v.ReturnResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ROSChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROS: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ROSChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROS: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROS", v.Choice)
	}
}

// MarshalDER encodes ROS to DER format.
func (v *ROS) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ROSChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROS: invoke is nil")
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding invoke as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ROSChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROS: returnResult is nil")
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding returnResult as DER: %w", derErr)
		}
		return enc_der_1, nil
	case ROSChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROS: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDERElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding returnError as DER: %w", derErr)
		}
		return enc_der_2, nil
	case ROSChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROS: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDERElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding reject as DER: %w", derErr)
		}
		return enc_der_3, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROS as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROS from BER/DER format.
func (v *ROS) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROS CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROS", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding invoke: %w", unmErr)
		}
		v.Invoke = &dec
		if v.Invoke.LinkedId != nil {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSChoiceReturnResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResult: %w", unmErr)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnError: %w", unmErr)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSChoiceReject
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding reject: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding reject: %w", unmErr)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ROS CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Invoke to BER format.
func (v *Invoke) MarshalBER() ([]byte, error) {
	if v.LinkedId != nil {
		return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding invokeId: %w", err)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding linkedId: %w", err)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Invoke to DER format.
func (v *Invoke) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Invoke as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Invoke from BER/DER format.
func (v *Invoke) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Invoke SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Invoke", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	// Decode nested CHOICE (InvokeId)
	_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:])
	if tlvErr_invokeid != nil {
		return fmt.Errorf("decoding invokeId: %w", tlvErr_invokeid)
	}
	if unmErr := v.InvokeId.UnmarshalBER(content[offset : offset+n_invokeid]); unmErr != nil {
		return fmt.Errorf("decoding invokeId: %w", unmErr)
	}
	offset += n_invokeid
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				// Decode nested CHOICE (InvokeLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:])
				if tlvErr_linkedid != nil {
					return fmt.Errorf("decoding linkedId: %w", tlvErr_linkedid)
				}
				var dec_linkedid InvokeLinkedId
				if unmErr := dec_linkedid.UnmarshalBER(content[offset : offset+n_linkedid]); unmErr != nil {
					return fmt.Errorf("decoding linkedId: %w", unmErr)
				}
				v.LinkedId = &dec_linkedid
				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	// Decode nested CHOICE (Code)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opcode: %w", tlvErr_opcode)
	}
	if unmErr := v.Opcode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opcode: %w", unmErr)
	}
	offset += n_opcode
	// Decode argument
	if offset < len(content) {
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:])
		if tlvErr_argument != nil {
			return fmt.Errorf("decoding argument: %w", tlvErr_argument)
		}
		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Invoke", Cause: ber.ErrExtraData}
	}
	if v.LinkedId != nil {
		return fmt.Errorf("decoded Invoke violates WITH COMPONENTS: LinkedId must be absent")
	}
	return nil
}

// MarshalBER encodes ReturnResult to BER format.
func (v *ReturnResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding invokeId: %w", err)
	}
	children = append(children, enc_invokeid...)
	if v.Result != nil {
		enc_result, err := v.Result.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding result: %w", err)
		}
		children = append(children, enc_result...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ReturnResult to DER format.
func (v *ReturnResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReturnResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReturnResult from BER/DER format.
func (v *ReturnResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	// Decode nested CHOICE (InvokeId)
	_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:])
	if tlvErr_invokeid != nil {
		return fmt.Errorf("decoding invokeId: %w", tlvErr_invokeid)
	}
	if unmErr := v.InvokeId.UnmarshalBER(content[offset : offset+n_invokeid]); unmErr != nil {
		return fmt.Errorf("decoding invokeId: %w", unmErr)
	}
	offset += n_invokeid
	// Decode result
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ReturnResultResult)
				_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:])
				if tlvErr_result != nil {
					return fmt.Errorf("decoding result: %w", tlvErr_result)
				}
				var dec_result ReturnResultResult
				if unmErr := dec_result.UnmarshalBER(content[offset : offset+n_result]); unmErr != nil {
					return fmt.Errorf("decoding result: %w", unmErr)
				}
				v.Result = &dec_result
				offset += n_result
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ReturnError to BER format.
func (v *ReturnError) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding invokeId: %w", err)
	}
	children = append(children, enc_invokeid...)
	enc_errcode, err := v.Errcode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding errcode: %w", err)
	}
	children = append(children, enc_errcode...)
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		children = append(children, enc_parameter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ReturnError to DER format.
func (v *ReturnError) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReturnError as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReturnError from BER/DER format.
func (v *ReturnError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	// Decode nested CHOICE (InvokeId)
	_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:])
	if tlvErr_invokeid != nil {
		return fmt.Errorf("decoding invokeId: %w", tlvErr_invokeid)
	}
	if unmErr := v.InvokeId.UnmarshalBER(content[offset : offset+n_invokeid]); unmErr != nil {
		return fmt.Errorf("decoding invokeId: %w", unmErr)
	}
	offset += n_invokeid
	// Decode errcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field errcode")
	}
	// Decode nested CHOICE (Code)
	_, n_errcode, _, tlvErr_errcode := ber.DecodeTLV(content[offset:])
	if tlvErr_errcode != nil {
		return fmt.Errorf("decoding errcode: %w", tlvErr_errcode)
	}
	if unmErr := v.Errcode.UnmarshalBER(content[offset : offset+n_errcode]); unmErr != nil {
		return fmt.Errorf("decoding errcode: %w", unmErr)
	}
	offset += n_errcode
	// Decode parameter
	if offset < len(content) {
		_, n_parameter, _, tlvErr_parameter := ber.DecodeTLV(content[offset:])
		if tlvErr_parameter != nil {
			return fmt.Errorf("decoding parameter: %w", tlvErr_parameter)
		}
		tmp_parameter := runtime.RawValue{Bytes: content[offset : offset+n_parameter]}
		v.Parameter = &tmp_parameter
		offset += n_parameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnError", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Reject to BER format.
func (v *Reject) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding invokeId: %w", err)
	}
	children = append(children, enc_invokeid...)
	enc_problem, err := v.Problem.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding problem: %w", err)
	}
	children = append(children, enc_problem...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Reject to DER format.
func (v *Reject) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Reject as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Reject from BER/DER format.
func (v *Reject) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Reject SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Reject", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	// Decode nested CHOICE (InvokeId)
	_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:])
	if tlvErr_invokeid != nil {
		return fmt.Errorf("decoding invokeId: %w", tlvErr_invokeid)
	}
	if unmErr := v.InvokeId.UnmarshalBER(content[offset : offset+n_invokeid]); unmErr != nil {
		return fmt.Errorf("decoding invokeId: %w", unmErr)
	}
	offset += n_invokeid
	// Decode problem
	if offset >= len(content) {
		return fmt.Errorf("missing required field problem")
	}
	// Decode nested CHOICE (OperationsRejectProblem)
	_, n_problem, _, tlvErr_problem := ber.DecodeTLV(content[offset:])
	if tlvErr_problem != nil {
		return fmt.Errorf("decoding problem: %w", tlvErr_problem)
	}
	if unmErr := v.Problem.UnmarshalBER(content[offset : offset+n_problem]); unmErr != nil {
		return fmt.Errorf("decoding problem: %w", unmErr)
	}
	offset += n_problem
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Reject", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes InvokeId to BER format.
func (v *InvokeId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case InvokeIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("choice InvokeId: present is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Present)
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding InvokeId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InvokeId from BER/DER format.
func (v *InvokeId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for InvokeId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InvokeId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding InvokeId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InvokeId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = InvokeIdChoicePresent
		decVal, _, intErr := ber.DecodeBigInt(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding present: %w", intErr)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = InvokeIdChoiceAbsent
		_, nullErr := ber.DecodeNull(choiceData)
		if nullErr != nil {
			return fmt.Errorf("decoding absent: %w", nullErr)
		}
	} else {
		return fmt.Errorf("unknown tag %s for InvokeId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Bind to BER format.
func (v *Bind) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case BindChoiceBindInvoke:
		if v.BindInvoke == nil {
			return nil, fmt.Errorf("choice Bind: bind-invoke is nil")
		}
		enc_0 := v.BindInvoke.Bytes
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding bind-invoke: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BindChoiceBindResult:
		if v.BindResult == nil {
			return nil, fmt.Errorf("choice Bind: bind-result is nil")
		}
		enc_1 := v.BindResult.Bytes
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding bind-result: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case BindChoiceBindError:
		if v.BindError == nil {
			return nil, fmt.Errorf("choice Bind: bind-error is nil")
		}
		enc_2 := v.BindError.Bytes
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding bind-error: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Bind", v.Choice)
	}
}

// MarshalDER encodes Bind to DER format.
func (v *Bind) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Bind as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Bind from BER/DER format.
func (v *Bind) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Bind CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Bind: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Bind CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Bind", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
		v.Choice = BindChoiceBindInvoke
		tmpRaw := runtime.RawValue{Bytes: choiceData}
		v.BindInvoke = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
		v.Choice = BindChoiceBindResult
		tmpRaw := runtime.RawValue{Bytes: choiceData}
		v.BindResult = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
		v.Choice = BindChoiceBindError
		tmpRaw := runtime.RawValue{Bytes: choiceData}
		v.BindError = &tmpRaw
	} else {
		return fmt.Errorf("unknown tag %s for Bind CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Unbind to BER format.
func (v *Unbind) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case UnbindChoiceUnbindInvoke:
		if v.UnbindInvoke == nil {
			return nil, fmt.Errorf("choice Unbind: unbind-invoke is nil")
		}
		enc_0 := v.UnbindInvoke.Bytes
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding unbind-invoke: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case UnbindChoiceUnbindResult:
		if v.UnbindResult == nil {
			return nil, fmt.Errorf("choice Unbind: unbind-result is nil")
		}
		enc_1 := v.UnbindResult.Bytes
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding unbind-result: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case UnbindChoiceUnbindError:
		if v.UnbindError == nil {
			return nil, fmt.Errorf("choice Unbind: unbind-error is nil")
		}
		enc_2 := v.UnbindError.Bytes
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding unbind-error: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Unbind", v.Choice)
	}
}

// MarshalDER encodes Unbind to DER format.
func (v *Unbind) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Unbind as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Unbind from BER/DER format.
func (v *Unbind) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Unbind CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Unbind: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Unbind CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Unbind", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
		v.Choice = UnbindChoiceUnbindInvoke
		tmpRaw := runtime.RawValue{Bytes: choiceData}
		v.UnbindInvoke = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
		v.Choice = UnbindChoiceUnbindResult
		tmpRaw := runtime.RawValue{Bytes: choiceData}
		v.UnbindResult = &tmpRaw
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
		v.Choice = UnbindChoiceUnbindError
		tmpRaw := runtime.RawValue{Bytes: choiceData}
		v.UnbindError = &tmpRaw
	} else {
		return fmt.Errorf("unknown tag %s for Unbind CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSInvokeLinkedId to BER format.
func (v *ROSInvokeLinkedId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("choice ROSInvokeLinkedId: present is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Present)
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding present: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding absent: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSInvokeLinkedId to DER format.
func (v *ROSInvokeLinkedId) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSInvokeLinkedId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSInvokeLinkedId from BER/DER format.
func (v *ROSInvokeLinkedId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROSInvokeLinkedId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSInvokeLinkedIdChoicePresent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding present: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding present: %w", intErr)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ROSInvokeLinkedIdChoiceAbsent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding absent: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding absent: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ROSInvokeLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSReturnResultResult to BER format.
func (v *ROSReturnResultResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ROSReturnResultResult to DER format.
func (v *ROSReturnResultResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSReturnResultResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSReturnResultResult from BER/DER format.
func (v *ROSReturnResultResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ROSReturnResultResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	// Decode nested CHOICE (Code)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opcode: %w", tlvErr_opcode)
	}
	if unmErr := v.Opcode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opcode: %w", unmErr)
	}
	offset += n_opcode
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:])
	if tlvErr_result != nil {
		return fmt.Errorf("decoding result: %w", tlvErr_result)
	}
	v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
	offset += n_result
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ROSReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes InvokeLinkedId to BER format.
func (v *InvokeLinkedId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case InvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("choice InvokeLinkedId: present is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Present)
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding present: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case InvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding absent: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes InvokeLinkedId to DER format.
func (v *InvokeLinkedId) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding InvokeLinkedId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InvokeLinkedId from BER/DER format.
func (v *InvokeLinkedId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for InvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding InvokeLinkedId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = InvokeLinkedIdChoicePresent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding present: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding present: %w", intErr)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = InvokeLinkedIdChoiceAbsent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding absent: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding absent: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for InvokeLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ReturnResultResult to BER format.
func (v *ReturnResultResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ReturnResultResult to DER format.
func (v *ReturnResultResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReturnResultResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReturnResultResult from BER/DER format.
func (v *ReturnResultResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnResultResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	// Decode nested CHOICE (Code)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opcode: %w", tlvErr_opcode)
	}
	if unmErr := v.Opcode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opcode: %w", unmErr)
	}
	offset += n_opcode
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:])
	if tlvErr_result != nil {
		return fmt.Errorf("decoding result: %w", tlvErr_result)
	}
	v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
	offset += n_result
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes OperationsRejectProblem to BER format.
func (v *OperationsRejectProblem) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case OperationsRejectProblemChoiceGeneral:
		if v.General == nil {
			return nil, fmt.Errorf("choice OperationsRejectProblem: general is nil")
		}
		enc_0 := ber.EncodeBigInt(v.General.BigInt())
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding general: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case OperationsRejectProblemChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice OperationsRejectProblem: invoke is nil")
		}
		enc_1 := ber.EncodeBigInt(v.Invoke.BigInt())
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case OperationsRejectProblemChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice OperationsRejectProblem: returnResult is nil")
		}
		enc_2 := ber.EncodeBigInt(v.ReturnResult.BigInt())
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case OperationsRejectProblemChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice OperationsRejectProblem: returnError is nil")
		}
		enc_3 := ber.EncodeBigInt(v.ReturnError.BigInt())
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for OperationsRejectProblem", v.Choice)
	}
}

// MarshalDER encodes OperationsRejectProblem to DER format.
func (v *OperationsRejectProblem) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OperationsRejectProblem as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OperationsRejectProblem from BER/DER format.
func (v *OperationsRejectProblem) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for OperationsRejectProblem CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for OperationsRejectProblem: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding OperationsRejectProblem CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "OperationsRejectProblem", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceGeneral
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding general: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding general: %w", intErr)
		}
		var named_general GeneralProblem
		if namedErr := named_general.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding general: %w", namedErr)
		}
		v.General = &named_general
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding invoke: %w", intErr)
		}
		var named_invoke InvokeProblem
		if namedErr := named_invoke.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding invoke: %w", namedErr)
		}
		v.Invoke = &named_invoke
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceReturnResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResult: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnResult: %w", intErr)
		}
		var named_returnresult ReturnResultProblem
		if namedErr := named_returnresult.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding returnResult: %w", namedErr)
		}
		v.ReturnResult = &named_returnresult
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == false {
		v.Choice = OperationsRejectProblemChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnError: %w", intErr)
		}
		var named_returnerror ReturnErrorProblem
		if namedErr := named_returnerror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding returnError: %w", namedErr)
		}
		v.ReturnError = &named_returnerror
	} else {
		return fmt.Errorf("unknown tag %s for OperationsRejectProblem CHOICE", peekTag)
	}
	return nil
}
