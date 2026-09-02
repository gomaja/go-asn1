// Code generated from ASN.1 module "DialoguePDUs". DO NOT EDIT.

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

// DialogueAsId returns the OID value for dialogue-as-id.
func DialogueAsId() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{0, 0, 17, 773, 1, 1, 1} }

// DialoguePDU choice constants.
const (
	DialoguePDUChoiceDialogueRequest  = 1
	DialoguePDUChoiceDialogueResponse = 2
	DialoguePDUChoiceDialogueAbort    = 3
)

// DialoguePDU represents the ASN.1 CHOICE type DialoguePDU.
type DialoguePDU struct {
	Choice           int
	DialogueRequest  *AARQApdu `json:"DialogueRequest,omitempty"`
	DialogueResponse *AAREApdu `json:"DialogueResponse,omitempty"`
	DialogueAbort    *ABRTApdu `json:"DialogueAbort,omitempty"`
}

// NewDialoguePDUDialogueRequest creates a DialoguePDU with the dialogueRequest alternative.
func NewDialoguePDUDialogueRequest(v AARQApdu) DialoguePDU {
	return DialoguePDU{
		Choice:          DialoguePDUChoiceDialogueRequest,
		DialogueRequest: &v,
	}
}

// NewDialoguePDUDialogueResponse creates a DialoguePDU with the dialogueResponse alternative.
func NewDialoguePDUDialogueResponse(v AAREApdu) DialoguePDU {
	return DialoguePDU{
		Choice:           DialoguePDUChoiceDialogueResponse,
		DialogueResponse: &v,
	}
}

// NewDialoguePDUDialogueAbort creates a DialoguePDU with the dialogueAbort alternative.
func NewDialoguePDUDialogueAbort(v ABRTApdu) DialoguePDU {
	return DialoguePDU{
		Choice:        DialoguePDUChoiceDialogueAbort,
		DialogueAbort: &v,
	}
}

// AARQApdu represents the ASN.1 type AARQ-apdu (SEQUENCE).
type AARQApdu struct {
	ProtocolVersion        *runtime.BitString       `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName runtime.ObjectIdentifier `asn1:"tag:1,context,explicit"`
	UserInformation        AARQApduUserInformation  `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_  bool                     `asn1:"-" json:"-"`
}

// AAREApdu represents the ASN.1 type AARE-apdu (SEQUENCE).
type AAREApdu struct {
	ProtocolVersion        *runtime.BitString        `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName runtime.ObjectIdentifier  `asn1:"tag:1,context,explicit"`
	Result                 AssociateResult           `asn1:"tag:2,context,explicit"`
	ResultSourceDiagnostic AssociateSourceDiagnostic `asn1:"tag:3,context,explicit"`
	UserInformation        AAREApduUserInformation   `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_  bool                      `asn1:"-" json:"-"`
}

// RLRQApdu represents the ASN.1 type RLRQ-apdu (SEQUENCE).
type RLRQApdu struct {
	Reason                *ReleaseRequestReason   `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation       RLRQApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                    `asn1:"-" json:"-"`
}

// RLREApdu represents the ASN.1 type RLRE-apdu (SEQUENCE).
type RLREApdu struct {
	Reason                *ReleaseResponseReason  `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation       RLREApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                    `asn1:"-" json:"-"`
}

// ABRTApdu represents the ASN.1 type ABRT-apdu (SEQUENCE).
type ABRTApdu struct {
	AbortSource           ABRTSource              `asn1:"tag:0,context,implicit"`
	UserInformation       ABRTApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                    `asn1:"-" json:"-"`
}

// ABRTSource represents the arbitrary-width ASN.1 INTEGER type ABRT-source with named numbers.
type ABRTSource struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ABRTSourceDialogueServiceUserDecimal     = "0"
	ABRTSourceDialogueServiceUser            = 0
	ABRTSourceDialogueServiceProviderDecimal = "1"
	ABRTSourceDialogueServiceProvider        = 1
)

// NewABRTSource returns an immutable ABRTSource containing value.
func NewABRTSource(value *big.Int) ABRTSource {
	return ABRTSource{value: runtime.CloneBigInt(value)}
}

// NewABRTSourceInt64 returns a ABRTSource containing value.
func NewABRTSourceInt64(value int64) ABRTSource {
	return NewABRTSource(big.NewInt(value))
}

// ABRTSourceDialogueServiceUserValue returns the named value dialogue-service-user.
func ABRTSourceDialogueServiceUserValue() ABRTSource {
	return NewABRTSource(runtime.MustParseBigIntDecimal(ABRTSourceDialogueServiceUserDecimal))
}

// ABRTSourceDialogueServiceProviderValue returns the named value dialogue-service-provider.
func ABRTSourceDialogueServiceProviderValue() ABRTSource {
	return NewABRTSource(runtime.MustParseBigIntDecimal(ABRTSourceDialogueServiceProviderDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ABRTSource) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ABRTSource) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ABRTSource) Name() (string, bool) {
	switch v.BigInt().String() {
	case ABRTSourceDialogueServiceUserDecimal:
		return "dialogue-service-user", true
	case ABRTSourceDialogueServiceProviderDecimal:
		return "dialogue-service-provider", true
	default:
		return "", false
	}
}

func (v ABRTSource) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ABRTSource) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ABRTSource) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ABRTSource into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewABRTSource(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ABRTSource) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ABRTSource) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ABRTSource into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewABRTSource(value)
	return nil
}

// AssociateResult represents the arbitrary-width ASN.1 INTEGER type Associate-result with named numbers.
type AssociateResult struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	AssociateResultAcceptedDecimal        = "0"
	AssociateResultAccepted               = 0
	AssociateResultRejectPermanentDecimal = "1"
	AssociateResultRejectPermanent        = 1
)

// NewAssociateResult returns an immutable AssociateResult containing value.
func NewAssociateResult(value *big.Int) AssociateResult {
	return AssociateResult{value: runtime.CloneBigInt(value)}
}

// NewAssociateResultInt64 returns a AssociateResult containing value.
func NewAssociateResultInt64(value int64) AssociateResult {
	return NewAssociateResult(big.NewInt(value))
}

// AssociateResultAcceptedValue returns the named value accepted.
func AssociateResultAcceptedValue() AssociateResult {
	return NewAssociateResult(runtime.MustParseBigIntDecimal(AssociateResultAcceptedDecimal))
}

// AssociateResultRejectPermanentValue returns the named value reject-permanent.
func AssociateResultRejectPermanentValue() AssociateResult {
	return NewAssociateResult(runtime.MustParseBigIntDecimal(AssociateResultRejectPermanentDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v AssociateResult) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v AssociateResult) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v AssociateResult) Name() (string, bool) {
	switch v.BigInt().String() {
	case AssociateResultAcceptedDecimal:
		return "accepted", true
	case AssociateResultRejectPermanentDecimal:
		return "reject-permanent", true
	default:
		return "", false
	}
}

func (v AssociateResult) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v AssociateResult) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *AssociateResult) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AssociateResult into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewAssociateResult(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v AssociateResult) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *AssociateResult) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AssociateResult into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewAssociateResult(value)
	return nil
}

// AssociateSourceDiagnostic choice constants.
const (
	AssociateSourceDiagnosticChoiceDialogueServiceUser     = 1
	AssociateSourceDiagnosticChoiceDialogueServiceProvider = 2
)

// AssociateSourceDiagnostic represents the ASN.1 CHOICE type Associate-source-diagnostic.
type AssociateSourceDiagnostic struct {
	Choice                  int
	DialogueServiceUser     *AssociateSourceDiagnosticDialogueServiceUserValue     `json:"DialogueServiceUser,omitempty"`
	DialogueServiceProvider *AssociateSourceDiagnosticDialogueServiceProviderValue `json:"DialogueServiceProvider,omitempty"`
}

// NewAssociateSourceDiagnosticDialogueServiceUser creates a AssociateSourceDiagnostic with the dialogue-service-user alternative.
func NewAssociateSourceDiagnosticDialogueServiceUser(v AssociateSourceDiagnosticDialogueServiceUserValue) AssociateSourceDiagnostic {
	return AssociateSourceDiagnostic{
		Choice:              AssociateSourceDiagnosticChoiceDialogueServiceUser,
		DialogueServiceUser: &v,
	}
}

// NewAssociateSourceDiagnosticDialogueServiceProvider creates a AssociateSourceDiagnostic with the dialogue-service-provider alternative.
func NewAssociateSourceDiagnosticDialogueServiceProvider(v AssociateSourceDiagnosticDialogueServiceProviderValue) AssociateSourceDiagnostic {
	return AssociateSourceDiagnostic{
		Choice:                  AssociateSourceDiagnosticChoiceDialogueServiceProvider,
		DialogueServiceProvider: &v,
	}
}

// ReleaseRequestReason represents the arbitrary-width ASN.1 INTEGER type Release-request-reason with named numbers.
type ReleaseRequestReason struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ReleaseRequestReasonNormalDecimal      = "0"
	ReleaseRequestReasonNormal             = 0
	ReleaseRequestReasonUrgentDecimal      = "1"
	ReleaseRequestReasonUrgent             = 1
	ReleaseRequestReasonUserDefinedDecimal = "30"
	ReleaseRequestReasonUserDefined        = 30
)

// NewReleaseRequestReason returns an immutable ReleaseRequestReason containing value.
func NewReleaseRequestReason(value *big.Int) ReleaseRequestReason {
	return ReleaseRequestReason{value: runtime.CloneBigInt(value)}
}

// NewReleaseRequestReasonInt64 returns a ReleaseRequestReason containing value.
func NewReleaseRequestReasonInt64(value int64) ReleaseRequestReason {
	return NewReleaseRequestReason(big.NewInt(value))
}

// ReleaseRequestReasonNormalValue returns the named value normal.
func ReleaseRequestReasonNormalValue() ReleaseRequestReason {
	return NewReleaseRequestReason(runtime.MustParseBigIntDecimal(ReleaseRequestReasonNormalDecimal))
}

// ReleaseRequestReasonUrgentValue returns the named value urgent.
func ReleaseRequestReasonUrgentValue() ReleaseRequestReason {
	return NewReleaseRequestReason(runtime.MustParseBigIntDecimal(ReleaseRequestReasonUrgentDecimal))
}

// ReleaseRequestReasonUserDefinedValue returns the named value user-defined.
func ReleaseRequestReasonUserDefinedValue() ReleaseRequestReason {
	return NewReleaseRequestReason(runtime.MustParseBigIntDecimal(ReleaseRequestReasonUserDefinedDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ReleaseRequestReason) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ReleaseRequestReason) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ReleaseRequestReason) Name() (string, bool) {
	switch v.BigInt().String() {
	case ReleaseRequestReasonNormalDecimal:
		return "normal", true
	case ReleaseRequestReasonUrgentDecimal:
		return "urgent", true
	case ReleaseRequestReasonUserDefinedDecimal:
		return "user-defined", true
	default:
		return "", false
	}
}

func (v ReleaseRequestReason) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ReleaseRequestReason) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ReleaseRequestReason) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReleaseRequestReason into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewReleaseRequestReason(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ReleaseRequestReason) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ReleaseRequestReason) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReleaseRequestReason into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewReleaseRequestReason(value)
	return nil
}

// ReleaseResponseReason represents the arbitrary-width ASN.1 INTEGER type Release-response-reason with named numbers.
type ReleaseResponseReason struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ReleaseResponseReasonNormalDecimal      = "0"
	ReleaseResponseReasonNormal             = 0
	ReleaseResponseReasonNotFinishedDecimal = "1"
	ReleaseResponseReasonNotFinished        = 1
	ReleaseResponseReasonUserDefinedDecimal = "30"
	ReleaseResponseReasonUserDefined        = 30
)

// NewReleaseResponseReason returns an immutable ReleaseResponseReason containing value.
func NewReleaseResponseReason(value *big.Int) ReleaseResponseReason {
	return ReleaseResponseReason{value: runtime.CloneBigInt(value)}
}

// NewReleaseResponseReasonInt64 returns a ReleaseResponseReason containing value.
func NewReleaseResponseReasonInt64(value int64) ReleaseResponseReason {
	return NewReleaseResponseReason(big.NewInt(value))
}

// ReleaseResponseReasonNormalValue returns the named value normal.
func ReleaseResponseReasonNormalValue() ReleaseResponseReason {
	return NewReleaseResponseReason(runtime.MustParseBigIntDecimal(ReleaseResponseReasonNormalDecimal))
}

// ReleaseResponseReasonNotFinishedValue returns the named value not-finished.
func ReleaseResponseReasonNotFinishedValue() ReleaseResponseReason {
	return NewReleaseResponseReason(runtime.MustParseBigIntDecimal(ReleaseResponseReasonNotFinishedDecimal))
}

// ReleaseResponseReasonUserDefinedValue returns the named value user-defined.
func ReleaseResponseReasonUserDefinedValue() ReleaseResponseReason {
	return NewReleaseResponseReason(runtime.MustParseBigIntDecimal(ReleaseResponseReasonUserDefinedDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ReleaseResponseReason) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ReleaseResponseReason) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ReleaseResponseReason) Name() (string, bool) {
	switch v.BigInt().String() {
	case ReleaseResponseReasonNormalDecimal:
		return "normal", true
	case ReleaseResponseReasonNotFinishedDecimal:
		return "not-finished", true
	case ReleaseResponseReasonUserDefinedDecimal:
		return "user-defined", true
	default:
		return "", false
	}
}

func (v ReleaseResponseReason) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ReleaseResponseReason) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ReleaseResponseReason) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReleaseResponseReason into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewReleaseResponseReason(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ReleaseResponseReason) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ReleaseResponseReason) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ReleaseResponseReason into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewReleaseResponseReason(value)
	return nil
}

// asn1c:raw-preserve
// AARQApduUserInformation represents the ASN.1 type AARQ-apdu-user-information (SEQUENCE_OF).
type AARQApduUserInformation = []runtime.RawValue

// asn1c:raw-preserve
// AAREApduUserInformation represents the ASN.1 type AARE-apdu-user-information (SEQUENCE_OF).
type AAREApduUserInformation = []runtime.RawValue

// asn1c:raw-preserve
// RLRQApduUserInformation represents the ASN.1 type RLRQ-apdu-user-information (SEQUENCE_OF).
type RLRQApduUserInformation = []runtime.RawValue

// asn1c:raw-preserve
// RLREApduUserInformation represents the ASN.1 type RLRE-apdu-user-information (SEQUENCE_OF).
type RLREApduUserInformation = []runtime.RawValue

// asn1c:raw-preserve
// ABRTApduUserInformation represents the ASN.1 type ABRT-apdu-user-information (SEQUENCE_OF).
type ABRTApduUserInformation = []runtime.RawValue

// AssociateSourceDiagnosticDialogueServiceUserValue represents the arbitrary-width ASN.1 INTEGER type Associate-source-diagnostic-dialogue-service-user-Value with named numbers.
type AssociateSourceDiagnosticDialogueServiceUserValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	AssociateSourceDiagnosticDialogueServiceUserValueNullDecimal                               = "0"
	AssociateSourceDiagnosticDialogueServiceUserValueNull                                      = 0
	AssociateSourceDiagnosticDialogueServiceUserValueNoReasonGivenDecimal                      = "1"
	AssociateSourceDiagnosticDialogueServiceUserValueNoReasonGiven                             = 1
	AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedDecimal = "2"
	AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupported        = 2
)

// NewAssociateSourceDiagnosticDialogueServiceUserValue returns an immutable AssociateSourceDiagnosticDialogueServiceUserValue containing value.
func NewAssociateSourceDiagnosticDialogueServiceUserValue(value *big.Int) AssociateSourceDiagnosticDialogueServiceUserValue {
	return AssociateSourceDiagnosticDialogueServiceUserValue{value: runtime.CloneBigInt(value)}
}

// NewAssociateSourceDiagnosticDialogueServiceUserValueInt64 returns a AssociateSourceDiagnosticDialogueServiceUserValue containing value.
func NewAssociateSourceDiagnosticDialogueServiceUserValueInt64(value int64) AssociateSourceDiagnosticDialogueServiceUserValue {
	return NewAssociateSourceDiagnosticDialogueServiceUserValue(big.NewInt(value))
}

// AssociateSourceDiagnosticDialogueServiceUserValueNullValue returns the named value null.
func AssociateSourceDiagnosticDialogueServiceUserValueNullValue() AssociateSourceDiagnosticDialogueServiceUserValue {
	return NewAssociateSourceDiagnosticDialogueServiceUserValue(runtime.MustParseBigIntDecimal(AssociateSourceDiagnosticDialogueServiceUserValueNullDecimal))
}

// AssociateSourceDiagnosticDialogueServiceUserValueNoReasonGivenValue returns the named value no-reason-given.
func AssociateSourceDiagnosticDialogueServiceUserValueNoReasonGivenValue() AssociateSourceDiagnosticDialogueServiceUserValue {
	return NewAssociateSourceDiagnosticDialogueServiceUserValue(runtime.MustParseBigIntDecimal(AssociateSourceDiagnosticDialogueServiceUserValueNoReasonGivenDecimal))
}

// AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedValue returns the named value application-context-name-not-supported.
func AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedValue() AssociateSourceDiagnosticDialogueServiceUserValue {
	return NewAssociateSourceDiagnosticDialogueServiceUserValue(runtime.MustParseBigIntDecimal(AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v AssociateSourceDiagnosticDialogueServiceUserValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v AssociateSourceDiagnosticDialogueServiceUserValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v AssociateSourceDiagnosticDialogueServiceUserValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case AssociateSourceDiagnosticDialogueServiceUserValueNullDecimal:
		return "null", true
	case AssociateSourceDiagnosticDialogueServiceUserValueNoReasonGivenDecimal:
		return "no-reason-given", true
	case AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedDecimal:
		return "application-context-name-not-supported", true
	default:
		return "", false
	}
}

func (v AssociateSourceDiagnosticDialogueServiceUserValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v AssociateSourceDiagnosticDialogueServiceUserValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *AssociateSourceDiagnosticDialogueServiceUserValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AssociateSourceDiagnosticDialogueServiceUserValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewAssociateSourceDiagnosticDialogueServiceUserValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v AssociateSourceDiagnosticDialogueServiceUserValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *AssociateSourceDiagnosticDialogueServiceUserValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AssociateSourceDiagnosticDialogueServiceUserValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewAssociateSourceDiagnosticDialogueServiceUserValue(value)
	return nil
}

// AssociateSourceDiagnosticDialogueServiceProviderValue represents the arbitrary-width ASN.1 INTEGER type Associate-source-diagnostic-dialogue-service-provider-Value with named numbers.
type AssociateSourceDiagnosticDialogueServiceProviderValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	AssociateSourceDiagnosticDialogueServiceProviderValueNullDecimal                    = "0"
	AssociateSourceDiagnosticDialogueServiceProviderValueNull                           = 0
	AssociateSourceDiagnosticDialogueServiceProviderValueNoReasonGivenDecimal           = "1"
	AssociateSourceDiagnosticDialogueServiceProviderValueNoReasonGiven                  = 1
	AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortionDecimal = "2"
	AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortion        = 2
)

// NewAssociateSourceDiagnosticDialogueServiceProviderValue returns an immutable AssociateSourceDiagnosticDialogueServiceProviderValue containing value.
func NewAssociateSourceDiagnosticDialogueServiceProviderValue(value *big.Int) AssociateSourceDiagnosticDialogueServiceProviderValue {
	return AssociateSourceDiagnosticDialogueServiceProviderValue{value: runtime.CloneBigInt(value)}
}

// NewAssociateSourceDiagnosticDialogueServiceProviderValueInt64 returns a AssociateSourceDiagnosticDialogueServiceProviderValue containing value.
func NewAssociateSourceDiagnosticDialogueServiceProviderValueInt64(value int64) AssociateSourceDiagnosticDialogueServiceProviderValue {
	return NewAssociateSourceDiagnosticDialogueServiceProviderValue(big.NewInt(value))
}

// AssociateSourceDiagnosticDialogueServiceProviderValueNullValue returns the named value null.
func AssociateSourceDiagnosticDialogueServiceProviderValueNullValue() AssociateSourceDiagnosticDialogueServiceProviderValue {
	return NewAssociateSourceDiagnosticDialogueServiceProviderValue(runtime.MustParseBigIntDecimal(AssociateSourceDiagnosticDialogueServiceProviderValueNullDecimal))
}

// AssociateSourceDiagnosticDialogueServiceProviderValueNoReasonGivenValue returns the named value no-reason-given.
func AssociateSourceDiagnosticDialogueServiceProviderValueNoReasonGivenValue() AssociateSourceDiagnosticDialogueServiceProviderValue {
	return NewAssociateSourceDiagnosticDialogueServiceProviderValue(runtime.MustParseBigIntDecimal(AssociateSourceDiagnosticDialogueServiceProviderValueNoReasonGivenDecimal))
}

// AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortionValue returns the named value no-common-dialogue-portion.
func AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortionValue() AssociateSourceDiagnosticDialogueServiceProviderValue {
	return NewAssociateSourceDiagnosticDialogueServiceProviderValue(runtime.MustParseBigIntDecimal(AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortionDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v AssociateSourceDiagnosticDialogueServiceProviderValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v AssociateSourceDiagnosticDialogueServiceProviderValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v AssociateSourceDiagnosticDialogueServiceProviderValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case AssociateSourceDiagnosticDialogueServiceProviderValueNullDecimal:
		return "null", true
	case AssociateSourceDiagnosticDialogueServiceProviderValueNoReasonGivenDecimal:
		return "no-reason-given", true
	case AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortionDecimal:
		return "no-common-dialogue-portion", true
	default:
		return "", false
	}
}

func (v AssociateSourceDiagnosticDialogueServiceProviderValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v AssociateSourceDiagnosticDialogueServiceProviderValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *AssociateSourceDiagnosticDialogueServiceProviderValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AssociateSourceDiagnosticDialogueServiceProviderValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewAssociateSourceDiagnosticDialogueServiceProviderValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v AssociateSourceDiagnosticDialogueServiceProviderValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *AssociateSourceDiagnosticDialogueServiceProviderValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AssociateSourceDiagnosticDialogueServiceProviderValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewAssociateSourceDiagnosticDialogueServiceProviderValue(value)
	return nil
}

// MarshalBER encodes DialoguePDU to BER format.
func (v *DialoguePDU) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DialoguePDUChoiceDialogueRequest:
		if v.DialogueRequest == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueRequest is nil")
		}
		enc_0, err := v.DialogueRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueRequest: %w", err)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding dialogueRequest: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueResponse is nil")
		}
		enc_1, err := v.DialogueResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueResponse: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding dialogueResponse: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueAbort is nil")
		}
		enc_2, err := v.DialogueAbort.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueAbort: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding dialogueAbort: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DialoguePDU", v.Choice)
	}
}

// MarshalDER encodes DialoguePDU to DER format.
func (v *DialoguePDU) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case DialoguePDUChoiceDialogueRequest:
		if v.DialogueRequest == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueRequest is nil")
		}
		enc_der_0, err := v.DialogueRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueRequest: %w", err)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding dialogueRequest: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding dialogueRequest as DER: %w", derErr)
		}
		return enc_der_0, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueResponse is nil")
		}
		enc_der_1, err := v.DialogueResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueResponse: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding dialogueResponse: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding dialogueResponse as DER: %w", derErr)
		}
		return enc_der_1, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueAbort is nil")
		}
		enc_der_2, err := v.DialogueAbort.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueAbort: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding dialogueAbort: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDERElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding dialogueAbort as DER: %w", derErr)
		}
		return enc_der_2, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DialoguePDU as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DialoguePDU from BER/DER format.
func (v *DialoguePDU) UnmarshalBER(data []byte) error {
	*v = DialoguePDU{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for DialoguePDU CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DialoguePDU: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DialoguePDU CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DialoguePDU", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueRequest
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueRequest: %w", tlvErr)
		}
		reconstructed := ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, rawVal)
		var dec AARQApdu
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding dialogueRequest: %w", unmErr)
		}
		v.DialogueRequest = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueResponse
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueResponse: %w", tlvErr)
		}
		reconstructed := ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 1, Constructed: true}, rawVal)
		var dec AAREApdu
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding dialogueResponse: %w", unmErr)
		}
		v.DialogueResponse = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueAbort
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueAbort: %w", tlvErr)
		}
		reconstructed := ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 4, Constructed: true}, rawVal)
		var dec ABRTApdu
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding dialogueAbort: %w", unmErr)
		}
		v.DialogueAbort = &dec
	} else {
		return fmt.Errorf("unknown tag %s for DialoguePDU CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AARQApdu to BER format.
func (v *AARQApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil {
		enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	enc_applicationcontextname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAARQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes AARQApdu to DER format.
func (v *AARQApdu) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil {
		enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	enc_applicationcontextname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERAARQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
		}
		enc_userinformation = retagged_enc_userinformation
		children = append(children, enc_userinformation...)
	}
	encoded := ber.EncodeSequence(children)
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding AARQApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AARQApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AARQApdu from BER/DER format.
func (v *AARQApdu) UnmarshalBER(data []byte) error {
	*v = AARQApdu{}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AARQApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AARQApdu: %w: expected tag [APPLICATION 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AARQApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocol-version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding protocol-version: %w", err)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return fmt.Errorf("decoding protocol-version: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion)
				if bsErr != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsErr)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: len(bsBytes_protocolversion)*8 - bsUnused_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
				offset += n_protocolversion
			}
		}
	}
	// Decode application-context-name
	if offset >= len(content) {
		return fmt.Errorf("missing required field application-context-name")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for application-context-name, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding application-context-name: %w", err)
	}
	if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
		return fmt.Errorf("decoding application-context-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname)
	}
	// Decode inner value from explicit tag wrapper
	val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname)
	if oidErr != nil {
		return fmt.Errorf("decoding application-context-name: %w", oidErr)
	}
	v.ApplicationContextName = runtime.ObjectIdentifier(val_applicationcontextname)
	offset += n_applicationcontextname
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERAARQApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AARQApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AAREApdu to BER format.
func (v *AAREApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil {
		enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	enc_applicationcontextname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
	children = append(children, enc_applicationcontextname...)
	enc_result := ber.EncodeBigInt((v.Result).BigInt())
	enc_result = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_result)
	children = append(children, enc_result...)
	enc_resultsourcediagnostic, err := v.ResultSourceDiagnostic.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding result-source-diagnostic: %w", err)
	}
	enc_resultsourcediagnostic = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_resultsourcediagnostic)
	children = append(children, enc_resultsourcediagnostic...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAAREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 1, Constructed: true}, children), nil
}

// MarshalDER encodes AAREApdu to DER format.
func (v *AAREApdu) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil {
		enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	enc_applicationcontextname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
	children = append(children, enc_applicationcontextname...)
	enc_result := ber.EncodeBigInt((v.Result).BigInt())
	enc_result = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_result)
	children = append(children, enc_result...)
	enc_resultsourcediagnostic, err := v.ResultSourceDiagnostic.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding result-source-diagnostic: %w", err)
	}
	enc_resultsourcediagnostic = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_resultsourcediagnostic)
	children = append(children, enc_resultsourcediagnostic...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERAAREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
		}
		enc_userinformation = retagged_enc_userinformation
		children = append(children, enc_userinformation...)
	}
	encoded := ber.EncodeSequence(children)
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding AAREApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AAREApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AAREApdu from BER/DER format.
func (v *AAREApdu) UnmarshalBER(data []byte) error {
	*v = AAREApdu{}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AAREApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AAREApdu: %w: expected tag [APPLICATION 1], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AAREApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocol-version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding protocol-version: %w", err)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return fmt.Errorf("decoding protocol-version: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion)
				if bsErr != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsErr)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: len(bsBytes_protocolversion)*8 - bsUnused_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
				offset += n_protocolversion
			}
		}
	}
	// Decode application-context-name
	if offset >= len(content) {
		return fmt.Errorf("missing required field application-context-name")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for application-context-name, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding application-context-name: %w", err)
	}
	if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
		return fmt.Errorf("decoding application-context-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname)
	}
	// Decode inner value from explicit tag wrapper
	val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname)
	if oidErr != nil {
		return fmt.Errorf("decoding application-context-name: %w", oidErr)
	}
	v.ApplicationContextName = runtime.ObjectIdentifier(val_applicationcontextname)
	offset += n_applicationcontextname
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for result, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_result, n_result, innerData_result, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding result: %w", err)
	}
	if decodedTag_result.Class != tag.ClassContextSpecific || decodedTag_result.Number != 2 || decodedTag_result.Constructed != true {
		return fmt.Errorf("decoding result: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_result)
	}
	// Decode inner value from explicit tag wrapper
	val_result, _, err := ber.DecodeBigInt(innerData_result)
	if err != nil {
		return fmt.Errorf("decoding result: %w", err)
	}
	var named_result AssociateResult
	if namedErr := named_result.UnmarshalText([]byte(val_result.String())); namedErr != nil {
		return fmt.Errorf("decoding result: %w", namedErr)
	}
	v.Result = named_result
	offset += n_result
	// Decode result-source-diagnostic
	if offset >= len(content) {
		return fmt.Errorf("missing required field result-source-diagnostic")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for result-source-diagnostic, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	decodedTag_resultsourcediagnostic, n_resultsourcediagnostic, innerData_resultsourcediagnostic, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding result-source-diagnostic: %w", err)
	}
	if decodedTag_resultsourcediagnostic.Class != tag.ClassContextSpecific || decodedTag_resultsourcediagnostic.Number != 3 || decodedTag_resultsourcediagnostic.Constructed != true {
		return fmt.Errorf("decoding result-source-diagnostic: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_resultsourcediagnostic)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.ResultSourceDiagnostic.UnmarshalBER(innerData_resultsourcediagnostic); unmErr != nil {
		return fmt.Errorf("decoding result-source-diagnostic: %w", unmErr)
	}
	offset += n_resultsourcediagnostic
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERAAREApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AAREApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RLRQApdu to BER format.
func (v *RLRQApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Reason != nil {
		enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", tagErr_enc_reason)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLRQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 2, Constructed: true}, children), nil
}

// MarshalDER encodes RLRQApdu to DER format.
func (v *RLRQApdu) MarshalDER() ([]byte, error) {
	var children []byte
	if v.Reason != nil {
		enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", tagErr_enc_reason)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERRLRQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
		}
		enc_userinformation = retagged_enc_userinformation
		children = append(children, enc_userinformation...)
	}
	encoded := ber.EncodeSequence(children)
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding RLRQApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLRQApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RLRQApdu from BER/DER format.
func (v *RLRQApdu) UnmarshalBER(data []byte) error {
	*v = RLRQApdu{}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RLRQApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 2 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RLRQApdu: %w: expected tag [APPLICATION 2], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RLRQApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_reason, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reason: %w", err)
				}
				if decodedTag_reason.Class != tag.ClassContextSpecific || decodedTag_reason.Number != 0 || decodedTag_reason.Constructed != false {
					return fmt.Errorf("decoding reason: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reason)
				}
				decVal_reason, intErr := ber.DecodeBigIntValue(rawVal_reason)
				if intErr != nil {
					return fmt.Errorf("decoding reason: %w", intErr)
				}
				var named_reason ReleaseRequestReason
				if namedErr := named_reason.UnmarshalText([]byte(decVal_reason.String())); namedErr != nil {
					return fmt.Errorf("decoding reason: %w", namedErr)
				}
				v.Reason = &named_reason
				offset += n_reason
			}
		}
	}
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERRLRQApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RLRQApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RLREApdu to BER format.
func (v *RLREApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Reason != nil {
		enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", tagErr_enc_reason)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 3, Constructed: true}, children), nil
}

// MarshalDER encodes RLREApdu to DER format.
func (v *RLREApdu) MarshalDER() ([]byte, error) {
	var children []byte
	if v.Reason != nil {
		enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", tagErr_enc_reason)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERRLREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
		}
		enc_userinformation = retagged_enc_userinformation
		children = append(children, enc_userinformation...)
	}
	encoded := ber.EncodeSequence(children)
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 3, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding RLREApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLREApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RLREApdu from BER/DER format.
func (v *RLREApdu) UnmarshalBER(data []byte) error {
	*v = RLREApdu{}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RLREApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RLREApdu: %w: expected tag [APPLICATION 3], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RLREApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_reason, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reason: %w", err)
				}
				if decodedTag_reason.Class != tag.ClassContextSpecific || decodedTag_reason.Number != 0 || decodedTag_reason.Constructed != false {
					return fmt.Errorf("decoding reason: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reason)
				}
				decVal_reason, intErr := ber.DecodeBigIntValue(rawVal_reason)
				if intErr != nil {
					return fmt.Errorf("decoding reason: %w", intErr)
				}
				var named_reason ReleaseResponseReason
				if namedErr := named_reason.UnmarshalText([]byte(decVal_reason.String())); namedErr != nil {
					return fmt.Errorf("decoding reason: %w", namedErr)
				}
				v.Reason = &named_reason
				offset += n_reason
			}
		}
	}
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERRLREApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RLREApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ABRTApdu to BER format.
func (v *ABRTApdu) MarshalBER() ([]byte, error) {
	var children []byte
	enc_abortsource := ber.EncodeBigInt((v.AbortSource).BigInt())
	retagged_enc_abortsource, tagErr_enc_abortsource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_abortsource)
	if tagErr_enc_abortsource != nil {
		return nil, fmt.Errorf("encoding abort-source: %w", tagErr_enc_abortsource)
	}
	enc_abortsource = retagged_enc_abortsource
	children = append(children, enc_abortsource...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERABRTApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 4, Constructed: true}, children), nil
}

// MarshalDER encodes ABRTApdu to DER format.
func (v *ABRTApdu) MarshalDER() ([]byte, error) {
	var children []byte
	enc_abortsource := ber.EncodeBigInt((v.AbortSource).BigInt())
	retagged_enc_abortsource, tagErr_enc_abortsource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_abortsource)
	if tagErr_enc_abortsource != nil {
		return nil, fmt.Errorf("encoding abort-source: %w", tagErr_enc_abortsource)
	}
	enc_abortsource = retagged_enc_abortsource
	children = append(children, enc_abortsource...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERABRTApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
		}
		enc_userinformation = retagged_enc_userinformation
		children = append(children, enc_userinformation...)
	}
	encoded := ber.EncodeSequence(children)
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ABRTApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ABRTApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ABRTApdu from BER/DER format.
func (v *ABRTApdu) UnmarshalBER(data []byte) error {
	*v = ABRTApdu{}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ABRTApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 4 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ABRTApdu: %w: expected tag [APPLICATION 4], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ABRTApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode abort-source
	if offset >= len(content) {
		return fmt.Errorf("missing required field abort-source")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for abort-source, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_abortsource, n_abortsource, rawVal_abortsource, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding abort-source: %w", err)
	}
	if decodedTag_abortsource.Class != tag.ClassContextSpecific || decodedTag_abortsource.Number != 0 || decodedTag_abortsource.Constructed != false {
		return fmt.Errorf("decoding abort-source: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_abortsource)
	}
	decVal_abortsource, intErr := ber.DecodeBigIntValue(rawVal_abortsource)
	if intErr != nil {
		return fmt.Errorf("decoding abort-source: %w", intErr)
	}
	var named_abortsource ABRTSource
	if namedErr := named_abortsource.UnmarshalText([]byte(decVal_abortsource.String())); namedErr != nil {
		return fmt.Errorf("decoding abort-source: %w", namedErr)
	}
	v.AbortSource = named_abortsource
	offset += n_abortsource
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERABRTApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ABRTApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AssociateSourceDiagnostic to BER format.
func (v *AssociateSourceDiagnostic) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AssociateSourceDiagnosticChoiceDialogueServiceUser:
		if v.DialogueServiceUser == nil {
			return nil, fmt.Errorf("choice AssociateSourceDiagnostic: dialogue-service-user is nil")
		}
		enc_0 := ber.EncodeBigInt(v.DialogueServiceUser.BigInt())
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		return enc_0, nil
	case AssociateSourceDiagnosticChoiceDialogueServiceProvider:
		if v.DialogueServiceProvider == nil {
			return nil, fmt.Errorf("choice AssociateSourceDiagnostic: dialogue-service-provider is nil")
		}
		enc_1 := ber.EncodeBigInt(v.DialogueServiceProvider.BigInt())
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AssociateSourceDiagnostic", v.Choice)
	}
}

// MarshalDER encodes AssociateSourceDiagnostic to DER format.
func (v *AssociateSourceDiagnostic) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AssociateSourceDiagnostic as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AssociateSourceDiagnostic from BER/DER format.
func (v *AssociateSourceDiagnostic) UnmarshalBER(data []byte) error {
	*v = AssociateSourceDiagnostic{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for AssociateSourceDiagnostic CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AssociateSourceDiagnostic: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AssociateSourceDiagnostic CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AssociateSourceDiagnostic", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = AssociateSourceDiagnosticChoiceDialogueServiceUser
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogue-service-user: %w", tlvErr)
		}
		decVal, _, intErr := ber.DecodeBigInt(innerData)
		if intErr != nil {
			return fmt.Errorf("decoding dialogue-service-user: %w", intErr)
		}
		var named_dialogueserviceuser AssociateSourceDiagnosticDialogueServiceUserValue
		if namedErr := named_dialogueserviceuser.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding dialogue-service-user: %w", namedErr)
		}
		v.DialogueServiceUser = &named_dialogueserviceuser
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = AssociateSourceDiagnosticChoiceDialogueServiceProvider
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogue-service-provider: %w", tlvErr)
		}
		decVal, _, intErr := ber.DecodeBigInt(innerData)
		if intErr != nil {
			return fmt.Errorf("decoding dialogue-service-provider: %w", intErr)
		}
		var named_dialogueserviceprovider AssociateSourceDiagnosticDialogueServiceProviderValue
		if namedErr := named_dialogueserviceprovider.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding dialogue-service-provider: %w", namedErr)
		}
		v.DialogueServiceProvider = &named_dialogueserviceprovider
	} else {
		return fmt.Errorf("unknown tag %s for AssociateSourceDiagnostic CHOICE", peekTag)
	}
	return nil
}

// MarshalBERAARQApduUserInformation encodes a AARQApduUserInformation list to BER.
func MarshalBERAARQApduUserInformation(list AARQApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERAARQApduUserInformation encodes a AARQApduUserInformation list to DER.
func MarshalDERAARQApduUserInformation(list AARQApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		if err := ber.ValidateDERElement(elem.Bytes); err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, elem.Bytes...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AARQApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAARQApduUserInformation decodes a AARQApduUserInformation list from BER.
func UnmarshalBERAARQApduUserInformation(data []byte) (AARQApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AARQApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AARQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result AARQApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERAAREApduUserInformation encodes a AAREApduUserInformation list to BER.
func MarshalBERAAREApduUserInformation(list AAREApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERAAREApduUserInformation encodes a AAREApduUserInformation list to DER.
func MarshalDERAAREApduUserInformation(list AAREApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		if err := ber.ValidateDERElement(elem.Bytes); err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, elem.Bytes...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AAREApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAAREApduUserInformation decodes a AAREApduUserInformation list from BER.
func UnmarshalBERAAREApduUserInformation(data []byte) (AAREApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AAREApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AAREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result AAREApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERRLRQApduUserInformation encodes a RLRQApduUserInformation list to BER.
func MarshalBERRLRQApduUserInformation(list RLRQApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERRLRQApduUserInformation encodes a RLRQApduUserInformation list to DER.
func MarshalDERRLRQApduUserInformation(list RLRQApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		if err := ber.ValidateDERElement(elem.Bytes); err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, elem.Bytes...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLRQApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRLRQApduUserInformation decodes a RLRQApduUserInformation list from BER.
func UnmarshalBERRLRQApduUserInformation(data []byte) (RLRQApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RLRQApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLRQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result RLRQApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERRLREApduUserInformation encodes a RLREApduUserInformation list to BER.
func MarshalBERRLREApduUserInformation(list RLREApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERRLREApduUserInformation encodes a RLREApduUserInformation list to DER.
func MarshalDERRLREApduUserInformation(list RLREApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		if err := ber.ValidateDERElement(elem.Bytes); err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, elem.Bytes...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLREApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRLREApduUserInformation decodes a RLREApduUserInformation list from BER.
func UnmarshalBERRLREApduUserInformation(data []byte) (RLREApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RLREApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result RLREApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERABRTApduUserInformation encodes a ABRTApduUserInformation list to BER.
func MarshalBERABRTApduUserInformation(list ABRTApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERABRTApduUserInformation encodes a ABRTApduUserInformation list to DER.
func MarshalDERABRTApduUserInformation(list ABRTApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		if err := ber.ValidateDERElement(elem.Bytes); err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, elem.Bytes...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ABRTApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERABRTApduUserInformation decodes a ABRTApduUserInformation list from BER.
func UnmarshalBERABRTApduUserInformation(data []byte) (ABRTApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ABRTApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ABRTApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result ABRTApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}
