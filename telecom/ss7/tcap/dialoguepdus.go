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
	berOriginal_     []byte    `json:"-"`
	berSnapshot_     []byte    `json:"-"`
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
	UserInformation        *AARQApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_  bool                     `asn1:"-" json:"-"`
	berOriginal_           []byte                   `asn1:"-" json:"-"`
	berSnapshot_           []byte                   `asn1:"-" json:"-"`
}

// AAREApdu represents the ASN.1 type AARE-apdu (SEQUENCE).
type AAREApdu struct {
	ProtocolVersion        *runtime.BitString        `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName runtime.ObjectIdentifier  `asn1:"tag:1,context,explicit"`
	Result                 AssociateResult           `asn1:"tag:2,context,explicit"`
	ResultSourceDiagnostic AssociateSourceDiagnostic `asn1:"tag:3,context,explicit"`
	UserInformation        *AAREApduUserInformation  `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_  bool                      `asn1:"-" json:"-"`
	berOriginal_           []byte                    `asn1:"-" json:"-"`
	berSnapshot_           []byte                    `asn1:"-" json:"-"`
}

// RLRQApdu represents the ASN.1 type RLRQ-apdu (SEQUENCE).
type RLRQApdu struct {
	Reason                *ReleaseRequestReason    `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation       *RLRQApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                     `asn1:"-" json:"-"`
	berOriginal_          []byte                   `asn1:"-" json:"-"`
	berSnapshot_          []byte                   `asn1:"-" json:"-"`
}

// RLREApdu represents the ASN.1 type RLRE-apdu (SEQUENCE).
type RLREApdu struct {
	Reason                *ReleaseResponseReason   `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation       *RLREApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                     `asn1:"-" json:"-"`
	berOriginal_          []byte                   `asn1:"-" json:"-"`
	berSnapshot_          []byte                   `asn1:"-" json:"-"`
}

// ABRTApdu represents the ASN.1 type ABRT-apdu (SEQUENCE).
type ABRTApdu struct {
	AbortSource           ABRTSource               `asn1:"tag:0,context,implicit"`
	UserInformation       *ABRTApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                     `asn1:"-" json:"-"`
	berOriginal_          []byte                   `asn1:"-" json:"-"`
	berSnapshot_          []byte                   `asn1:"-" json:"-"`
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
	berOriginal_            []byte                                                 `json:"-"`
	berSnapshot_            []byte                                                 `json:"-"`
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
type AARQApduUserInformation struct {
	Values       []runtime.External `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

// asn1c:raw-preserve
// AAREApduUserInformation represents the ASN.1 type AARE-apdu-user-information (SEQUENCE_OF).
type AAREApduUserInformation struct {
	Values       []runtime.External `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

// asn1c:raw-preserve
// RLRQApduUserInformation represents the ASN.1 type RLRQ-apdu-user-information (SEQUENCE_OF).
type RLRQApduUserInformation struct {
	Values       []runtime.External `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

// asn1c:raw-preserve
// RLREApduUserInformation represents the ASN.1 type RLRE-apdu-user-information (SEQUENCE_OF).
type RLREApduUserInformation struct {
	Values       []runtime.External `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

// asn1c:raw-preserve
// ABRTApduUserInformation represents the ASN.1 type ABRT-apdu-user-information (SEQUENCE_OF).
type ABRTApduUserInformation struct {
	Values       []runtime.External `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

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
func (v *DialoguePDU) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DialoguePDU) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case DialoguePDUChoiceDialogueRequest:
		if v.DialogueRequest == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueRequest is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.DialogueRequest.MarshalBER(ber.ChildEncodeOptions(opts, "dialogueRequest")...)
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
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueResponse is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.DialogueResponse.MarshalBER(ber.ChildEncodeOptions(opts, "dialogueResponse")...)
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
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueAbort is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.DialogueAbort.MarshalBER(ber.ChildEncodeOptions(opts, "dialogueAbort")...)
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
	if v == nil {
		return nil, fmt.Errorf("%w: DialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case DialoguePDUChoiceDialogueRequest:
		if v.DialogueRequest == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueRequest is nil", ber.ErrInvalidValue)
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
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding dialogueRequest as DER: %w", derErr)
		}
		return enc_der_0, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueResponse is nil", ber.ErrInvalidValue)
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
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding dialogueResponse as DER: %w", derErr)
		}
		return enc_der_1, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueAbort is nil", ber.ErrInvalidValue)
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
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding dialogueAbort as DER: %w", derErr)
		}
		return enc_der_2, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DialoguePDU as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DialoguePDU from BER/DER format.
func (v *DialoguePDU) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DialoguePDU destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DialoguePDU{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for DialoguePDU CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DialoguePDU: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding DialoguePDU CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DialoguePDU", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueRequest
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueRequest: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AARQApdu
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "dialogueRequest")...); unmErr != nil {
			return fmt.Errorf("decoding dialogueRequest: %w", unmErr)
		}
		v.DialogueRequest = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueResponse
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueResponse: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 1, Constructed: true}, rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AAREApdu
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "dialogueResponse")...); unmErr != nil {
			return fmt.Errorf("decoding dialogueResponse: %w", unmErr)
		}
		v.DialogueResponse = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueAbort
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueAbort: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 4, Constructed: true}, rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ABRTApdu
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "dialogueAbort")...); unmErr != nil {
			return fmt.Errorf("decoding dialogueAbort: %w", unmErr)
		}
		v.DialogueAbort = &dec
	} else {
		return fmt.Errorf("unknown tag %s for DialoguePDU CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AARQApdu to BER format.
func (v *AARQApdu) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AARQApdu receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AARQApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ProtocolVersion != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:626
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		if encodeErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", encodeErr_enc_protocolversion)
		}
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
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding application-context-name: %w", encodeErr)
		}
	}
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAARQApduUserInformation(v.UserInformation, ber.ChildEncodeOptions(opts, "user-information")...)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding user-information: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes AARQApdu to DER format.
func (v *AARQApdu) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AARQApdu receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ProtocolVersion != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:626
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeDERNamedBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength)
		if encodeErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", encodeErr_enc_protocolversion)
		}
		if string(enc_protocolversion) != "\x03\x02\a\x80" {
			retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
			if tagErr_enc_protocolversion != nil {
				return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
			}
			enc_protocolversion = retagged_enc_protocolversion
			children = append(children, enc_protocolversion...)
		}
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding application-context-name: %w", encodeErr)
		}
	}
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding AARQApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AARQApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AARQApdu from BER/DER format.
func (v *AARQApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AARQApdu destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AARQApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding protocol-version: %w", err)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return fmt.Errorf("decoding protocol-version: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsErr)
				}
				bsBitLength_protocolversion, bsLenErr_protocolversion := ber.BitStringBitLength(len(bsBytes_protocolversion), bsUnused_protocolversion)
				if bsLenErr_protocolversion != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsLenErr_protocolversion)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: bsBitLength_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
				if offset > len(content) || n_protocolversion < 0 || n_protocolversion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
	decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding application-context-name: %w", err)
	}
	if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
		return fmt.Errorf("decoding application-context-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname)
	}
	_, innerUsed_applicationcontextname, _, innerErr_applicationcontextname := ber.DecodeTLV(innerData_applicationcontextname, opts...)
	if innerErr_applicationcontextname != nil {
		return fmt.Errorf("decoding application-context-name: %w", innerErr_applicationcontextname)
	}
	if innerUsed_applicationcontextname != len(innerData_applicationcontextname) {
		return fmt.Errorf("decoding application-context-name: %w", ber.ErrExtraData)
	}
	// Decode inner value from explicit tag wrapper
	val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname, opts...)
	if oidErr != nil {
		return fmt.Errorf("decoding application-context-name: %w", oidErr)
	}
	v.ApplicationContextName = runtime.ObjectIdentifier(val_applicationcontextname)
	if offset < 0 || offset >
		len(content) || n_applicationcontextname < 0 || n_applicationcontextname >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_applicationcontextname
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return fmt.Errorf("decoding user-information: %w", reconstructionErr_userinformation)
				}
				dec_userinformation, unmErr := UnmarshalBERAARQApduUserInformation(reconstructed_userinformation, ber.ChildDecodeOptions(opts, "user-information")...)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
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
func (v *AAREApdu) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AAREApdu receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AAREApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ProtocolVersion != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:626
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		if encodeErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", encodeErr_enc_protocolversion)
		}
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
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding application-context-name: %w", encodeErr)
		}
	}
	children = append(children, enc_applicationcontextname...)
	enc_result, encodeErr_enc_result := ber.EncodeBigInt((v.Result).BigInt())
	if encodeErr_enc_result != nil {
		return nil, fmt.Errorf("encoding result: %w", encodeErr_enc_result)
	}
	{
		var encodeErr error
		enc_result, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_result)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding result: %w", encodeErr)
		}
	}
	children = append(children, enc_result...)
	enc_resultsourcediagnostic, err := v.ResultSourceDiagnostic.MarshalBER(ber.ChildEncodeOptions(opts, "result-source-diagnostic")...)
	if err != nil {
		return nil, fmt.Errorf("encoding result-source-diagnostic: %w", err)
	}
	{
		var encodeErr error
		enc_resultsourcediagnostic, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_resultsourcediagnostic)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding result-source-diagnostic: %w", encodeErr)
		}
	}
	children = append(children, enc_resultsourcediagnostic...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAAREApduUserInformation(v.UserInformation, ber.ChildEncodeOptions(opts, "user-information")...)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding user-information: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 1, Constructed: true}, children)
}

// MarshalDER encodes AAREApdu to DER format.
func (v *AAREApdu) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AAREApdu receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ProtocolVersion != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:626
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeDERNamedBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength)
		if encodeErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", encodeErr_enc_protocolversion)
		}
		if string(enc_protocolversion) != "\x03\x02\a\x80" {
			retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
			if tagErr_enc_protocolversion != nil {
				return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
			}
			enc_protocolversion = retagged_enc_protocolversion
			children = append(children, enc_protocolversion...)
		}
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding application-context-name: %w", encodeErr)
		}
	}
	children = append(children, enc_applicationcontextname...)
	enc_result, encodeErr_enc_result := ber.EncodeBigInt((v.Result).BigInt())
	if encodeErr_enc_result != nil {
		return nil, fmt.Errorf("encoding result: %w", encodeErr_enc_result)
	}
	{
		var encodeErr error
		enc_result, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_result)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding result: %w", encodeErr)
		}
	}
	children = append(children, enc_result...)
	enc_resultsourcediagnostic, err := v.ResultSourceDiagnostic.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding result-source-diagnostic: %w", err)
	}
	{
		var encodeErr error
		enc_resultsourcediagnostic, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_resultsourcediagnostic)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding result-source-diagnostic: %w", encodeErr)
		}
	}
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding AAREApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AAREApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AAREApdu from BER/DER format.
func (v *AAREApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AAREApdu destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AAREApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding protocol-version: %w", err)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return fmt.Errorf("decoding protocol-version: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsErr)
				}
				bsBitLength_protocolversion, bsLenErr_protocolversion := ber.BitStringBitLength(len(bsBytes_protocolversion), bsUnused_protocolversion)
				if bsLenErr_protocolversion != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsLenErr_protocolversion)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: bsBitLength_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
				if offset > len(content) || n_protocolversion < 0 || n_protocolversion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
	decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding application-context-name: %w", err)
	}
	if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
		return fmt.Errorf("decoding application-context-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname)
	}
	_, innerUsed_applicationcontextname, _, innerErr_applicationcontextname := ber.DecodeTLV(innerData_applicationcontextname, opts...)
	if innerErr_applicationcontextname != nil {
		return fmt.Errorf("decoding application-context-name: %w", innerErr_applicationcontextname)
	}
	if innerUsed_applicationcontextname != len(innerData_applicationcontextname) {
		return fmt.Errorf("decoding application-context-name: %w", ber.ErrExtraData)
	}
	// Decode inner value from explicit tag wrapper
	val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname, opts...)
	if oidErr != nil {
		return fmt.Errorf("decoding application-context-name: %w", oidErr)
	}
	v.ApplicationContextName = runtime.ObjectIdentifier(val_applicationcontextname)
	if offset < 0 || offset >
		len(content) || n_applicationcontextname < 0 || n_applicationcontextname >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

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
	decodedTag_result, n_result, innerData_result, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding result: %w", err)
	}
	if decodedTag_result.Class != tag.ClassContextSpecific || decodedTag_result.Number != 2 || decodedTag_result.Constructed != true {
		return fmt.Errorf("decoding result: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_result)
	}
	_, innerUsed_result, _, innerErr_result := ber.DecodeTLV(innerData_result, opts...)
	if innerErr_result != nil {
		return fmt.Errorf("decoding result: %w", innerErr_result)
	}
	if innerUsed_result != len(innerData_result) {
		return fmt.Errorf("decoding result: %w", ber.ErrExtraData)
	}
	// Decode inner value from explicit tag wrapper
	val_result, _, err := ber.DecodeBigInt(innerData_result, opts...)
	if err != nil {
		return fmt.Errorf("decoding result: %w", err)
	}
	var named_result AssociateResult
	if namedErr := named_result.UnmarshalText([]byte(val_result.String())); namedErr != nil {
		return fmt.Errorf("decoding result: %w", namedErr)
	}
	v.Result = named_result
	if offset < 0 || offset >
		len(content) || n_result < 0 || n_result > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

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
	decodedTag_resultsourcediagnostic, n_resultsourcediagnostic, innerData_resultsourcediagnostic, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding result-source-diagnostic: %w", err)
	}
	if decodedTag_resultsourcediagnostic.Class != tag.ClassContextSpecific || decodedTag_resultsourcediagnostic.Number != 3 || decodedTag_resultsourcediagnostic.Constructed != true {
		return fmt.Errorf("decoding result-source-diagnostic: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_resultsourcediagnostic)
	}
	_, innerUsed_resultsourcediagnostic, _, innerErr_resultsourcediagnostic := ber.DecodeTLV(innerData_resultsourcediagnostic, opts...)
	if innerErr_resultsourcediagnostic != nil {
		return fmt.Errorf("decoding result-source-diagnostic: %w", innerErr_resultsourcediagnostic)
	}
	if innerUsed_resultsourcediagnostic != len(innerData_resultsourcediagnostic) {
		return fmt.Errorf("decoding result-source-diagnostic: %w", ber.ErrExtraData)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.ResultSourceDiagnostic.UnmarshalBER(innerData_resultsourcediagnostic, ber.ChildDecodeOptions(opts, "result-source-diagnostic")...); unmErr != nil {
		return fmt.Errorf("decoding result-source-diagnostic: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_resultsourcediagnostic < 0 || n_resultsourcediagnostic >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_resultsourcediagnostic
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return fmt.Errorf("decoding user-information: %w", reconstructionErr_userinformation)
				}
				dec_userinformation, unmErr := UnmarshalBERAAREApduUserInformation(reconstructed_userinformation, ber.ChildDecodeOptions(opts, "user-information")...)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
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
func (v *RLRQApdu) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RLRQApdu receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RLRQApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Reason != nil {
		enc_reason, encodeErr_enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		if encodeErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", encodeErr_enc_reason)
		}
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", tagErr_enc_reason)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLRQApduUserInformation(v.UserInformation, ber.ChildEncodeOptions(opts, "user-information")...)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding user-information: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 2, Constructed: true}, children)
}

// MarshalDER encodes RLRQApdu to DER format.
func (v *RLRQApdu) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RLRQApdu receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Reason != nil {
		enc_reason, encodeErr_enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		if encodeErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", encodeErr_enc_reason)
		}
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding RLRQApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLRQApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RLRQApdu from BER/DER format.
func (v *RLRQApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RLRQApdu destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RLRQApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
				decodedTag_reason, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:], opts...)
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
				if offset > len(content) || n_reason < 0 || n_reason > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return fmt.Errorf("decoding user-information: %w", reconstructionErr_userinformation)
				}
				dec_userinformation, unmErr := UnmarshalBERRLRQApduUserInformation(reconstructed_userinformation, ber.ChildDecodeOptions(opts, "user-information")...)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
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
func (v *RLREApdu) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RLREApdu receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RLREApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Reason != nil {
		enc_reason, encodeErr_enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		if encodeErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", encodeErr_enc_reason)
		}
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", tagErr_enc_reason)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLREApduUserInformation(v.UserInformation, ber.ChildEncodeOptions(opts, "user-information")...)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding user-information: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 3, Constructed: true}, children)
}

// MarshalDER encodes RLREApdu to DER format.
func (v *RLREApdu) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RLREApdu receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Reason != nil {
		enc_reason, encodeErr_enc_reason := ber.EncodeBigInt((*v.Reason).BigInt())
		if encodeErr_enc_reason != nil {
			return nil, fmt.Errorf("encoding reason: %w", encodeErr_enc_reason)
		}
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 3, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding RLREApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLREApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RLREApdu from BER/DER format.
func (v *RLREApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RLREApdu destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RLREApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
				decodedTag_reason, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:], opts...)
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
				if offset > len(content) || n_reason < 0 || n_reason > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return fmt.Errorf("decoding user-information: %w", reconstructionErr_userinformation)
				}
				dec_userinformation, unmErr := UnmarshalBERRLREApduUserInformation(reconstructed_userinformation, ber.ChildDecodeOptions(opts, "user-information")...)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
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
func (v *ABRTApdu) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ABRTApdu receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ABRTApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_abortsource, encodeErr_enc_abortsource := ber.EncodeBigInt((v.AbortSource).BigInt())
	if encodeErr_enc_abortsource != nil {
		return nil, fmt.Errorf("encoding abort-source: %w", encodeErr_enc_abortsource)
	}
	retagged_enc_abortsource, tagErr_enc_abortsource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_abortsource)
	if tagErr_enc_abortsource != nil {
		return nil, fmt.Errorf("encoding abort-source: %w", tagErr_enc_abortsource)
	}
	enc_abortsource = retagged_enc_abortsource
	children = append(children, enc_abortsource...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERABRTApduUserInformation(v.UserInformation, ber.ChildEncodeOptions(opts, "user-information")...)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding user-information: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 4, Constructed: true}, children)
}

// MarshalDER encodes ABRTApdu to DER format.
func (v *ABRTApdu) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ABRTApdu receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_abortsource, encodeErr_enc_abortsource := ber.EncodeBigInt((v.AbortSource).BigInt())
	if encodeErr_enc_abortsource != nil {
		return nil, fmt.Errorf("encoding abort-source: %w", encodeErr_enc_abortsource)
	}
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ABRTApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ABRTApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ABRTApdu from BER/DER format.
func (v *ABRTApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ABRTApdu destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ABRTApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
	decodedTag_abortsource, n_abortsource, rawVal_abortsource, err := ber.DecodeTLV(content[offset:], opts...)
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
	if offset > len(content) || n_abortsource < 0 || n_abortsource > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_abortsource
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return fmt.Errorf("decoding user-information: %w", reconstructionErr_userinformation)
				}
				dec_userinformation, unmErr := UnmarshalBERABRTApduUserInformation(reconstructed_userinformation, ber.ChildDecodeOptions(opts, "user-information")...)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
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
func (v *AssociateSourceDiagnostic) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AssociateSourceDiagnostic receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AssociateSourceDiagnostic) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case AssociateSourceDiagnosticChoiceDialogueServiceUser:
		if v.DialogueServiceUser == nil {
			return nil, fmt.Errorf("%w: choice AssociateSourceDiagnostic: dialogue-service-user is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.DialogueServiceUser.BigInt())
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding dialogue-service-user: %w", encodeErr_enc_0)
		}
		{
			var encodeErr error
			enc_0, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding dialogue-service-user: %w", encodeErr)
			}
		}
		return enc_0, nil
	case AssociateSourceDiagnosticChoiceDialogueServiceProvider:
		if v.DialogueServiceProvider == nil {
			return nil, fmt.Errorf("%w: choice AssociateSourceDiagnostic: dialogue-service-provider is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeBigInt(v.DialogueServiceProvider.BigInt())
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding dialogue-service-provider: %w", encodeErr_enc_1)
		}
		{
			var encodeErr error
			enc_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding dialogue-service-provider: %w", encodeErr)
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AssociateSourceDiagnostic", v.Choice)
	}
}

// MarshalDER encodes AssociateSourceDiagnostic to DER format.
func (v *AssociateSourceDiagnostic) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AssociateSourceDiagnostic receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AssociateSourceDiagnostic as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AssociateSourceDiagnostic from BER/DER format.
func (v *AssociateSourceDiagnostic) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AssociateSourceDiagnostic destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AssociateSourceDiagnostic{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for AssociateSourceDiagnostic CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AssociateSourceDiagnostic: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding AssociateSourceDiagnostic CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AssociateSourceDiagnostic", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = AssociateSourceDiagnosticChoiceDialogueServiceUser
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogue-service-user: %w", tlvErr)
		}
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return fmt.Errorf("decoding dialogue-service-user: %w", innerErr)
		}
		if innerUsed != len(innerData) {
			return fmt.Errorf("decoding dialogue-service-user: %w", ber.ErrExtraData)
		}
		decVal, _, intErr := ber.DecodeBigInt(innerData, opts...)
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
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogue-service-provider: %w", tlvErr)
		}
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return fmt.Errorf("decoding dialogue-service-provider: %w", innerErr)
		}
		if innerUsed != len(innerData) {
			return fmt.Errorf("decoding dialogue-service-provider: %w", ber.ErrExtraData)
		}
		decVal, _, intErr := ber.DecodeBigInt(innerData, opts...)
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
func MarshalBERAARQApduUserInformation(collection *AARQApduUserInformation, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERAARQApduUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERAARQApduUserInformation(collection *AARQApduUserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERAARQApduUserInformation encodes a AARQApduUserInformation list to DER.
func MarshalDERAARQApduUserInformation(collection *AARQApduUserInformation) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AARQApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAARQApduUserInformation decodes a AARQApduUserInformation list from BER.
func UnmarshalBERAARQApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *AARQApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding AARQApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AARQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, fmt.Errorf("decoding element: %w", extErr)
		}
		result = append(result, decodedElem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &AARQApduUserInformation{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERAARQApduUserInformation(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERAAREApduUserInformation encodes a AAREApduUserInformation list to BER.
func MarshalBERAAREApduUserInformation(collection *AAREApduUserInformation, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERAAREApduUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERAAREApduUserInformation(collection *AAREApduUserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERAAREApduUserInformation encodes a AAREApduUserInformation list to DER.
func MarshalDERAAREApduUserInformation(collection *AAREApduUserInformation) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AAREApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAAREApduUserInformation decodes a AAREApduUserInformation list from BER.
func UnmarshalBERAAREApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *AAREApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding AAREApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AAREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, fmt.Errorf("decoding element: %w", extErr)
		}
		result = append(result, decodedElem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &AAREApduUserInformation{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERAAREApduUserInformation(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERRLRQApduUserInformation encodes a RLRQApduUserInformation list to BER.
func MarshalBERRLRQApduUserInformation(collection *RLRQApduUserInformation, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERRLRQApduUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERRLRQApduUserInformation(collection *RLRQApduUserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERRLRQApduUserInformation encodes a RLRQApduUserInformation list to DER.
func MarshalDERRLRQApduUserInformation(collection *RLRQApduUserInformation) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLRQApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRLRQApduUserInformation decodes a RLRQApduUserInformation list from BER.
func UnmarshalBERRLRQApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *RLRQApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding RLRQApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLRQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, fmt.Errorf("decoding element: %w", extErr)
		}
		result = append(result, decodedElem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &RLRQApduUserInformation{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERRLRQApduUserInformation(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERRLREApduUserInformation encodes a RLREApduUserInformation list to BER.
func MarshalBERRLREApduUserInformation(collection *RLREApduUserInformation, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERRLREApduUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERRLREApduUserInformation(collection *RLREApduUserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERRLREApduUserInformation encodes a RLREApduUserInformation list to DER.
func MarshalDERRLREApduUserInformation(collection *RLREApduUserInformation) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RLREApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRLREApduUserInformation decodes a RLREApduUserInformation list from BER.
func UnmarshalBERRLREApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *RLREApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding RLREApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, fmt.Errorf("decoding element: %w", extErr)
		}
		result = append(result, decodedElem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &RLREApduUserInformation{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERRLREApduUserInformation(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERABRTApduUserInformation encodes a ABRTApduUserInformation list to BER.
func MarshalBERABRTApduUserInformation(collection *ABRTApduUserInformation, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERABRTApduUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERABRTApduUserInformation(collection *ABRTApduUserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERABRTApduUserInformation encodes a ABRTApduUserInformation list to DER.
func MarshalDERABRTApduUserInformation(collection *ABRTApduUserInformation) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ABRTApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERABRTApduUserInformation decodes a ABRTApduUserInformation list from BER.
func UnmarshalBERABRTApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *ABRTApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding ABRTApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ABRTApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, fmt.Errorf("decoding element: %w", extErr)
		}
		result = append(result, decodedElem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &ABRTApduUserInformation{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERABRTApduUserInformation(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}
