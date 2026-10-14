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
func DialogueAsId() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x00\x11\x86\x05\x01\x01\x01")
}

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
			return nil, qualifyBERError(err, "dialogueRequest", "encoding", false)
		}
		return enc_0, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueResponse is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.DialogueResponse.MarshalBER(ber.ChildEncodeOptions(opts, "dialogueResponse")...)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueResponse", "encoding", false)
		}
		return enc_1, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueAbort is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.DialogueAbort.MarshalBER(ber.ChildEncodeOptions(opts, "dialogueAbort")...)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueAbort", "encoding", false)
		}
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
			return nil, qualifyBERError(err, "dialogueRequest", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "dialogueRequest", "encoding", true)
		}
		return enc_der_0, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueResponse is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.DialogueResponse.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "dialogueResponse", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "dialogueResponse", "encoding", true)
		}
		return enc_der_1, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueAbort is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.DialogueAbort.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "dialogueAbort", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "dialogueAbort", "encoding", true)
		}
		return enc_der_2, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case DialoguePDUChoiceDialogueRequest:
			return nil, qualifyBERError(err, "dialogueRequest", "encoding", true)
		case DialoguePDUChoiceDialogueResponse:
			return nil, qualifyBERError(err, "dialogueResponse", "encoding", true)
		case DialoguePDUChoiceDialogueAbort:
			return nil, qualifyBERError(err, "dialogueAbort", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding DialoguePDU as DER", qualifyBERError(err, "", "encoding", true))
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DialoguePDU
			return probe.UnmarshalBER(data, probeOpts...)
		})
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
		return fmt.Errorf("%s: %w", "decoding DialoguePDU CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DialoguePDU", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueRequest
		ber.MarkPreflightTarget(opts, "dialogueRequest", choiceData)
		var dec AARQApdu
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "dialogueRequest")...); unmErr != nil {
			return qualifyBERError(unmErr, "dialogueRequest", "decoding", false)
		}
		v.DialogueRequest = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueResponse
		ber.MarkPreflightTarget(opts, "dialogueResponse", choiceData)
		var dec AAREApdu
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "dialogueResponse")...); unmErr != nil {
			return qualifyBERError(unmErr, "dialogueResponse", "decoding", false)
		}
		v.DialogueResponse = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = DialoguePDUChoiceDialogueAbort
		ber.MarkPreflightTarget(opts, "dialogueAbort", choiceData)
		var dec ABRTApdu
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "dialogueAbort")...); unmErr != nil {
			return qualifyBERError(unmErr, "dialogueAbort", "decoding", false)
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
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", false)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", false)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked(v.ApplicationContextName)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "application-context-name", "encoding", false)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "application-context-name", "encoding", false)
		}
	}
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAARQApduUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "user-information", "encoding", false)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", false)
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
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeDERNamedBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength)
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		if string(enc_protocolversion) != "\x03\x02\a\x80" {
			retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
			if tagErr_enc_protocolversion != nil {
				return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
			}
			enc_protocolversion = retagged_enc_protocolversion
			children = append(children, enc_protocolversion...)
		}
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked(v.ApplicationContextName)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "application-context-name", "encoding", true)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "application-context-name", "encoding", true)
		}
	}
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERAARQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", true)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
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
		return nil, qualifyBERError(tagErr_encoded, "AARQApdu", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AARQApdu as DER", qualifyBERError(err, "", "encoding", true))
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AARQApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
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
		return fmt.Errorf("%s: %w", "decoding AARQApdu", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("%s: %w", "decoding AARQApdu", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 0], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "protocol-version", content[offset:])
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "protocol-version", "decoding", false)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion), "protocol-version", "decoding", false)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "protocol-version", "decoding", false)
				}
				bsBitLength_protocolversion, bsLenErr_protocolversion := ber.BitStringBitLength(len(bsBytes_protocolversion), bsUnused_protocolversion)
				if bsLenErr_protocolversion != nil {
					return qualifyBERError(bsLenErr_protocolversion, "protocol-version", "decoding", false)
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
	{
		ber.MarkPreflightTarget(opts, "application-context-name", content[offset:])
		decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "application-context-name", "decoding", false)
		}
		if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname), "application-context-name", "decoding", false)
		}
		_, innerUsed_applicationcontextname, _, innerErr_applicationcontextname := ber.DecodeTLV(innerData_applicationcontextname, opts...)
		if innerErr_applicationcontextname != nil {
			return qualifyBERError(innerErr_applicationcontextname, "application-context-name", "decoding", false)
		}
		if innerUsed_applicationcontextname != len(innerData_applicationcontextname) {
			return qualifyBERError(ber.ErrExtraData, "application-context-name", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "application-context-name", innerData_applicationcontextname)
		val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname, opts...)
		if oidErr != nil {
			return qualifyBERError(oidErr, "application-context-name", "decoding", false)
		}
		v.ApplicationContextName = val_applicationcontextname
		if offset < 0 || offset >
			len(content) || n_applicationcontextname < 0 || n_applicationcontextname >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_applicationcontextname
	}
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				ber.MarkPreflightTarget(opts, "user-information", content[offset:])
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "user-information", "decoding", false)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation), "user-information", "decoding", false)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := UnmarshalBERAARQApduUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "user-information", "decoding", false)
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
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", false)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", false)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked(v.ApplicationContextName)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "application-context-name", "encoding", false)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "application-context-name", "encoding", false)
		}
	}
	children = append(children, enc_applicationcontextname...)
	enc_result, encodeErr_enc_result := ber.EncodeBigInt((v.Result).BigInt())
	if encodeErr_enc_result != nil {
		return nil, qualifyBERError(encodeErr_enc_result, "result", "encoding", false)
	}
	{
		var encodeErr error
		enc_result, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_result)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "result", "encoding", false)
		}
	}
	children = append(children, enc_result...)
	enc_resultsourcediagnostic, err := v.ResultSourceDiagnostic.MarshalBER(ber.ChildEncodeOptions(opts, "result-source-diagnostic")...)
	if err != nil {
		return nil, qualifyBERError(err, "result-source-diagnostic", "encoding", false)
	}
	{
		var encodeErr error
		enc_resultsourcediagnostic, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_resultsourcediagnostic)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "result-source-diagnostic", "encoding", false)
		}
	}
	children = append(children, enc_resultsourcediagnostic...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAAREApduUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "user-information", "encoding", false)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", false)
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
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeDERNamedBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength)
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		if string(enc_protocolversion) != "\x03\x02\a\x80" {
			retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
			if tagErr_enc_protocolversion != nil {
				return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
			}
			enc_protocolversion = retagged_enc_protocolversion
			children = append(children, enc_protocolversion...)
		}
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked(v.ApplicationContextName)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "application-context-name", "encoding", true)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "application-context-name", "encoding", true)
		}
	}
	children = append(children, enc_applicationcontextname...)
	enc_result, encodeErr_enc_result := ber.EncodeBigInt((v.Result).BigInt())
	if encodeErr_enc_result != nil {
		return nil, qualifyBERError(encodeErr_enc_result, "result", "encoding", true)
	}
	{
		var encodeErr error
		enc_result, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_result)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "result", "encoding", true)
		}
	}
	children = append(children, enc_result...)
	enc_resultsourcediagnostic, err := v.ResultSourceDiagnostic.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "result-source-diagnostic", "encoding", true)
	}
	{
		var encodeErr error
		enc_resultsourcediagnostic, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_resultsourcediagnostic)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "result-source-diagnostic", "encoding", true)
		}
	}
	children = append(children, enc_resultsourcediagnostic...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERAAREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", true)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
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
		return nil, qualifyBERError(tagErr_encoded, "AAREApdu", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AAREApdu as DER", qualifyBERError(err, "", "encoding", true))
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AAREApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
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
		return fmt.Errorf("%s: %w", "decoding AAREApdu", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("%s: %w", "decoding AAREApdu", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 1], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "protocol-version", content[offset:])
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "protocol-version", "decoding", false)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion), "protocol-version", "decoding", false)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "protocol-version", "decoding", false)
				}
				bsBitLength_protocolversion, bsLenErr_protocolversion := ber.BitStringBitLength(len(bsBytes_protocolversion), bsUnused_protocolversion)
				if bsLenErr_protocolversion != nil {
					return qualifyBERError(bsLenErr_protocolversion, "protocol-version", "decoding", false)
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
	{
		ber.MarkPreflightTarget(opts, "application-context-name", content[offset:])
		decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "application-context-name", "decoding", false)
		}
		if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname), "application-context-name", "decoding", false)
		}
		_, innerUsed_applicationcontextname, _, innerErr_applicationcontextname := ber.DecodeTLV(innerData_applicationcontextname, opts...)
		if innerErr_applicationcontextname != nil {
			return qualifyBERError(innerErr_applicationcontextname, "application-context-name", "decoding", false)
		}
		if innerUsed_applicationcontextname != len(innerData_applicationcontextname) {
			return qualifyBERError(ber.ErrExtraData, "application-context-name", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "application-context-name", innerData_applicationcontextname)
		val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname, opts...)
		if oidErr != nil {
			return qualifyBERError(oidErr, "application-context-name", "decoding", false)
		}
		v.ApplicationContextName = val_applicationcontextname
		if offset < 0 || offset >
			len(content) || n_applicationcontextname < 0 || n_applicationcontextname >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_applicationcontextname
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for result, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		decodedTag_result, n_result, innerData_result, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "result", "decoding", false)
		}
		if decodedTag_result.Class != tag.ClassContextSpecific || decodedTag_result.Number != 2 || decodedTag_result.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_result), "result", "decoding", false)
		}
		_, innerUsed_result, _, innerErr_result := ber.DecodeTLV(innerData_result, opts...)
		if innerErr_result != nil {
			return qualifyBERError(innerErr_result, "result", "decoding", false)
		}
		if innerUsed_result != len(innerData_result) {
			return qualifyBERError(ber.ErrExtraData, "result", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "result", innerData_result)
		val_result, _, err := ber.DecodeBigInt(innerData_result, opts...)
		if err != nil {
			return qualifyBERError(err, "result", "decoding", false)
		}
		var named_result AssociateResult
		if namedErr := named_result.UnmarshalText([]byte(val_result.String())); namedErr != nil {
			return qualifyBERError(namedErr, "result", "decoding", false)
		}
		v.Result = named_result
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	// Decode result-source-diagnostic
	if offset >= len(content) {
		return fmt.Errorf("missing required field result-source-diagnostic")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for result-source-diagnostic, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "result-source-diagnostic", content[offset:])
		decodedTag_resultsourcediagnostic, n_resultsourcediagnostic, innerData_resultsourcediagnostic, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "result-source-diagnostic", "decoding", false)
		}
		if decodedTag_resultsourcediagnostic.Class != tag.ClassContextSpecific || decodedTag_resultsourcediagnostic.Number != 3 || decodedTag_resultsourcediagnostic.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_resultsourcediagnostic), "result-source-diagnostic", "decoding", false)
		}
		_, innerUsed_resultsourcediagnostic, _, innerErr_resultsourcediagnostic := ber.DecodeTLV(innerData_resultsourcediagnostic, opts...)
		if innerErr_resultsourcediagnostic != nil {
			return qualifyBERError(innerErr_resultsourcediagnostic, "result-source-diagnostic", "decoding", false)
		}
		if innerUsed_resultsourcediagnostic != len(innerData_resultsourcediagnostic) {
			return qualifyBERError(ber.ErrExtraData, "result-source-diagnostic", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "result-source-diagnostic", innerData_resultsourcediagnostic)
		if unmErr := v.ResultSourceDiagnostic.UnmarshalBER(innerData_resultsourcediagnostic, ber.ChildDecodeOptions(opts, "result-source-diagnostic")...); unmErr != nil {
			return qualifyBERError(unmErr, "result-source-diagnostic", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_resultsourcediagnostic < 0 || n_resultsourcediagnostic >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_resultsourcediagnostic
	}
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				ber.MarkPreflightTarget(opts, "user-information", content[offset:])
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "user-information", "decoding", false)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation), "user-information", "decoding", false)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := UnmarshalBERAAREApduUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "user-information", "decoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_reason, "reason", "encoding", false)
		}
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, qualifyBERError(tagErr_enc_reason, "reason", "encoding", false)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLRQApduUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "user-information", "encoding", false)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_reason, "reason", "encoding", true)
		}
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, qualifyBERError(tagErr_enc_reason, "reason", "encoding", true)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERRLRQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", true)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
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
		return nil, qualifyBERError(tagErr_encoded, "RLRQApdu", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RLRQApdu as DER", qualifyBERError(err, "", "encoding", true))
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RLRQApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
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
		return fmt.Errorf("%s: %w", "decoding RLRQApdu", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 2 || !decodedTag.Constructed {
		return fmt.Errorf("%s: %w", "decoding RLRQApdu", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 2], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "reason", content[offset:])
				decodedTag_reason, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reason", "decoding", false)
				}
				if decodedTag_reason.Class != tag.ClassContextSpecific || decodedTag_reason.Number != 0 || decodedTag_reason.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reason), "reason", "decoding", false)
				}
				decVal_reason, intErr := ber.DecodeBigIntValue(rawVal_reason)
				if intErr != nil {
					return qualifyBERError(intErr, "reason", "decoding", false)
				}
				var named_reason ReleaseRequestReason
				if namedErr := named_reason.UnmarshalText([]byte(decVal_reason.String())); namedErr != nil {
					return qualifyBERError(namedErr, "reason", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "user-information", content[offset:])
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "user-information", "decoding", false)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation), "user-information", "decoding", false)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := UnmarshalBERRLRQApduUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "user-information", "decoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_reason, "reason", "encoding", false)
		}
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, qualifyBERError(tagErr_enc_reason, "reason", "encoding", false)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLREApduUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "user-information", "encoding", false)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_reason, "reason", "encoding", true)
		}
		retagged_enc_reason, tagErr_enc_reason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reason)
		if tagErr_enc_reason != nil {
			return nil, qualifyBERError(tagErr_enc_reason, "reason", "encoding", true)
		}
		enc_reason = retagged_enc_reason
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERRLREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", true)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
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
		return nil, qualifyBERError(tagErr_encoded, "RLREApdu", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RLREApdu as DER", qualifyBERError(err, "", "encoding", true))
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RLREApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
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
		return fmt.Errorf("%s: %w", "decoding RLREApdu", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("%s: %w", "decoding RLREApdu", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 3], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "reason", content[offset:])
				decodedTag_reason, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reason", "decoding", false)
				}
				if decodedTag_reason.Class != tag.ClassContextSpecific || decodedTag_reason.Number != 0 || decodedTag_reason.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reason), "reason", "decoding", false)
				}
				decVal_reason, intErr := ber.DecodeBigIntValue(rawVal_reason)
				if intErr != nil {
					return qualifyBERError(intErr, "reason", "decoding", false)
				}
				var named_reason ReleaseResponseReason
				if namedErr := named_reason.UnmarshalText([]byte(decVal_reason.String())); namedErr != nil {
					return qualifyBERError(namedErr, "reason", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "user-information", content[offset:])
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "user-information", "decoding", false)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation), "user-information", "decoding", false)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := UnmarshalBERRLREApduUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "user-information", "decoding", false)
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
		return nil, qualifyBERError(encodeErr_enc_abortsource, "abort-source", "encoding", false)
	}
	retagged_enc_abortsource, tagErr_enc_abortsource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_abortsource)
	if tagErr_enc_abortsource != nil {
		return nil, qualifyBERError(tagErr_enc_abortsource, "abort-source", "encoding", false)
	}
	enc_abortsource = retagged_enc_abortsource
	children = append(children, enc_abortsource...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERABRTApduUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "user-information", "encoding", false)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", false)
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
		return nil, qualifyBERError(encodeErr_enc_abortsource, "abort-source", "encoding", true)
	}
	retagged_enc_abortsource, tagErr_enc_abortsource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_abortsource)
	if tagErr_enc_abortsource != nil {
		return nil, qualifyBERError(tagErr_enc_abortsource, "abort-source", "encoding", true)
	}
	enc_abortsource = retagged_enc_abortsource
	children = append(children, enc_abortsource...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERABRTApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", true)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
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
		return nil, qualifyBERError(tagErr_encoded, "ABRTApdu", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ABRTApdu as DER", qualifyBERError(err, "", "encoding", true))
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ABRTApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
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
		return fmt.Errorf("%s: %w", "decoding ABRTApdu", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 4 || !decodedTag.Constructed {
		return fmt.Errorf("%s: %w", "decoding ABRTApdu", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 4], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "abort-source", content[offset:])
		decodedTag_abortsource, n_abortsource, rawVal_abortsource, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "abort-source", "decoding", false)
		}
		if decodedTag_abortsource.Class != tag.ClassContextSpecific || decodedTag_abortsource.Number != 0 || decodedTag_abortsource.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_abortsource), "abort-source", "decoding", false)
		}
		decVal_abortsource, intErr := ber.DecodeBigIntValue(rawVal_abortsource)
		if intErr != nil {
			return qualifyBERError(intErr, "abort-source", "decoding", false)
		}
		var named_abortsource ABRTSource
		if namedErr := named_abortsource.UnmarshalText([]byte(decVal_abortsource.String())); namedErr != nil {
			return qualifyBERError(namedErr, "abort-source", "decoding", false)
		}
		v.AbortSource = named_abortsource
		if offset > len(content) || n_abortsource < 0 || n_abortsource > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_abortsource
	}
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				ber.MarkPreflightTarget(opts, "user-information", content[offset:])
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "user-information", "decoding", false)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation), "user-information", "decoding", false)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := UnmarshalBERABRTApduUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "user-information", "decoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_0, "dialogue-service-user", "encoding", false)
		}
		{
			var encodeErr error
			enc_0, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "dialogue-service-user", "encoding", false)
			}
		}
		return enc_0, nil
	case AssociateSourceDiagnosticChoiceDialogueServiceProvider:
		if v.DialogueServiceProvider == nil {
			return nil, fmt.Errorf("%w: choice AssociateSourceDiagnostic: dialogue-service-provider is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeBigInt(v.DialogueServiceProvider.BigInt())
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "dialogue-service-provider", "encoding", false)
		}
		{
			var encodeErr error
			enc_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "dialogue-service-provider", "encoding", false)
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
		switch v.Choice {
		case AssociateSourceDiagnosticChoiceDialogueServiceUser:
			return nil, qualifyBERError(err, "dialogue-service-user", "encoding", true)
		case AssociateSourceDiagnosticChoiceDialogueServiceProvider:
			return nil, qualifyBERError(err, "dialogue-service-provider", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding AssociateSourceDiagnostic as DER", qualifyBERError(err, "", "encoding", true))
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AssociateSourceDiagnostic
			return probe.UnmarshalBER(data, probeOpts...)
		})
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
		return fmt.Errorf("%s: %w", "decoding AssociateSourceDiagnostic CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AssociateSourceDiagnostic", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = AssociateSourceDiagnosticChoiceDialogueServiceUser
		ber.MarkPreflightTarget(opts, "dialogue-service-user", choiceData)
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "dialogue-service-user", "decoding", false)
		}
		ber.MarkPreflightTarget(opts, "dialogue-service-user", innerData)
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return qualifyBERError(innerErr, "dialogue-service-user", "decoding", false)
		}
		if innerUsed != len(innerData) {
			return qualifyBERError(ber.ErrExtraData, "dialogue-service-user", "decoding", false)
		}
		decVal, _, intErr := ber.DecodeBigInt(innerData, opts...)
		if intErr != nil {
			return qualifyBERError(intErr, "dialogue-service-user", "decoding", false)
		}
		var named_dialogueserviceuser AssociateSourceDiagnosticDialogueServiceUserValue
		if namedErr := named_dialogueserviceuser.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return qualifyBERError(namedErr, "dialogue-service-user", "decoding", false)
		}
		v.DialogueServiceUser = &named_dialogueserviceuser
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = AssociateSourceDiagnosticChoiceDialogueServiceProvider
		ber.MarkPreflightTarget(opts, "dialogue-service-provider", choiceData)
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "dialogue-service-provider", "decoding", false)
		}
		ber.MarkPreflightTarget(opts, "dialogue-service-provider", innerData)
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return qualifyBERError(innerErr, "dialogue-service-provider", "decoding", false)
		}
		if innerUsed != len(innerData) {
			return qualifyBERError(ber.ErrExtraData, "dialogue-service-provider", "decoding", false)
		}
		decVal, _, intErr := ber.DecodeBigInt(innerData, opts...)
		if intErr != nil {
			return qualifyBERError(intErr, "dialogue-service-provider", "decoding", false)
		}
		var named_dialogueserviceprovider AssociateSourceDiagnosticDialogueServiceProviderValue
		if namedErr := named_dialogueserviceprovider.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return qualifyBERError(namedErr, "dialogue-service-provider", "decoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem), ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AARQApduUserInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERAARQApduUserInformation decodes a AARQApduUserInformation list from BER.
func UnmarshalBERAARQApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *AARQApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERAARQApduUserInformation(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding AARQApduUserInformation", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AARQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem), ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AAREApduUserInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERAAREApduUserInformation decodes a AAREApduUserInformation list from BER.
func UnmarshalBERAAREApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *AAREApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERAAREApduUserInformation(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding AAREApduUserInformation", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AAREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem), ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RLRQApduUserInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERRLRQApduUserInformation decodes a RLRQApduUserInformation list from BER.
func UnmarshalBERRLRQApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *RLRQApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERRLRQApduUserInformation(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding RLRQApduUserInformation", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLRQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem), ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RLREApduUserInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERRLREApduUserInformation decodes a RLREApduUserInformation list from BER.
func UnmarshalBERRLREApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *RLREApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERRLREApduUserInformation(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding RLREApduUserInformation", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem), ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
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
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ABRTApduUserInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERABRTApduUserInformation decodes a ABRTApduUserInformation list from BER.
func UnmarshalBERABRTApduUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *ABRTApduUserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERABRTApduUserInformation(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding ABRTApduUserInformation", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ABRTApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		decodedElem, n, extErr := ber.DecodeExternal(elementData, opts...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
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
