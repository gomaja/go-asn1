// Code generated from ASN.1 module "DialoguePDUs". DO NOT EDIT.

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
	berReplayNode_   *ber.ReplayNode `json:"-"`
	DialogueRequest  *AARQApdu       `json:"DialogueRequest,omitempty"`
	DialogueResponse *AAREApdu       `json:"DialogueResponse,omitempty"`
	DialogueAbort    *ABRTApdu       `json:"DialogueAbort,omitempty"`
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
	ProtocolVersion            *runtime.BitString       `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName     runtime.ObjectIdentifier `asn1:"tag:1,context,explicit"`
	UserInformation            *UserInformation         `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	berUserInformationIndef_   bool                     `asn1:"-" json:"-"`
	berReplayNode_             *ber.ReplayNode          `asn1:"-" json:"-"`
	berProtocolVersionPresent_ bool
}

const (
	// AARQApduProtocolVersionVersion1 is position 0 of ASN.1 named bit version1 of AARQ-apdu.protocol-version (ITU-T X.680 (02/2021) §22).
	AARQApduProtocolVersionVersion1 = 0
)

// AAREApdu represents the ASN.1 type AARE-apdu (SEQUENCE).
type AAREApdu struct {
	ProtocolVersion            *runtime.BitString        `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName     runtime.ObjectIdentifier  `asn1:"tag:1,context,explicit"`
	Result                     AssociateResult           `asn1:"tag:2,context,explicit"`
	ResultSourceDiagnostic     AssociateSourceDiagnostic `asn1:"tag:3,context,explicit"`
	UserInformation            *UserInformation          `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	berUserInformationIndef_   bool                      `asn1:"-" json:"-"`
	berReplayNode_             *ber.ReplayNode           `asn1:"-" json:"-"`
	berProtocolVersionPresent_ bool
}

const (
	// AAREApduProtocolVersionVersion1 is position 0 of ASN.1 named bit version1 of AARE-apdu.protocol-version (ITU-T X.680 (02/2021) §22).
	AAREApduProtocolVersionVersion1 = 0
)

// RLRQApdu represents the ASN.1 type RLRQ-apdu (SEQUENCE).
type RLRQApdu struct {
	Reason                   *ReleaseRequestReason `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation          *UserInformation      `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	berUserInformationIndef_ bool                  `asn1:"-" json:"-"`
	berReplayNode_           *ber.ReplayNode       `asn1:"-" json:"-"`
}

// RLREApdu represents the ASN.1 type RLRE-apdu (SEQUENCE).
type RLREApdu struct {
	Reason                   *ReleaseResponseReason `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation          *UserInformation       `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	berUserInformationIndef_ bool                   `asn1:"-" json:"-"`
	berReplayNode_           *ber.ReplayNode        `asn1:"-" json:"-"`
}

// ABRTApdu represents the ASN.1 type ABRT-apdu (SEQUENCE).
type ABRTApdu struct {
	AbortSource              ABRTSource       `asn1:"tag:0,context,implicit"`
	UserInformation          *UserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	berUserInformationIndef_ bool             `asn1:"-" json:"-"`
	berReplayNode_           *ber.ReplayNode  `asn1:"-" json:"-"`
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
	berReplayNode_          *ber.ReplayNode                                        `json:"-"`
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
// UserInformation represents the ASN.1 type UserInformation (SEQUENCE_OF).
type UserInformation struct {
	Values         []runtime.External `json:"Values"`
	berReplayNode_ *ber.ReplayNode    `json:"-"`
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
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "DialoguePDU", "DialoguePDUs", "DialoguePDU")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: DialoguePDU receiver is nil", ber.ErrInvalidValue)
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
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == DialoguePDUChoiceDialogueRequest || v.Choice == DialoguePDUChoiceDialogueResponse || v.Choice == DialoguePDUChoiceDialogueAbort) {
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
func (v *DialoguePDU) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: DialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case DialoguePDUChoiceDialogueRequest:
		if v.DialogueRequest == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueRequest is nil", ber.ErrInvalidValue)
		}
		_, err := v.DialogueRequest.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "dialogueRequest")...)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueRequest", "encoding", true)
		}
		return nil, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueResponse is nil", ber.ErrInvalidValue)
		}
		_, err := v.DialogueResponse.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "dialogueResponse")...)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueResponse", "encoding", true)
		}
		return nil, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueAbort is nil", ber.ErrInvalidValue)
		}
		_, err := v.DialogueAbort.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "dialogueAbort")...)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueAbort", "encoding", true)
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
func (v *DialoguePDU) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: DialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == DialoguePDUChoiceDialogueRequest || v.Choice == DialoguePDUChoiceDialogueResponse || v.Choice == DialoguePDUChoiceDialogueAbort {
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

func (v *DialoguePDU) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: DialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case DialoguePDUChoiceDialogueRequest:
		if v.DialogueRequest == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueRequest is nil", ber.ErrInvalidValue)
		}
		_, err := v.DialogueRequest.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueRequest", "encoding", true)
		}
		return nil, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueResponse is nil", ber.ErrInvalidValue)
		}
		_, err := v.DialogueResponse.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueResponse", "encoding", true)
		}
		return nil, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("%w: choice DialoguePDU: dialogueAbort is nil", ber.ErrInvalidValue)
		}
		_, err := v.DialogueAbort.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "dialogueAbort", "encoding", true)
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

// UnmarshalBER decodes DialoguePDU from BER/DER format.
func (destination *DialoguePDU) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil DialoguePDU destination")
	}
	var next DialoguePDU

	v := &next
	defer func() {
		if returnErr == nil {
			*destination =
				*v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "DialoguePDU", "DialoguePDUs", "DialoguePDU")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *DialoguePDU, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DialoguePDU
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.DialoguePDU", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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

	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "DialoguePDU.dialogueRequest", "decoding", false)
	}
	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "DialoguePDU.dialogueResponse", "decoding", false)
	}
	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "DialoguePDU.dialogueAbort", "decoding", false)
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
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "AARQApdu", "DialoguePDUs", "AARQ-apdu")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: AARQApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *AARQApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
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
		enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berUserInformationIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_userinformation)
		children = append(children, enc_userinformation...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, children)
}
func (v *AARQApdu) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AARQApdu receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 0})
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		enc_protocolversion = retagged_enc_protocolversion
		encoder.Append(enc_protocolversion)
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
	encoder.Append(enc_applicationcontextname)
	if v.UserInformation != nil {
		if v.berUserInformationIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_ {
				// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
				_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "user-information", "encoding", true)
					}
				}
			} else {
				retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
				if tagErr_enc_userinformation != nil {
					return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
				}
				enc_userinformation = retagged_enc_userinformation
			}
			encoder.Append(enc_userinformation)
		} else {
			{
				encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_)
				_, err := appendBERLinearUserInformation(encoder, v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
				if err != nil {
					return nil, qualifyBERError(err, "user-information", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes AARQApdu to DER format.
func (v *AARQApdu) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: AARQApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *AARQApdu) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AARQApdu receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 0})
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPNamedBitStringDER(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength)
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		if string(enc_protocolversion) != "\x03\x02\a\x80" {
			retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
			if tagErr_enc_protocolversion != nil {
				return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
			}
			enc_protocolversion = retagged_enc_protocolversion
			encoder.Append(enc_protocolversion)
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
	encoder.Append(enc_applicationcontextname)
	if v.UserInformation != nil {
		{
			encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, false)
			_, err := appendDERLinearUserInformation(encoder, v.UserInformation)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes AARQApdu from BER/DER format.
func (destination *AARQApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil AARQApdu destination")
	}
	var next AARQApdu
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "AARQApdu", "DialoguePDUs", "AARQ-apdu")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AARQApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.AARQ-apdu", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AARQApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *AARQApdu, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
				v.berProtocolVersionPresent_ = v.ProtocolVersion !=
					nil
				if v.ProtocolVersion !=
					nil &&
					v.ProtocolVersion.
						EqualBits("\x80", 1, true) {
					ber.MarkBERNonCanonical(opts)
				}

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
	v.berUserInformationIndef_ = false
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
				_ = rawVal_userinformation
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_userinformation])
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := tcapUnmarshalBERUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
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
						v.berUserInformationIndef_ = true
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
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "AAREApdu", "DialoguePDUs", "AARE-apdu")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: AAREApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *AAREApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
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
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_resultsourcediagnostic)
	children = append(children, enc_resultsourcediagnostic...)
	if v.UserInformation != nil {
		enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berUserInformationIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_userinformation)
		children = append(children, enc_userinformation...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 1, Constructed: true}, children)
}
func (v *AAREApdu) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AAREApdu receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 1})
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		enc_protocolversion = retagged_enc_protocolversion
		encoder.Append(enc_protocolversion)
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
	encoder.Append(enc_applicationcontextname)
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
	encoder.Append(enc_result)
	{
		linearTagFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassContextSpecific, Number: 3})
		_, err := v.ResultSourceDiagnostic.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "result-source-diagnostic")...)
		if err != nil {
			return nil, qualifyBERError(err, "result-source-diagnostic", "encoding", true)
		}
		if err := encoder.End(linearTagFrame_); err != nil {
			return nil, err
		}
	}
	if v.UserInformation != nil {
		if v.berUserInformationIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_ {
				// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
				_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "user-information", "encoding", true)
					}
				}
			} else {
				retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
				if tagErr_enc_userinformation != nil {
					return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
				}
				enc_userinformation = retagged_enc_userinformation
			}
			encoder.Append(enc_userinformation)
		} else {
			{
				encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_)
				_, err := appendBERLinearUserInformation(encoder, v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
				if err != nil {
					return nil, qualifyBERError(err, "user-information", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes AAREApdu to DER format.
func (v *AAREApdu) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: AAREApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *AAREApdu) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AAREApdu receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 1})
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPNamedBitStringDER(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength)
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		if string(enc_protocolversion) != "\x03\x02\a\x80" {
			retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
			if tagErr_enc_protocolversion != nil {
				return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
			}
			enc_protocolversion = retagged_enc_protocolversion
			encoder.Append(enc_protocolversion)
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
	encoder.Append(enc_applicationcontextname)
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
	encoder.Append(enc_result)
	{
		linearTagFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassContextSpecific, Number: 3})
		_, err := v.ResultSourceDiagnostic.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "result-source-diagnostic", "encoding", true)
		}
		if err := encoder.End(linearTagFrame_); err != nil {
			return nil, err
		}
	}
	if v.UserInformation != nil {
		{
			encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, false)
			_, err := appendDERLinearUserInformation(encoder, v.UserInformation)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes AAREApdu from BER/DER format.
func (destination *AAREApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil AAREApdu destination")
	}
	var next AAREApdu
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "AAREApdu", "DialoguePDUs", "AARE-apdu")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AAREApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.AARE-apdu", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AAREApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *AAREApdu, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
				v.berProtocolVersionPresent_ = v.ProtocolVersion !=
					nil
				if v.ProtocolVersion !=
					nil &&
					v.ProtocolVersion.
						EqualBits("\x80", 1, true) {
					ber.MarkBERNonCanonical(opts)
				}

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
	v.berUserInformationIndef_ = false
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
				_ = rawVal_userinformation
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_userinformation])
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := tcapUnmarshalBERUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
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
						v.berUserInformationIndef_ = true
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
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "RLRQApdu", "DialoguePDUs", "RLRQ-apdu")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: RLRQApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *RLRQApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berUserInformationIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_userinformation)
		children = append(children, enc_userinformation...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 2, Constructed: true}, children)
}
func (v *RLRQApdu) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RLRQApdu receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 2})
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
		encoder.Append(enc_reason)
	}
	if v.UserInformation != nil {
		if v.berUserInformationIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_ {
				// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
				_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "user-information", "encoding", true)
					}
				}
			} else {
				retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
				if tagErr_enc_userinformation != nil {
					return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
				}
				enc_userinformation = retagged_enc_userinformation
			}
			encoder.Append(enc_userinformation)
		} else {
			{
				encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_)
				_, err := appendBERLinearUserInformation(encoder, v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
				if err != nil {
					return nil, qualifyBERError(err, "user-information", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes RLRQApdu to DER format.
func (v *RLRQApdu) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: RLRQApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *RLRQApdu) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RLRQApdu receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 2})
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
		encoder.Append(enc_reason)
	}
	if v.UserInformation != nil {
		{
			encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, false)
			_, err := appendDERLinearUserInformation(encoder, v.UserInformation)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes RLRQApdu from BER/DER format.
func (destination *RLRQApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil RLRQApdu destination")
	}
	var next RLRQApdu
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "RLRQApdu", "DialoguePDUs", "RLRQ-apdu")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RLRQApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.RLRQ-apdu", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RLRQApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *RLRQApdu, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
	v.berUserInformationIndef_ = false
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
				_ = rawVal_userinformation
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_userinformation])
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := tcapUnmarshalBERUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
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
						v.berUserInformationIndef_ = true
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
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "RLREApdu", "DialoguePDUs", "RLRE-apdu")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: RLREApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *RLREApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berUserInformationIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_userinformation)
		children = append(children, enc_userinformation...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 3, Constructed: true}, children)
}
func (v *RLREApdu) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RLREApdu receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 3})
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
		encoder.Append(enc_reason)
	}
	if v.UserInformation != nil {
		if v.berUserInformationIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_ {
				// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
				_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "user-information", "encoding", true)
					}
				}
			} else {
				retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
				if tagErr_enc_userinformation != nil {
					return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
				}
				enc_userinformation = retagged_enc_userinformation
			}
			encoder.Append(enc_userinformation)
		} else {
			{
				encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_)
				_, err := appendBERLinearUserInformation(encoder, v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
				if err != nil {
					return nil, qualifyBERError(err, "user-information", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes RLREApdu to DER format.
func (v *RLREApdu) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: RLREApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *RLREApdu) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RLREApdu receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 3})
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
		encoder.Append(enc_reason)
	}
	if v.UserInformation != nil {
		{
			encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, false)
			_, err := appendDERLinearUserInformation(encoder, v.UserInformation)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes RLREApdu from BER/DER format.
func (destination *RLREApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil RLREApdu destination")
	}
	var next RLREApdu
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "RLREApdu", "DialoguePDUs", "RLRE-apdu")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RLREApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.RLRE-apdu", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RLREApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *RLREApdu, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
	v.berUserInformationIndef_ = false
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
				_ = rawVal_userinformation
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_userinformation])
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := tcapUnmarshalBERUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
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
						v.berUserInformationIndef_ = true
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
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ABRTApdu", "DialoguePDUs", "ABRT-apdu")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ABRTApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *ABRTApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berUserInformationIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_userinformation)
		children = append(children, enc_userinformation...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 4, Constructed: true}, children)
}
func (v *ABRTApdu) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ABRTApdu receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 4})
	enc_abortsource, encodeErr_enc_abortsource := ber.EncodeBigInt((v.AbortSource).BigInt())
	if encodeErr_enc_abortsource != nil {
		return nil, qualifyBERError(encodeErr_enc_abortsource, "abort-source", "encoding", true)
	}
	retagged_enc_abortsource, tagErr_enc_abortsource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_abortsource)
	if tagErr_enc_abortsource != nil {
		return nil, qualifyBERError(tagErr_enc_abortsource, "abort-source", "encoding", true)
	}
	enc_abortsource = retagged_enc_abortsource
	encoder.Append(enc_abortsource)
	if v.UserInformation != nil {
		if v.berUserInformationIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_ {
				// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
				_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "user-information", "encoding", true)
					}
				}
			} else {
				retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
				if tagErr_enc_userinformation != nil {
					return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
				}
				enc_userinformation = retagged_enc_userinformation
			}
			encoder.Append(enc_userinformation)
		} else {
			{
				encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_)
				_, err := appendBERLinearUserInformation(encoder, v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
				if err != nil {
					return nil, qualifyBERError(err, "user-information", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes ABRTApdu to DER format.
func (v *ABRTApdu) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ABRTApdu receiver is nil", ber.ErrInvalidValue)
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
func (v *ABRTApdu) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ABRTApdu receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 4})
	enc_abortsource, encodeErr_enc_abortsource := ber.EncodeBigInt((v.AbortSource).BigInt())
	if encodeErr_enc_abortsource != nil {
		return nil, qualifyBERError(encodeErr_enc_abortsource, "abort-source", "encoding", true)
	}
	retagged_enc_abortsource, tagErr_enc_abortsource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_abortsource)
	if tagErr_enc_abortsource != nil {
		return nil, qualifyBERError(tagErr_enc_abortsource, "abort-source", "encoding", true)
	}
	enc_abortsource = retagged_enc_abortsource
	encoder.Append(enc_abortsource)
	if v.UserInformation != nil {
		{
			encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, false)
			_, err := appendDERLinearUserInformation(encoder, v.UserInformation)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes ABRTApdu from BER/DER format.
func (destination *ABRTApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ABRTApdu destination")
	}
	var next ABRTApdu
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ABRTApdu", "DialoguePDUs", "ABRT-apdu")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ABRTApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.ABRT-apdu", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ABRTApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ABRTApdu, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
	v.berUserInformationIndef_ = false
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
				_ = rawVal_userinformation
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_userinformation])
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := tcapUnmarshalBERUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
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
						v.berUserInformationIndef_ = true
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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AssociateSourceDiagnostic receiver is nil", ber.ErrInvalidValue)
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
func (v *AssociateSourceDiagnostic) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
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
func (v *AssociateSourceDiagnostic) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

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

func (v *AssociateSourceDiagnostic) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
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

// UnmarshalBER decodes AssociateSourceDiagnostic from BER/DER format.
func (destination *AssociateSourceDiagnostic) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil AssociateSourceDiagnostic destination")
	}
	var next AssociateSourceDiagnostic
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "AssociateSourceDiagnostic", "DialoguePDUs", "Associate-source-diagnostic")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *AssociateSourceDiagnostic, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AssociateSourceDiagnostic
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.Associate-source-diagnostic", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "AssociateSourceDiagnostic.dialogue-service-user", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "AssociateSourceDiagnostic.dialogue-service-provider", "decoding", false)
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

// MarshalBERUserInformation encodes a UserInformation list to BER.
func tcapMarshalBERUserInformation(collection *UserInformation, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	if collection.berReplayNode_ == nil {
		return marshalBERUserInformation(collection, opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(collection.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) {
		return tcapMarshalBERUserInformation(collection, []ber.EncodeOption{mode}...)
	}, collection)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(collection.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := marshalBERUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, collection.berReplayNode_, opts), nil
}
func marshalBERUserInformation(collection *UserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := encodeTCAPExternal(runtime.External(elem), ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearUserInformation(encoder *ber.LinearEncoder, collection *UserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := tcapMarshalBERUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERUserInformation encodes a UserInformation list to DER.
func tcapMarshalDERUserInformation(collection *UserInformation) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		encodedElem, extErr := encodeTCAPExternalDER(runtime.External(elem))
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
		return nil, fmt.Errorf("%s: %w", "encoding UserInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearUserInformation(encoder *ber.LinearEncoder, collection *UserInformation) ([]byte, error) {
	encoded, err := tcapMarshalDERUserInformation(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERUserInformation decodes a UserInformation list from BER.
func tcapUnmarshalBERUserInformation(data []byte, opts ...ber.DecodeOption) (returnValue *UserInformation, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "UserInformation", "DialoguePDUs", "UserInformation")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := tcapUnmarshalBERUserInformation(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "DialoguePDUs.UserInformation", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding UserInformation", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "UserInformation", Cause: ber.ErrExtraData}
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
	decoded := &UserInformation{Values: result}
	if ber.BERNeedsPreservation(opts) {
		decoded.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if replayErr := ber.CompleteGeneratedBERDecode(opts, decoded, func(base *UserInformation, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return tcapMarshalBERUserInformation(base, replayOpts...)
		}); replayErr != nil {
			return nil, replayErr
		}
	}
	return decoded, nil
}
func (v *AssociateSourceDiagnostic) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil AssociateSourceDiagnostic CHOICE")
	}
	count := 0
	if v.DialogueServiceUser != nil {
		count++
	}
	if v.DialogueServiceProvider != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.DialogueServiceUser == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.DialogueServiceProvider == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *DialoguePDU) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil DialoguePDU CHOICE")
	}
	count := 0
	if v.DialogueRequest != nil {
		count++
	}
	if v.DialogueResponse != nil {
		count++
	}
	if v.DialogueAbort != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.DialogueRequest == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.DialogueResponse == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.DialogueAbort == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *AAREApdu) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if v.ProtocolVersion != nil {
		if err := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); err != nil {
			return err
		}
	}
	if err := validateTCAPStructureValue(&v.Result); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(&v.ResultSourceDiagnostic); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.UserInformation); err != nil {
		return err
	}
	return nil
}
func (v *AAREApdu) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if v.berReplayNode_ != nil && (v.ProtocolVersion != nil) != v.berProtocolVersionPresent_ {
		return true
	}
	if hasTCAPPresenceEditValue(&v.Result) {
		return true
	}
	if hasTCAPPresenceEditValue(&v.ResultSourceDiagnostic) {
		return true
	}
	if hasTCAPPresenceEditValue(v.UserInformation) {
		return true
	}
	return false
}
func (v AAREApdu) equalTCAPValue(other any) bool {
	right, ok := other.(AAREApdu)
	if !ok {
		return false
	}
	_ = right
	if (v.ProtocolVersion == nil) != (right.ProtocolVersion == nil) {
		return false
	}
	if v.ProtocolVersion != nil && !equalTCAPValue(*v.ProtocolVersion, *right.ProtocolVersion) {
		return false
	}
	if !equalTCAPValue(v.ApplicationContextName, right.ApplicationContextName) {
		return false
	}
	if !equalTCAPValue(v.Result, right.Result) {
		return false
	}
	if !equalTCAPValue(v.ResultSourceDiagnostic, right.ResultSourceDiagnostic) {
		return false
	}
	if (v.UserInformation == nil) != (right.UserInformation == nil) {
		return false
	}
	if v.UserInformation != nil && !equalTCAPValue(*v.UserInformation, *right.UserInformation) {
		return false
	}
	return true
}
func (v *AARQApdu) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if v.ProtocolVersion != nil {
		if err := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); err != nil {
			return err
		}
	}
	if err := validateTCAPStructureValue(v.UserInformation); err != nil {
		return err
	}
	return nil
}
func (v *AARQApdu) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if v.berReplayNode_ != nil && (v.ProtocolVersion != nil) != v.berProtocolVersionPresent_ {
		return true
	}
	if hasTCAPPresenceEditValue(v.UserInformation) {
		return true
	}
	return false
}
func (v AARQApdu) equalTCAPValue(other any) bool {
	right, ok := other.(AARQApdu)
	if !ok {
		return false
	}
	_ = right
	if (v.ProtocolVersion == nil) != (right.ProtocolVersion == nil) {
		return false
	}
	if v.ProtocolVersion != nil && !equalTCAPValue(*v.ProtocolVersion, *right.ProtocolVersion) {
		return false
	}
	if !equalTCAPValue(v.ApplicationContextName, right.ApplicationContextName) {
		return false
	}
	if (v.UserInformation == nil) != (right.UserInformation == nil) {
		return false
	}
	if v.UserInformation != nil && !equalTCAPValue(*v.UserInformation, *right.UserInformation) {
		return false
	}
	return true
}
func (v *ABRTApdu) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.AbortSource); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.UserInformation); err != nil {
		return err
	}
	return nil
}
func (v *ABRTApdu) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.AbortSource) {
		return true
	}
	if hasTCAPPresenceEditValue(v.UserInformation) {
		return true
	}
	return false
}
func (v ABRTApdu) equalTCAPValue(other any) bool {
	right, ok := other.(ABRTApdu)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.AbortSource, right.AbortSource) {
		return false
	}
	if (v.UserInformation == nil) != (right.UserInformation == nil) {
		return false
	}
	if v.UserInformation != nil && !equalTCAPValue(*v.UserInformation, *right.UserInformation) {
		return false
	}
	return true
}
func (v *ABRTSource) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *ABRTSource) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v ABRTSource) equalTCAPValue(other any) bool {
	right, ok := other.(ABRTSource)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *AssociateResult) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *AssociateResult) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v AssociateResult) equalTCAPValue(other any) bool {
	right, ok := other.(AssociateResult)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *AssociateSourceDiagnostic) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialogueServiceUser); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialogueServiceProvider); err != nil {
		return err
	}
	return nil
}
func (v *AssociateSourceDiagnostic) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.DialogueServiceUser) {
		return true
	}
	if hasTCAPPresenceEditValue(v.DialogueServiceProvider) {
		return true
	}
	return false
}
func (v AssociateSourceDiagnostic) equalTCAPValue(other any) bool {
	right, ok := other.(AssociateSourceDiagnostic)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.DialogueServiceUser == nil) != (right.DialogueServiceUser == nil) {
		return false
	}
	if v.DialogueServiceUser != nil && !equalTCAPValue(*v.DialogueServiceUser, *right.DialogueServiceUser) {
		return false
	}
	if (v.DialogueServiceProvider == nil) != (right.DialogueServiceProvider == nil) {
		return false
	}
	if v.DialogueServiceProvider != nil && !equalTCAPValue(*v.DialogueServiceProvider, *right.DialogueServiceProvider) {
		return false
	}
	return true
}
func (v *AssociateSourceDiagnosticDialogueServiceProviderValue) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *AssociateSourceDiagnosticDialogueServiceProviderValue) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v AssociateSourceDiagnosticDialogueServiceProviderValue) equalTCAPValue(other any) bool {
	right, ok := other.(AssociateSourceDiagnosticDialogueServiceProviderValue)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *AssociateSourceDiagnosticDialogueServiceUserValue) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *AssociateSourceDiagnosticDialogueServiceUserValue) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v AssociateSourceDiagnosticDialogueServiceUserValue) equalTCAPValue(other any) bool {
	right, ok := other.(AssociateSourceDiagnosticDialogueServiceUserValue)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *DialoguePDU) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialogueRequest); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialogueResponse); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialogueAbort); err != nil {
		return err
	}
	return nil
}
func (v *DialoguePDU) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.DialogueRequest) {
		return true
	}
	if hasTCAPPresenceEditValue(v.DialogueResponse) {
		return true
	}
	if hasTCAPPresenceEditValue(v.DialogueAbort) {
		return true
	}
	return false
}
func (v DialoguePDU) equalTCAPValue(other any) bool {
	right, ok := other.(DialoguePDU)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.DialogueRequest == nil) != (right.DialogueRequest == nil) {
		return false
	}
	if v.DialogueRequest != nil && !equalTCAPValue(*v.DialogueRequest, *right.DialogueRequest) {
		return false
	}
	if (v.DialogueResponse == nil) != (right.DialogueResponse == nil) {
		return false
	}
	if v.DialogueResponse != nil && !equalTCAPValue(*v.DialogueResponse, *right.DialogueResponse) {
		return false
	}
	if (v.DialogueAbort == nil) != (right.DialogueAbort == nil) {
		return false
	}
	if v.DialogueAbort != nil && !equalTCAPValue(*v.DialogueAbort, *right.DialogueAbort) {
		return false
	}
	return true
}
func (v *RLREApdu) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(v.Reason); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.UserInformation); err != nil {
		return err
	}
	return nil
}
func (v *RLREApdu) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.Reason) {
		return true
	}
	if hasTCAPPresenceEditValue(v.UserInformation) {
		return true
	}
	return false
}
func (v RLREApdu) equalTCAPValue(other any) bool {
	right, ok := other.(RLREApdu)
	if !ok {
		return false
	}
	_ = right
	if (v.Reason == nil) != (right.Reason == nil) {
		return false
	}
	if v.Reason != nil && !equalTCAPValue(*v.Reason, *right.Reason) {
		return false
	}
	if (v.UserInformation == nil) != (right.UserInformation == nil) {
		return false
	}
	if v.UserInformation != nil && !equalTCAPValue(*v.UserInformation, *right.UserInformation) {
		return false
	}
	return true
}
func (v *RLRQApdu) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(v.Reason); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.UserInformation); err != nil {
		return err
	}
	return nil
}
func (v *RLRQApdu) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.Reason) {
		return true
	}
	if hasTCAPPresenceEditValue(v.UserInformation) {
		return true
	}
	return false
}
func (v RLRQApdu) equalTCAPValue(other any) bool {
	right, ok := other.(RLRQApdu)
	if !ok {
		return false
	}
	_ = right
	if (v.Reason == nil) != (right.Reason == nil) {
		return false
	}
	if v.Reason != nil && !equalTCAPValue(*v.Reason, *right.Reason) {
		return false
	}
	if (v.UserInformation == nil) != (right.UserInformation == nil) {
		return false
	}
	if v.UserInformation != nil && !equalTCAPValue(*v.UserInformation, *right.UserInformation) {
		return false
	}
	return true
}
func (v *ReleaseRequestReason) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *ReleaseRequestReason) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v ReleaseRequestReason) equalTCAPValue(other any) bool {
	right, ok := other.(ReleaseRequestReason)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *ReleaseResponseReason) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *ReleaseResponseReason) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v ReleaseResponseReason) equalTCAPValue(other any) bool {
	right, ok := other.(ReleaseResponseReason)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *UserInformation) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *UserInformation) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v UserInformation) equalTCAPValue(other any) bool {
	right, ok := other.(UserInformation)
	if !ok {
		return false
	}
	_ = right
	if len(v.Values) != len(right.Values) {
		return false
	}
	for i := range v.Values {
		if !equalTCAPValue(v.Values[i], right.Values[i]) {
			return false
		}
	}
	return true
}
