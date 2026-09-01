// Code generated from ASN.1 module "RSPDefinitions". DO NOT EDIT.

package sgp32

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

// IdRsp returns the OID value for IdRsp.
func IdRsp() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1} }

// IdRspCertObjects returns the OID value for IdRspCertObjects.
func IdRspCertObjects() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1, 2} }

// IdRspExt returns the OID value for IdRspExt.
func IdRspExt() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 0} }

// IdRspRole returns the OID value for IdRspRole.
func IdRspRole() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1} }

// IdRspRoleCi returns the OID value for IdRspRoleCi.
func IdRspRoleCi() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 0} }

// IdRspRoleEuicc returns the OID value for IdRspRoleEuicc.
func IdRspRoleEuicc() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 1}
}

// IdRspRoleEum returns the OID value for IdRspRoleEum.
func IdRspRoleEum() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 2} }

// IdRspRoleDpTls returns the OID value for IdRspRoleDpTls.
func IdRspRoleDpTls() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 3}
}

// IdRspRoleDpAuth returns the OID value for IdRspRoleDpAuth.
func IdRspRoleDpAuth() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 4}
}

// IdRspRoleDpPb returns the OID value for IdRspRoleDpPb.
func IdRspRoleDpPb() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 5}
}

// IdRspRoleDsTls returns the OID value for IdRspRoleDsTls.
func IdRspRoleDsTls() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 6}
}

// IdRspRoleDsAuth returns the OID value for IdRspRoleDsAuth.
func IdRspRoleDsAuth() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 1, 7}
}

// IdRspExpDate returns the OID value for IdRspExpDate.
func IdRspExpDate() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 0, 1} }

// IdRspTotalPartialCrlNumber returns the OID value for IdRspTotalPartialCrlNumber.
func IdRspTotalPartialCrlNumber() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 0, 2}
}

// IdRspPartialCrlNumber returns the OID value for IdRspPartialCrlNumber.
func IdRspPartialCrlNumber() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 2, 0, 3}
}

// IdRspMetadata returns the OID value for IdRspMetadata.
func IdRspMetadata() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 23, 146, 1, 3} }

// IdRspMetadataServiceSpecificOIDs returns the OID value for IdRspMetadataServiceSpecificOIDs.
func IdRspMetadataServiceSpecificOIDs() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 3, 1}
}

// IdRspMetadataActivationCodeRetrievalInfo returns the OID value for IdRspMetadataActivationCodeRetrievalInfo.
func IdRspMetadataActivationCodeRetrievalInfo() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 23, 146, 1, 3, 1, 1}
}

// Octet1 represents the ASN.1 type Octet1 (OCTET_STRING).
type Octet1 = []byte

// Octet4 represents the ASN.1 type Octet4 (OCTET_STRING).
type Octet4 = []byte

// Octet8 represents the ASN.1 type Octet8 (OCTET_STRING).
type Octet8 = []byte

// Octet16 represents the ASN.1 type Octet16 (OCTET_STRING).
type Octet16 = []byte

// OctetTo16 represents the ASN.1 type OctetTo16 (OCTET_STRING).
type OctetTo16 = []byte

// Octet32 represents the ASN.1 type Octet32 (OCTET_STRING).
type Octet32 = []byte

// VersionType represents the ASN.1 type VersionType (OCTET_STRING).
type VersionType = []byte

// Iccid represents the ASN.1 type Iccid (OCTET_STRING).
type Iccid = []byte

// RemoteOpId represents the arbitrary-width ASN.1 INTEGER type RemoteOpId with named numbers.
type RemoteOpId struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	RemoteOpIdInstallBoundProfilePackageDecimal = "1"
	RemoteOpIdInstallBoundProfilePackage        = 1
)

// NewRemoteOpId returns an immutable RemoteOpId containing value.
func NewRemoteOpId(value *big.Int) RemoteOpId {
	return RemoteOpId{value: runtime.CloneBigInt(value)}
}

// NewRemoteOpIdInt64 returns a RemoteOpId containing value.
func NewRemoteOpIdInt64(value int64) RemoteOpId {
	return NewRemoteOpId(big.NewInt(value))
}

// RemoteOpIdInstallBoundProfilePackageValue returns the named value installBoundProfilePackage.
func RemoteOpIdInstallBoundProfilePackageValue() RemoteOpId {
	return NewRemoteOpId(runtime.MustParseBigIntDecimal(RemoteOpIdInstallBoundProfilePackageDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v RemoteOpId) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v RemoteOpId) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v RemoteOpId) Name() (string, bool) {
	switch v.BigInt().String() {
	case RemoteOpIdInstallBoundProfilePackageDecimal:
		return "installBoundProfilePackage", true
	default:
		return "", false
	}
}

func (v RemoteOpId) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v RemoteOpId) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *RemoteOpId) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal RemoteOpId into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewRemoteOpId(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v RemoteOpId) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *RemoteOpId) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal RemoteOpId into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewRemoteOpId(value)
	return nil
}

// TransactionId represents the ASN.1 type TransactionId (OCTET_STRING).
type TransactionId = []byte

// PprIds represents the ASN.1 type PprIds (BIT_STRING).
type PprIds = runtime.BitString

// OperatorId represents the ASN.1 type OperatorId (SEQUENCE).
type OperatorId struct {
	MccMnc      []byte   `asn1:"tag:0,context,implicit"`
	Gid1        []byte   `asn1:"tag:1,context,implicit,optional" json:"Gid1,omitempty"`
	Gid2        []byte   `asn1:"tag:2,context,implicit,optional" json:"Gid2,omitempty"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// BoundProfilePackage represents the ASN.1 type BoundProfilePackage (SEQUENCE).
type BoundProfilePackage struct {
	InitialiseSecureChannelRequest InitialiseSecureChannelRequest        `asn1:"tag:35,context,implicit"`
	FirstSequenceOf87              BoundProfilePackageFirstSequenceOf87  `asn1:"tag:0,context,implicit"`
	FirstSequenceOf87Indef_        bool                                  `asn1:"-" json:"-"`
	SequenceOf88                   BoundProfilePackageSequenceOf88       `asn1:"tag:1,context,implicit"`
	SequenceOf88Indef_             bool                                  `asn1:"-" json:"-"`
	SecondSequenceOf87             BoundProfilePackageSecondSequenceOf87 `asn1:"tag:2,context,implicit,optional" json:"SecondSequenceOf87,omitempty"`
	SecondSequenceOf87Indef_       bool                                  `asn1:"-" json:"-"`
	SequenceOf86                   BoundProfilePackageSequenceOf86       `asn1:"tag:3,context,implicit"`
	SequenceOf86Indef_             bool                                  `asn1:"-" json:"-"`
	ExtCount_                      int64                                 `asn1:"-" json:"-"`
	ExtPresent_                    []bool                                `asn1:"-" json:"-"`
	ExtData_                       [][]byte                              `asn1:"-" json:"-"`
}

// ProfileInstallationResult represents the ASN.1 type ProfileInstallationResult (SEQUENCE).
type ProfileInstallationResult struct {
	ProfileInstallationResultData ProfileInstallationResultData `asn1:"tag:39,context,implicit"`
	EuiccSignPIR                  EuiccSignPIR                  `asn1:""`
	ExtCount_                     int64                         `asn1:"-" json:"-"`
	ExtPresent_                   []bool                        `asn1:"-" json:"-"`
	ExtData_                      [][]byte                      `asn1:"-" json:"-"`
}

// ProfileInstallationResultData represents the ASN.1 type ProfileInstallationResultData (SEQUENCE).
type ProfileInstallationResultData struct {
	TransactionId        TransactionId                            `asn1:"tag:0,context,implicit"`
	NotificationMetadata NotificationMetadata                     `asn1:"tag:47,context,implicit"`
	SmdpOid              runtime.ObjectIdentifier                 `asn1:""`
	FinalResult          ProfileInstallationResultDataFinalResult `asn1:"tag:2,context,explicit"`
	ExtCount_            int64                                    `asn1:"-" json:"-"`
	ExtPresent_          []bool                                   `asn1:"-" json:"-"`
	ExtData_             [][]byte                                 `asn1:"-" json:"-"`
}

// EuiccSignPIR represents the ASN.1 type EuiccSignPIR (OCTET_STRING).
type EuiccSignPIR = []byte

// SuccessResult represents the ASN.1 type SuccessResult (SEQUENCE).
type SuccessResult struct {
	Aid          []byte   `asn1:"tag:15,application,implicit"`
	SimaResponse []byte   `asn1:""`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
}

// ErrorResult represents the ASN.1 type ErrorResult (SEQUENCE).
type ErrorResult struct {
	BppCommandId BppCommandId `asn1:"tag:0,context,implicit"`
	ErrorReason  ErrorReason  `asn1:"tag:1,context,implicit"`
	SimaResponse []byte       `asn1:"tag:2,context,implicit,optional" json:"SimaResponse,omitempty"`
	ExtCount_    int64        `asn1:"-" json:"-"`
	ExtPresent_  []bool       `asn1:"-" json:"-"`
	ExtData_     [][]byte     `asn1:"-" json:"-"`
}

// BppCommandId represents the arbitrary-width ASN.1 INTEGER type BppCommandId with named numbers.
type BppCommandId struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	BppCommandIdInitialiseSecureChannelDecimal = "0"
	BppCommandIdInitialiseSecureChannel        = 0
	BppCommandIdConfigureISDPDecimal           = "1"
	BppCommandIdConfigureISDP                  = 1
	BppCommandIdStoreMetadataDecimal           = "2"
	BppCommandIdStoreMetadata                  = 2
	BppCommandIdStoreMetadata2Decimal          = "3"
	BppCommandIdStoreMetadata2                 = 3
	BppCommandIdReplaceSessionKeysDecimal      = "4"
	BppCommandIdReplaceSessionKeys             = 4
	BppCommandIdLoadProfileElementsDecimal     = "5"
	BppCommandIdLoadProfileElements            = 5
)

// NewBppCommandId returns an immutable BppCommandId containing value.
func NewBppCommandId(value *big.Int) BppCommandId {
	return BppCommandId{value: runtime.CloneBigInt(value)}
}

// NewBppCommandIdInt64 returns a BppCommandId containing value.
func NewBppCommandIdInt64(value int64) BppCommandId {
	return NewBppCommandId(big.NewInt(value))
}

// BppCommandIdInitialiseSecureChannelValue returns the named value initialiseSecureChannel.
func BppCommandIdInitialiseSecureChannelValue() BppCommandId {
	return NewBppCommandId(runtime.MustParseBigIntDecimal(BppCommandIdInitialiseSecureChannelDecimal))
}

// BppCommandIdConfigureISDPValue returns the named value configureISDP.
func BppCommandIdConfigureISDPValue() BppCommandId {
	return NewBppCommandId(runtime.MustParseBigIntDecimal(BppCommandIdConfigureISDPDecimal))
}

// BppCommandIdStoreMetadataValue returns the named value storeMetadata.
func BppCommandIdStoreMetadataValue() BppCommandId {
	return NewBppCommandId(runtime.MustParseBigIntDecimal(BppCommandIdStoreMetadataDecimal))
}

// BppCommandIdStoreMetadata2Value returns the named value storeMetadata2.
func BppCommandIdStoreMetadata2Value() BppCommandId {
	return NewBppCommandId(runtime.MustParseBigIntDecimal(BppCommandIdStoreMetadata2Decimal))
}

// BppCommandIdReplaceSessionKeysValue returns the named value replaceSessionKeys.
func BppCommandIdReplaceSessionKeysValue() BppCommandId {
	return NewBppCommandId(runtime.MustParseBigIntDecimal(BppCommandIdReplaceSessionKeysDecimal))
}

// BppCommandIdLoadProfileElementsValue returns the named value loadProfileElements.
func BppCommandIdLoadProfileElementsValue() BppCommandId {
	return NewBppCommandId(runtime.MustParseBigIntDecimal(BppCommandIdLoadProfileElementsDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v BppCommandId) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v BppCommandId) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v BppCommandId) Name() (string, bool) {
	switch v.BigInt().String() {
	case BppCommandIdInitialiseSecureChannelDecimal:
		return "initialiseSecureChannel", true
	case BppCommandIdConfigureISDPDecimal:
		return "configureISDP", true
	case BppCommandIdStoreMetadataDecimal:
		return "storeMetadata", true
	case BppCommandIdStoreMetadata2Decimal:
		return "storeMetadata2", true
	case BppCommandIdReplaceSessionKeysDecimal:
		return "replaceSessionKeys", true
	case BppCommandIdLoadProfileElementsDecimal:
		return "loadProfileElements", true
	default:
		return "", false
	}
}

func (v BppCommandId) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v BppCommandId) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *BppCommandId) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal BppCommandId into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewBppCommandId(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v BppCommandId) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *BppCommandId) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal BppCommandId into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewBppCommandId(value)
	return nil
}

// ErrorReason represents the arbitrary-width ASN.1 INTEGER type ErrorReason with named numbers.
type ErrorReason struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ErrorReasonIncorrectInputValuesDecimal                                  = "1"
	ErrorReasonIncorrectInputValues                                         = 1
	ErrorReasonInvalidSignatureDecimal                                      = "2"
	ErrorReasonInvalidSignature                                             = 2
	ErrorReasonInvalidTransactionIdDecimal                                  = "3"
	ErrorReasonInvalidTransactionId                                         = 3
	ErrorReasonUnsupportedCrtValuesDecimal                                  = "4"
	ErrorReasonUnsupportedCrtValues                                         = 4
	ErrorReasonUnsupportedRemoteOperationTypeDecimal                        = "5"
	ErrorReasonUnsupportedRemoteOperationType                               = 5
	ErrorReasonUnsupportedProfileClassDecimal                               = "6"
	ErrorReasonUnsupportedProfileClass                                      = 6
	ErrorReasonScp03tStructureErrorDecimal                                  = "7"
	ErrorReasonScp03tStructureError                                         = 7
	ErrorReasonScp03tSecurityErrorDecimal                                   = "8"
	ErrorReasonScp03tSecurityError                                          = 8
	ErrorReasonInstallFailedDueToIccidAlreadyExistsOnEuiccDecimal           = "9"
	ErrorReasonInstallFailedDueToIccidAlreadyExistsOnEuicc                  = 9
	ErrorReasonInstallFailedDueToInsufficientMemoryForProfileDecimal        = "10"
	ErrorReasonInstallFailedDueToInsufficientMemoryForProfile               = 10
	ErrorReasonInstallFailedDueToInterruptionDecimal                        = "11"
	ErrorReasonInstallFailedDueToInterruption                               = 11
	ErrorReasonInstallFailedDueToPEProcessingErrorDecimal                   = "12"
	ErrorReasonInstallFailedDueToPEProcessingError                          = 12
	ErrorReasonInstallFailedDueToDataMismatchDecimal                        = "13"
	ErrorReasonInstallFailedDueToDataMismatch                               = 13
	ErrorReasonTestProfileInstallFailedDueToInvalidNaaKeyDecimal            = "14"
	ErrorReasonTestProfileInstallFailedDueToInvalidNaaKey                   = 14
	ErrorReasonPprNotAllowedDecimal                                         = "15"
	ErrorReasonPprNotAllowed                                                = 15
	ErrorReasonInstallFailedDueToInsufficientMinimumSecurityLevelDecimal    = "31"
	ErrorReasonInstallFailedDueToInsufficientMinimumSecurityLevel           = 31
	ErrorReasonInstallFailedDueToServerAddressAbsentInEuiccAllowListDecimal = "32"
	ErrorReasonInstallFailedDueToServerAddressAbsentInEuiccAllowList        = 32
	ErrorReasonInstallFailedDueToUnknownErrorDecimal                        = "127"
	ErrorReasonInstallFailedDueToUnknownError                               = 127
)

// NewErrorReason returns an immutable ErrorReason containing value.
func NewErrorReason(value *big.Int) ErrorReason {
	return ErrorReason{value: runtime.CloneBigInt(value)}
}

// NewErrorReasonInt64 returns a ErrorReason containing value.
func NewErrorReasonInt64(value int64) ErrorReason {
	return NewErrorReason(big.NewInt(value))
}

// ErrorReasonIncorrectInputValuesValue returns the named value incorrectInputValues.
func ErrorReasonIncorrectInputValuesValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonIncorrectInputValuesDecimal))
}

// ErrorReasonInvalidSignatureValue returns the named value invalidSignature.
func ErrorReasonInvalidSignatureValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInvalidSignatureDecimal))
}

// ErrorReasonInvalidTransactionIdValue returns the named value invalidTransactionId.
func ErrorReasonInvalidTransactionIdValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInvalidTransactionIdDecimal))
}

// ErrorReasonUnsupportedCrtValuesValue returns the named value unsupportedCrtValues.
func ErrorReasonUnsupportedCrtValuesValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonUnsupportedCrtValuesDecimal))
}

// ErrorReasonUnsupportedRemoteOperationTypeValue returns the named value unsupportedRemoteOperationType.
func ErrorReasonUnsupportedRemoteOperationTypeValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonUnsupportedRemoteOperationTypeDecimal))
}

// ErrorReasonUnsupportedProfileClassValue returns the named value unsupportedProfileClass.
func ErrorReasonUnsupportedProfileClassValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonUnsupportedProfileClassDecimal))
}

// ErrorReasonScp03tStructureErrorValue returns the named value scp03tStructureError.
func ErrorReasonScp03tStructureErrorValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonScp03tStructureErrorDecimal))
}

// ErrorReasonScp03tSecurityErrorValue returns the named value scp03tSecurityError.
func ErrorReasonScp03tSecurityErrorValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonScp03tSecurityErrorDecimal))
}

// ErrorReasonInstallFailedDueToIccidAlreadyExistsOnEuiccValue returns the named value installFailedDueToIccidAlreadyExistsOnEuicc.
func ErrorReasonInstallFailedDueToIccidAlreadyExistsOnEuiccValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToIccidAlreadyExistsOnEuiccDecimal))
}

// ErrorReasonInstallFailedDueToInsufficientMemoryForProfileValue returns the named value installFailedDueToInsufficientMemoryForProfile.
func ErrorReasonInstallFailedDueToInsufficientMemoryForProfileValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToInsufficientMemoryForProfileDecimal))
}

// ErrorReasonInstallFailedDueToInterruptionValue returns the named value installFailedDueToInterruption.
func ErrorReasonInstallFailedDueToInterruptionValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToInterruptionDecimal))
}

// ErrorReasonInstallFailedDueToPEProcessingErrorValue returns the named value installFailedDueToPEProcessingError.
func ErrorReasonInstallFailedDueToPEProcessingErrorValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToPEProcessingErrorDecimal))
}

// ErrorReasonInstallFailedDueToDataMismatchValue returns the named value installFailedDueToDataMismatch.
func ErrorReasonInstallFailedDueToDataMismatchValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToDataMismatchDecimal))
}

// ErrorReasonTestProfileInstallFailedDueToInvalidNaaKeyValue returns the named value testProfileInstallFailedDueToInvalidNaaKey.
func ErrorReasonTestProfileInstallFailedDueToInvalidNaaKeyValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonTestProfileInstallFailedDueToInvalidNaaKeyDecimal))
}

// ErrorReasonPprNotAllowedValue returns the named value pprNotAllowed.
func ErrorReasonPprNotAllowedValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonPprNotAllowedDecimal))
}

// ErrorReasonInstallFailedDueToInsufficientMinimumSecurityLevelValue returns the named value installFailedDueToInsufficientMinimumSecurityLevel.
func ErrorReasonInstallFailedDueToInsufficientMinimumSecurityLevelValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToInsufficientMinimumSecurityLevelDecimal))
}

// ErrorReasonInstallFailedDueToServerAddressAbsentInEuiccAllowListValue returns the named value installFailedDueToServerAddressAbsentInEuiccAllowList.
func ErrorReasonInstallFailedDueToServerAddressAbsentInEuiccAllowListValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToServerAddressAbsentInEuiccAllowListDecimal))
}

// ErrorReasonInstallFailedDueToUnknownErrorValue returns the named value installFailedDueToUnknownError.
func ErrorReasonInstallFailedDueToUnknownErrorValue() ErrorReason {
	return NewErrorReason(runtime.MustParseBigIntDecimal(ErrorReasonInstallFailedDueToUnknownErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ErrorReason) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ErrorReason) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ErrorReason) Name() (string, bool) {
	switch v.BigInt().String() {
	case ErrorReasonIncorrectInputValuesDecimal:
		return "incorrectInputValues", true
	case ErrorReasonInvalidSignatureDecimal:
		return "invalidSignature", true
	case ErrorReasonInvalidTransactionIdDecimal:
		return "invalidTransactionId", true
	case ErrorReasonUnsupportedCrtValuesDecimal:
		return "unsupportedCrtValues", true
	case ErrorReasonUnsupportedRemoteOperationTypeDecimal:
		return "unsupportedRemoteOperationType", true
	case ErrorReasonUnsupportedProfileClassDecimal:
		return "unsupportedProfileClass", true
	case ErrorReasonScp03tStructureErrorDecimal:
		return "scp03tStructureError", true
	case ErrorReasonScp03tSecurityErrorDecimal:
		return "scp03tSecurityError", true
	case ErrorReasonInstallFailedDueToIccidAlreadyExistsOnEuiccDecimal:
		return "installFailedDueToIccidAlreadyExistsOnEuicc", true
	case ErrorReasonInstallFailedDueToInsufficientMemoryForProfileDecimal:
		return "installFailedDueToInsufficientMemoryForProfile", true
	case ErrorReasonInstallFailedDueToInterruptionDecimal:
		return "installFailedDueToInterruption", true
	case ErrorReasonInstallFailedDueToPEProcessingErrorDecimal:
		return "installFailedDueToPEProcessingError", true
	case ErrorReasonInstallFailedDueToDataMismatchDecimal:
		return "installFailedDueToDataMismatch", true
	case ErrorReasonTestProfileInstallFailedDueToInvalidNaaKeyDecimal:
		return "testProfileInstallFailedDueToInvalidNaaKey", true
	case ErrorReasonPprNotAllowedDecimal:
		return "pprNotAllowed", true
	case ErrorReasonInstallFailedDueToInsufficientMinimumSecurityLevelDecimal:
		return "installFailedDueToInsufficientMinimumSecurityLevel", true
	case ErrorReasonInstallFailedDueToServerAddressAbsentInEuiccAllowListDecimal:
		return "installFailedDueToServerAddressAbsentInEuiccAllowList", true
	case ErrorReasonInstallFailedDueToUnknownErrorDecimal:
		return "installFailedDueToUnknownError", true
	default:
		return "", false
	}
}

func (v ErrorReason) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ErrorReason) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ErrorReason) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ErrorReason into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewErrorReason(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ErrorReason) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ErrorReason) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ErrorReason into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewErrorReason(value)
	return nil
}

// DeviceInfo represents the ASN.1 type DeviceInfo (SEQUENCE).
type DeviceInfo struct {
	Tac                Octet4             `asn1:"tag:0,context,implicit"`
	DeviceCapabilities DeviceCapabilities `asn1:"tag:1,context,implicit"`
	Imei               *Octet8            `asn1:"tag:2,context,implicit,optional" json:"Imei,omitempty"`
	ExtCount_          int64              `asn1:"-" json:"-"`
	ExtPresent_        []bool             `asn1:"-" json:"-"`
	ExtData_           [][]byte           `asn1:"-" json:"-"`
}

// DeviceCapabilities represents the ASN.1 type DeviceCapabilities (SEQUENCE).
type DeviceCapabilities struct {
	GsmSupportedRelease            *VersionType                    `asn1:"tag:0,context,implicit,optional" json:"GsmSupportedRelease,omitempty"`
	UtranSupportedRelease          *VersionType                    `asn1:"tag:1,context,implicit,optional" json:"UtranSupportedRelease,omitempty"`
	Cdma2000onexSupportedRelease   *VersionType                    `asn1:"tag:2,context,implicit,optional" json:"Cdma2000onexSupportedRelease,omitempty"`
	Cdma2000hrpdSupportedRelease   *VersionType                    `asn1:"tag:3,context,implicit,optional" json:"Cdma2000hrpdSupportedRelease,omitempty"`
	Cdma2000ehrpdSupportedRelease  *VersionType                    `asn1:"tag:4,context,implicit,optional" json:"Cdma2000ehrpdSupportedRelease,omitempty"`
	EutranEpcSupportedRelease      *VersionType                    `asn1:"tag:5,context,implicit,optional" json:"EutranEpcSupportedRelease,omitempty"`
	ContactlessSupportedRelease    *VersionType                    `asn1:"tag:6,context,implicit,optional" json:"ContactlessSupportedRelease,omitempty"`
	RspCrlSupportedVersion         *VersionType                    `asn1:"tag:7,context,implicit,optional" json:"RspCrlSupportedVersion,omitempty"`
	NrEpcSupportedRelease          *VersionType                    `asn1:"tag:8,context,implicit,optional" json:"NrEpcSupportedRelease,omitempty"`
	Nr5gcSupportedRelease          *VersionType                    `asn1:"tag:9,context,implicit,optional" json:"Nr5gcSupportedRelease,omitempty"`
	Eutran5gcSupportedRelease      *VersionType                    `asn1:"tag:10,context,implicit,optional" json:"Eutran5gcSupportedRelease,omitempty"`
	LpaSvn                         *VersionType                    `asn1:"tag:11,context,implicit,optional" json:"LpaSvn,omitempty"`
	CatSupportedClasses            *CatSupportedClasses            `asn1:"tag:12,context,implicit,optional" json:"CatSupportedClasses,omitempty"`
	EuiccFormFactorType            EuiccFormFactorType             `asn1:"tag:13,context,implicit,optional" json:"EuiccFormFactorType,omitempty"`
	DeviceAdditionalFeatureSupport *DeviceAdditionalFeatureSupport `asn1:"tag:14,context,implicit,optional" json:"DeviceAdditionalFeatureSupport,omitempty"`
	ExtCount_                      int64                           `asn1:"-" json:"-"`
	ExtPresent_                    []bool                          `asn1:"-" json:"-"`
	ExtData_                       [][]byte                        `asn1:"-" json:"-"`
}

// DeviceAdditionalFeatureSupport represents the ASN.1 type DeviceAdditionalFeatureSupport (SEQUENCE).
type DeviceAdditionalFeatureSupport struct {
	NaiSupport                   *VersionType             `asn1:"tag:0,context,implicit,optional" json:"NaiSupport,omitempty"`
	GroupOfDeviceManufacturerOid runtime.ObjectIdentifier `asn1:"tag:1,context,implicit,optional" json:"GroupOfDeviceManufacturerOid,omitempty"`
	ExtCount_                    int64                    `asn1:"-" json:"-"`
	ExtPresent_                  []bool                   `asn1:"-" json:"-"`
	ExtData_                     [][]byte                 `asn1:"-" json:"-"`
}

// CatSupportedClasses represents the ASN.1 type CatSupportedClasses (BIT_STRING).
type CatSupportedClasses = runtime.BitString

// EuiccFormFactorType represents the ASN.1 type EuiccFormFactorType (INTEGER).
type EuiccFormFactorType = *big.Int

// SegmentedCrlList represents the ASN.1 type SegmentedCrlList (SEQUENCE_OF).
type SegmentedCrlList = []CertificateList

// ExpirationDate represents the ASN.1 type ExpirationDate (CHOICE).
type ExpirationDate = Time

// TotalPartialCrlNumber represents the ASN.1 type TotalPartialCrlNumber (INTEGER).
type TotalPartialCrlNumber = *big.Int

// PartialCrlNumber represents the ASN.1 type PartialCrlNumber (INTEGER).
type PartialCrlNumber = *big.Int

// ActivationCodeRetrievalInfo choice constants.
const (
	ActivationCodeRetrievalInfoChoiceActivationCodeForProfileRedownload = 1
	ActivationCodeRetrievalInfoChoiceActivationCodeRetrievalAvailable   = 2
	ActivationCodeRetrievalInfoChoiceRetryDelay                         = 3
)

// ActivationCodeRetrievalInfo represents the ASN.1 CHOICE type ActivationCodeRetrievalInfo.
type ActivationCodeRetrievalInfo struct {
	Choice                             int
	ActivationCodeForProfileRedownload *string  `json:"ActivationCodeForProfileRedownload,omitempty"`
	ActivationCodeRetrievalAvailable   *bool    `json:"ActivationCodeRetrievalAvailable,omitempty"`
	RetryDelay                         *big.Int `json:"RetryDelay,omitempty"`
}

// NewActivationCodeRetrievalInfoActivationCodeForProfileRedownload creates a ActivationCodeRetrievalInfo with the activationCodeForProfileRedownload alternative.
func NewActivationCodeRetrievalInfoActivationCodeForProfileRedownload(v string) ActivationCodeRetrievalInfo {
	return ActivationCodeRetrievalInfo{
		Choice:                             ActivationCodeRetrievalInfoChoiceActivationCodeForProfileRedownload,
		ActivationCodeForProfileRedownload: &v,
	}
}

// NewActivationCodeRetrievalInfoActivationCodeRetrievalAvailable creates a ActivationCodeRetrievalInfo with the activationCodeRetrievalAvailable alternative.
func NewActivationCodeRetrievalInfoActivationCodeRetrievalAvailable(v bool) ActivationCodeRetrievalInfo {
	return ActivationCodeRetrievalInfo{
		Choice:                           ActivationCodeRetrievalInfoChoiceActivationCodeRetrievalAvailable,
		ActivationCodeRetrievalAvailable: &v,
	}
}

// NewActivationCodeRetrievalInfoRetryDelay creates a ActivationCodeRetrievalInfo with the retryDelay alternative.
func NewActivationCodeRetrievalInfoRetryDelay(v *big.Int) ActivationCodeRetrievalInfo {
	return ActivationCodeRetrievalInfo{
		Choice:     ActivationCodeRetrievalInfoChoiceRetryDelay,
		RetryDelay: v,
	}
}

// UpdateMetadataRequest represents the ASN.1 type UpdateMetadataRequest (SEQUENCE).
type UpdateMetadataRequest struct {
	ServiceProviderName                    *string                 `asn1:"tag:17,context,implicit,optional" json:"ServiceProviderName,omitempty"`
	ProfileName                            *string                 `asn1:"tag:18,context,implicit,optional" json:"ProfileName,omitempty"`
	IconType                               *IconType               `asn1:"tag:19,context,implicit,optional" json:"IconType,omitempty"`
	Icon                                   []byte                  `asn1:"tag:20,context,implicit,optional" json:"Icon,omitempty"`
	ProfilePolicyRules                     *PprIds                 `asn1:"tag:25,context,implicit,optional" json:"ProfilePolicyRules,omitempty"`
	ServiceSpecificDataStoredInEuicc       VendorSpecificExtension `asn1:"tag:34,context,implicit,optional" json:"ServiceSpecificDataStoredInEuicc,omitempty"`
	ServiceSpecificDataStoredInEuiccIndef_ bool                    `asn1:"-" json:"-"`
	Reserved103                            *bool                   `asn1:"tag:103,context,implicit,optional" json:"Reserved103,omitempty"`
	Reserved103Raw_                        byte                    `asn1:"-" json:"-"`
	ExtCount_                              int64                   `asn1:"-" json:"-"`
	ExtPresent_                            []bool                  `asn1:"-" json:"-"`
	ExtData_                               [][]byte                `asn1:"-" json:"-"`
}

// InitialiseSecureChannelRequest represents the ASN.1 type InitialiseSecureChannelRequest (SEQUENCE).
type InitialiseSecureChannelRequest struct {
	RemoteOpId         RemoteOpId         `asn1:""`
	TransactionId      TransactionId      `asn1:"tag:0,context,implicit"`
	ControlRefTemplate ControlRefTemplate `asn1:"tag:6,context,implicit"`
	SmdpOtpk           []byte             `asn1:"tag:73,application,implicit"`
	SmdpSign           []byte             `asn1:"tag:55,application,implicit"`
	ExtCount_          int64              `asn1:"-" json:"-"`
	ExtPresent_        []bool             `asn1:"-" json:"-"`
	ExtData_           [][]byte           `asn1:"-" json:"-"`
}

// ControlRefTemplate represents the ASN.1 type ControlRefTemplate (SEQUENCE).
type ControlRefTemplate struct {
	KeyType     Octet1    `asn1:"tag:0,context,implicit"`
	KeyLen      Octet1    `asn1:"tag:1,context,implicit"`
	HostId      OctetTo16 `asn1:"tag:4,context,implicit"`
	ExtCount_   int64     `asn1:"-" json:"-"`
	ExtPresent_ []bool    `asn1:"-" json:"-"`
	ExtData_    [][]byte  `asn1:"-" json:"-"`
}

// ConfigureISDPRequest represents the ASN.1 type ConfigureISDPRequest (SEQUENCE).
type ConfigureISDPRequest struct {
	DpProprietaryData *DpProprietaryData `asn1:"tag:24,context,implicit,optional" json:"DpProprietaryData,omitempty"`
	ExtCount_         int64              `asn1:"-" json:"-"`
	ExtPresent_       []bool             `asn1:"-" json:"-"`
	ExtData_          [][]byte           `asn1:"-" json:"-"`
}

// DpProprietaryData represents the ASN.1 type DpProprietaryData (SEQUENCE).
type DpProprietaryData struct {
	DpOid       runtime.ObjectIdentifier `asn1:"tag:0,context,implicit"`
	ExtCount_   int64                    `asn1:"-" json:"-"`
	ExtPresent_ []bool                   `asn1:"-" json:"-"`
	ExtData_    [][]byte                 `asn1:"-" json:"-"`
}

// StoreMetadataRequest represents the ASN.1 type StoreMetadataRequest (SEQUENCE).
type StoreMetadataRequest struct {
	Iccid                                     Iccid                                             `asn1:""`
	ServiceProviderName                       string                                            `asn1:"tag:17,context,implicit"`
	ProfileName                               string                                            `asn1:"tag:18,context,implicit"`
	IconType                                  *IconType                                         `asn1:"tag:19,context,implicit,optional" json:"IconType,omitempty"`
	Icon                                      []byte                                            `asn1:"tag:20,context,implicit,optional" json:"Icon,omitempty"`
	ProfileClass                              *ProfileClass                                     `asn1:"tag:21,context,implicit,optional" json:"ProfileClass,omitempty"`
	NotificationConfigurationInfo             StoreMetadataRequestNotificationConfigurationInfo `asn1:"tag:22,context,implicit,optional" json:"NotificationConfigurationInfo,omitempty"`
	NotificationConfigurationInfoIndef_       bool                                              `asn1:"-" json:"-"`
	ProfileOwner                              *OperatorId                                       `asn1:"tag:23,context,implicit,optional" json:"ProfileOwner,omitempty"`
	ProfilePolicyRules                        *PprIds                                           `asn1:"tag:25,context,implicit,optional" json:"ProfilePolicyRules,omitempty"`
	ServiceSpecificDataStoredInEuicc          VendorSpecificExtension                           `asn1:"tag:34,context,implicit,optional" json:"ServiceSpecificDataStoredInEuicc,omitempty"`
	ServiceSpecificDataStoredInEuiccIndef_    bool                                              `asn1:"-" json:"-"`
	ServiceSpecificDataNotStoredInEuicc       VendorSpecificExtension                           `asn1:"tag:35,context,implicit,optional" json:"ServiceSpecificDataNotStoredInEuicc,omitempty"`
	ServiceSpecificDataNotStoredInEuiccIndef_ bool                                              `asn1:"-" json:"-"`
	EcallIndication                           *bool                                             `asn1:"tag:123,context,implicit,optional" json:"EcallIndication,omitempty"`
	EcallIndicationRaw_                       byte                                              `asn1:"-" json:"-"`
	FallbackAllowed                           *bool                                             `asn1:"tag:103,context,implicit,optional" json:"FallbackAllowed,omitempty"`
	FallbackAllowedRaw_                       byte                                              `asn1:"-" json:"-"`
	IotSpecificMetadata                       *StoreMetadataRequestIotSpecificMetadata          `asn1:"tag:100,context,implicit,optional" json:"IotSpecificMetadata,omitempty"`
	ExtCount_                                 int64                                             `asn1:"-" json:"-"`
	ExtPresent_                               []bool                                            `asn1:"-" json:"-"`
	ExtData_                                  [][]byte                                          `asn1:"-" json:"-"`
}

// NotificationEvent represents the ASN.1 type NotificationEvent (BIT_STRING).
type NotificationEvent = runtime.BitString

// NotificationConfigurationInformation represents the ASN.1 type NotificationConfigurationInformation (SEQUENCE).
type NotificationConfigurationInformation struct {
	ProfileManagementOperation NotificationEvent `asn1:"tag:0,context,implicit"`
	NotificationAddress        string            `asn1:"tag:1,context,implicit"`
	ExtCount_                  int64             `asn1:"-" json:"-"`
	ExtPresent_                []bool            `asn1:"-" json:"-"`
	ExtData_                   [][]byte          `asn1:"-" json:"-"`
}

// VendorSpecificExtension represents the ASN.1 type VendorSpecificExtension (SEQUENCE_OF).
type VendorSpecificExtension = []VendorSpecificExtensionElem

// ReplaceSessionKeysRequest represents the ASN.1 type ReplaceSessionKeysRequest (SEQUENCE).
type ReplaceSessionKeysRequest struct {
	InitialMacChainingValue []byte   `asn1:"tag:0,context,implicit"`
	PpkEnc                  []byte   `asn1:"tag:1,context,implicit"`
	PpkCmac                 []byte   `asn1:"tag:2,context,implicit"`
	ExtCount_               int64    `asn1:"-" json:"-"`
	ExtPresent_             []bool   `asn1:"-" json:"-"`
	ExtData_                [][]byte `asn1:"-" json:"-"`
}

// ISDRProprietaryApplicationTemplate represents the ASN.1 type ISDRProprietaryApplicationTemplate (SEQUENCE).
type ISDRProprietaryApplicationTemplate struct {
	Svn         VersionType        `asn1:"tag:2,context,implicit"`
	LpaeSupport *runtime.BitString `asn1:",optional" json:"LpaeSupport,omitempty"`
	ExtCount_   int64              `asn1:"-" json:"-"`
	ExtPresent_ []bool             `asn1:"-" json:"-"`
	ExtData_    [][]byte           `asn1:"-" json:"-"`
}

// LpaeActivationRequest represents the ASN.1 type LpaeActivationRequest (SEQUENCE).
type LpaeActivationRequest struct {
	LpaeOption  runtime.BitString `asn1:"tag:0,context,implicit"`
	ExtCount_   int64             `asn1:"-" json:"-"`
	ExtPresent_ []bool            `asn1:"-" json:"-"`
	ExtData_    [][]byte          `asn1:"-" json:"-"`
}

// LpaeActivationResponse represents the ASN.1 type LpaeActivationResponse (SEQUENCE).
type LpaeActivationResponse struct {
	LpaeActivationResult LpaeActivationResponseLpaeActivationResultValue `asn1:"tag:0,context,implicit"`
	ExtCount_            int64                                           `asn1:"-" json:"-"`
	ExtPresent_          []bool                                          `asn1:"-" json:"-"`
	ExtData_             [][]byte                                        `asn1:"-" json:"-"`
}

// EuiccConfiguredAddressesRequest represents the ASN.1 type EuiccConfiguredAddressesRequest (SEQUENCE).
type EuiccConfiguredAddressesRequest struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// EuiccConfiguredAddressesResponse represents the ASN.1 type EuiccConfiguredAddressesResponse (SEQUENCE).
type EuiccConfiguredAddressesResponse struct {
	DefaultDpAddress *string  `asn1:"tag:0,context,implicit,optional" json:"DefaultDpAddress,omitempty"`
	RootDsAddress    string   `asn1:"tag:1,context,implicit"`
	ExtCount_        int64    `asn1:"-" json:"-"`
	ExtPresent_      []bool   `asn1:"-" json:"-"`
	ExtData_         [][]byte `asn1:"-" json:"-"`
}

// SetDefaultDpAddressRequest represents the ASN.1 type SetDefaultDpAddressRequest (SEQUENCE).
type SetDefaultDpAddressRequest struct {
	DefaultDpAddress string   `asn1:"tag:0,context,implicit"`
	ExtCount_        int64    `asn1:"-" json:"-"`
	ExtPresent_      []bool   `asn1:"-" json:"-"`
	ExtData_         [][]byte `asn1:"-" json:"-"`
}

// SetDefaultDpAddressResponse represents the ASN.1 type SetDefaultDpAddressResponse (SEQUENCE).
type SetDefaultDpAddressResponse struct {
	SetDefaultDpAddressResult SetDefaultDpAddressResponseSetDefaultDpAddressResultValue `asn1:"tag:0,context,implicit"`
	ExtCount_                 int64                                                     `asn1:"-" json:"-"`
	ExtPresent_               []bool                                                    `asn1:"-" json:"-"`
	ExtData_                  [][]byte                                                  `asn1:"-" json:"-"`
}

// PrepareDownloadRequest represents the ASN.1 type PrepareDownloadRequest (SEQUENCE).
type PrepareDownloadRequest struct {
	SmdpSigned2     SmdpSigned2 `asn1:""`
	SmdpSignature2  []byte      `asn1:"tag:55,application,implicit"`
	HashCc          *Octet32    `asn1:",optional" json:"HashCc,omitempty"`
	SmdpCertificate Certificate `asn1:""`
	ExtCount_       int64       `asn1:"-" json:"-"`
	ExtPresent_     []bool      `asn1:"-" json:"-"`
	ExtData_        [][]byte    `asn1:"-" json:"-"`
}

// SmdpSigned2 represents the ASN.1 type SmdpSigned2 (SEQUENCE).
type SmdpSigned2 struct {
	TransactionId      TransactionId `asn1:"tag:0,context,implicit"`
	CcRequiredFlag     bool          `asn1:""`
	CcRequiredFlagRaw_ byte          `asn1:"-" json:"-"`
	BppEuiccOtpk       []byte        `asn1:"tag:73,application,implicit,optional" json:"BppEuiccOtpk,omitempty"`
	ExtCount_          int64         `asn1:"-" json:"-"`
	ExtPresent_        []bool        `asn1:"-" json:"-"`
	ExtData_           [][]byte      `asn1:"-" json:"-"`
}

// PrepareDownloadResponse choice constants.
const (
	PrepareDownloadResponseChoiceDownloadResponseOk    = 1
	PrepareDownloadResponseChoiceDownloadResponseError = 2
)

// PrepareDownloadResponse represents the ASN.1 CHOICE type PrepareDownloadResponse.
type PrepareDownloadResponse struct {
	Choice                int
	DownloadResponseOk    *PrepareDownloadResponseOk    `json:"DownloadResponseOk,omitempty"`
	DownloadResponseError *PrepareDownloadResponseError `json:"DownloadResponseError,omitempty"`
}

// NewPrepareDownloadResponseDownloadResponseOk creates a PrepareDownloadResponse with the downloadResponseOk alternative.
func NewPrepareDownloadResponseDownloadResponseOk(v PrepareDownloadResponseOk) PrepareDownloadResponse {
	return PrepareDownloadResponse{
		Choice:             PrepareDownloadResponseChoiceDownloadResponseOk,
		DownloadResponseOk: &v,
	}
}

// NewPrepareDownloadResponseDownloadResponseError creates a PrepareDownloadResponse with the downloadResponseError alternative.
func NewPrepareDownloadResponseDownloadResponseError(v PrepareDownloadResponseError) PrepareDownloadResponse {
	return PrepareDownloadResponse{
		Choice:                PrepareDownloadResponseChoiceDownloadResponseError,
		DownloadResponseError: &v,
	}
}

// PrepareDownloadResponseOk represents the ASN.1 type PrepareDownloadResponseOk (SEQUENCE).
type PrepareDownloadResponseOk struct {
	EuiccSigned2    EUICCSigned2 `asn1:""`
	EuiccSignature2 []byte       `asn1:"tag:55,application,implicit"`
	ExtCount_       int64        `asn1:"-" json:"-"`
	ExtPresent_     []bool       `asn1:"-" json:"-"`
	ExtData_        [][]byte     `asn1:"-" json:"-"`
}

// EUICCSigned2 represents the ASN.1 type EUICCSigned2 (SEQUENCE).
type EUICCSigned2 struct {
	TransactionId TransactionId `asn1:"tag:0,context,implicit"`
	EuiccOtpk     []byte        `asn1:"tag:73,application,implicit"`
	HashCc        *Octet32      `asn1:",optional" json:"HashCc,omitempty"`
	ExtCount_     int64         `asn1:"-" json:"-"`
	ExtPresent_   []bool        `asn1:"-" json:"-"`
	ExtData_      [][]byte      `asn1:"-" json:"-"`
}

// PrepareDownloadResponseError represents the ASN.1 type PrepareDownloadResponseError (SEQUENCE).
type PrepareDownloadResponseError struct {
	TransactionId     TransactionId     `asn1:"tag:0,context,implicit"`
	DownloadErrorCode DownloadErrorCode `asn1:""`
	ExtCount_         int64             `asn1:"-" json:"-"`
	ExtPresent_       []bool            `asn1:"-" json:"-"`
	ExtData_          [][]byte          `asn1:"-" json:"-"`
}

// DownloadErrorCode represents the arbitrary-width ASN.1 INTEGER type DownloadErrorCode with named numbers.
type DownloadErrorCode struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	DownloadErrorCodeInvalidCertificateDecimal   = "1"
	DownloadErrorCodeInvalidCertificate          = 1
	DownloadErrorCodeInvalidSignatureDecimal     = "2"
	DownloadErrorCodeInvalidSignature            = 2
	DownloadErrorCodeUnsupportedCurveDecimal     = "3"
	DownloadErrorCodeUnsupportedCurve            = 3
	DownloadErrorCodeNoSessionContextDecimal     = "4"
	DownloadErrorCodeNoSessionContext            = 4
	DownloadErrorCodeInvalidTransactionIdDecimal = "5"
	DownloadErrorCodeInvalidTransactionId        = 5
	DownloadErrorCodeUndefinedErrorDecimal       = "127"
	DownloadErrorCodeUndefinedError              = 127
)

// NewDownloadErrorCode returns an immutable DownloadErrorCode containing value.
func NewDownloadErrorCode(value *big.Int) DownloadErrorCode {
	return DownloadErrorCode{value: runtime.CloneBigInt(value)}
}

// NewDownloadErrorCodeInt64 returns a DownloadErrorCode containing value.
func NewDownloadErrorCodeInt64(value int64) DownloadErrorCode {
	return NewDownloadErrorCode(big.NewInt(value))
}

// DownloadErrorCodeInvalidCertificateValue returns the named value invalidCertificate.
func DownloadErrorCodeInvalidCertificateValue() DownloadErrorCode {
	return NewDownloadErrorCode(runtime.MustParseBigIntDecimal(DownloadErrorCodeInvalidCertificateDecimal))
}

// DownloadErrorCodeInvalidSignatureValue returns the named value invalidSignature.
func DownloadErrorCodeInvalidSignatureValue() DownloadErrorCode {
	return NewDownloadErrorCode(runtime.MustParseBigIntDecimal(DownloadErrorCodeInvalidSignatureDecimal))
}

// DownloadErrorCodeUnsupportedCurveValue returns the named value unsupportedCurve.
func DownloadErrorCodeUnsupportedCurveValue() DownloadErrorCode {
	return NewDownloadErrorCode(runtime.MustParseBigIntDecimal(DownloadErrorCodeUnsupportedCurveDecimal))
}

// DownloadErrorCodeNoSessionContextValue returns the named value noSessionContext.
func DownloadErrorCodeNoSessionContextValue() DownloadErrorCode {
	return NewDownloadErrorCode(runtime.MustParseBigIntDecimal(DownloadErrorCodeNoSessionContextDecimal))
}

// DownloadErrorCodeInvalidTransactionIdValue returns the named value invalidTransactionId.
func DownloadErrorCodeInvalidTransactionIdValue() DownloadErrorCode {
	return NewDownloadErrorCode(runtime.MustParseBigIntDecimal(DownloadErrorCodeInvalidTransactionIdDecimal))
}

// DownloadErrorCodeUndefinedErrorValue returns the named value undefinedError.
func DownloadErrorCodeUndefinedErrorValue() DownloadErrorCode {
	return NewDownloadErrorCode(runtime.MustParseBigIntDecimal(DownloadErrorCodeUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v DownloadErrorCode) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v DownloadErrorCode) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v DownloadErrorCode) Name() (string, bool) {
	switch v.BigInt().String() {
	case DownloadErrorCodeInvalidCertificateDecimal:
		return "invalidCertificate", true
	case DownloadErrorCodeInvalidSignatureDecimal:
		return "invalidSignature", true
	case DownloadErrorCodeUnsupportedCurveDecimal:
		return "unsupportedCurve", true
	case DownloadErrorCodeNoSessionContextDecimal:
		return "noSessionContext", true
	case DownloadErrorCodeInvalidTransactionIdDecimal:
		return "invalidTransactionId", true
	case DownloadErrorCodeUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v DownloadErrorCode) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v DownloadErrorCode) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *DownloadErrorCode) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DownloadErrorCode into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewDownloadErrorCode(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v DownloadErrorCode) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *DownloadErrorCode) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DownloadErrorCode into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewDownloadErrorCode(value)
	return nil
}

// GetEuiccChallengeRequest represents the ASN.1 type GetEuiccChallengeRequest (SEQUENCE).
type GetEuiccChallengeRequest struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// GetEuiccChallengeResponse represents the ASN.1 type GetEuiccChallengeResponse (SEQUENCE).
type GetEuiccChallengeResponse struct {
	EuiccChallenge Octet16  `asn1:"tag:0,context,implicit"`
	ExtCount_      int64    `asn1:"-" json:"-"`
	ExtPresent_    []bool   `asn1:"-" json:"-"`
	ExtData_       [][]byte `asn1:"-" json:"-"`
}

// GetEuiccInfo1Request represents the ASN.1 type GetEuiccInfo1Request (SEQUENCE).
type GetEuiccInfo1Request struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// GetEuiccInfo2Request represents the ASN.1 type GetEuiccInfo2Request (SEQUENCE).
type GetEuiccInfo2Request struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// EUICCInfo1 represents the ASN.1 type EUICCInfo1 (SEQUENCE).
type EUICCInfo1 struct {
	Svn                                  VersionType                              `asn1:"tag:2,context,implicit"`
	EuiccCiPKIdListForVerification       EUICCInfo1EuiccCiPKIdListForVerification `asn1:"tag:9,context,implicit"`
	EuiccCiPKIdListForVerificationIndef_ bool                                     `asn1:"-" json:"-"`
	EuiccCiPKIdListForSigning            EUICCInfo1EuiccCiPKIdListForSigning      `asn1:"tag:10,context,implicit"`
	EuiccCiPKIdListForSigningIndef_      bool                                     `asn1:"-" json:"-"`
	ExtCount_                            int64                                    `asn1:"-" json:"-"`
	ExtPresent_                          []bool                                   `asn1:"-" json:"-"`
	ExtData_                             [][]byte                                 `asn1:"-" json:"-"`
}

// EUICCInfo2 represents the ASN.1 type EUICCInfo2 (SEQUENCE).
type EUICCInfo2 struct {
	ProfileVersion                              VersionType                                     `asn1:"tag:1,context,implicit"`
	Svn                                         VersionType                                     `asn1:"tag:2,context,implicit"`
	EuiccFirmwareVer                            VersionType                                     `asn1:"tag:3,context,implicit"`
	ExtCardResource                             []byte                                          `asn1:"tag:4,context,implicit"`
	UiccCapability                              UICCCapability                                  `asn1:"tag:5,context,implicit"`
	Ts102241Version                             *VersionType                                    `asn1:"tag:6,context,implicit,optional" json:"Ts102241Version,omitempty"`
	GlobalplatformVersion                       *VersionType                                    `asn1:"tag:7,context,implicit,optional" json:"GlobalplatformVersion,omitempty"`
	RspCapability                               RspCapability                                   `asn1:"tag:8,context,implicit"`
	EuiccCiPKIdListForVerification              EUICCInfo2EuiccCiPKIdListForVerification        `asn1:"tag:9,context,implicit"`
	EuiccCiPKIdListForVerificationIndef_        bool                                            `asn1:"-" json:"-"`
	EuiccCiPKIdListForSigning                   EUICCInfo2EuiccCiPKIdListForSigning             `asn1:"tag:10,context,implicit"`
	EuiccCiPKIdListForSigningIndef_             bool                                            `asn1:"-" json:"-"`
	EuiccCategory                               *EUICCInfo2EuiccCategoryValue                   `asn1:"tag:11,context,implicit,optional" json:"EuiccCategory,omitempty"`
	ForbiddenProfilePolicyRules                 *PprIds                                         `asn1:"tag:25,context,implicit,optional" json:"ForbiddenProfilePolicyRules,omitempty"`
	PpVersion                                   VersionType                                     `asn1:""`
	SasAcreditationNumber                       string                                          `asn1:""`
	CertificationDataObject                     *CertificationDataObject                        `asn1:"tag:12,context,implicit,optional" json:"CertificationDataObject,omitempty"`
	TreProperties                               *runtime.BitString                              `asn1:"tag:13,context,implicit,optional" json:"TreProperties,omitempty"`
	TreProductReference                         *string                                         `asn1:"tag:14,context,implicit,optional" json:"TreProductReference,omitempty"`
	AdditionalEuiccProfilePackageVersions       EUICCInfo2AdditionalEuiccProfilePackageVersions `asn1:"tag:15,context,implicit,optional" json:"AdditionalEuiccProfilePackageVersions,omitempty"`
	AdditionalEuiccProfilePackageVersionsIndef_ bool                                            `asn1:"-" json:"-"`
	LpaMode                                     LpaMode                                         `asn1:"tag:16,context,implicit,optional" json:"LpaMode,omitempty"`
	EuiccCiPKIdListForSigningV3                 EUICCInfo2EuiccCiPKIdListForSigningV3           `asn1:"tag:17,context,implicit,optional" json:"EuiccCiPKIdListForSigningV3,omitempty"`
	EuiccCiPKIdListForSigningV3Indef_           bool                                            `asn1:"-" json:"-"`
	AdditionalEuiccInfo                         []byte                                          `asn1:"tag:18,context,implicit,optional" json:"AdditionalEuiccInfo,omitempty"`
	HighestSvn                                  *VersionType                                    `asn1:"tag:19,context,implicit,optional" json:"HighestSvn,omitempty"`
	IotSpecificInfo                             *IoTSpecificInfo                                `asn1:"tag:20,context,implicit,optional" json:"IotSpecificInfo,omitempty"`
	EuiccMinimumSecurityLevel                   []byte                                          `asn1:"tag:21,context,implicit,optional" json:"EuiccMinimumSecurityLevel,omitempty"`
	ExtCount_                                   int64                                           `asn1:"-" json:"-"`
	ExtPresent_                                 []bool                                          `asn1:"-" json:"-"`
	ExtData_                                    [][]byte                                        `asn1:"-" json:"-"`
}

// RspCapability represents the ASN.1 type RspCapability (BIT_STRING).
type RspCapability = runtime.BitString

// CertificationDataObject represents the ASN.1 type CertificationDataObject (SEQUENCE).
type CertificationDataObject struct {
	PlatformLabel    string   `asn1:"tag:0,context,implicit"`
	DiscoveryBaseURL string   `asn1:"tag:1,context,implicit"`
	ExtCount_        int64    `asn1:"-" json:"-"`
	ExtPresent_      []bool   `asn1:"-" json:"-"`
	ExtData_         [][]byte `asn1:"-" json:"-"`
}

// LpaMode represents the ASN.1 type LpaMode (INTEGER).
type LpaMode = *big.Int

// IoTSpecificInfo represents the ASN.1 type IoTSpecificInfo (SEQUENCE).
type IoTSpecificInfo struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// ListNotificationRequest represents the ASN.1 type ListNotificationRequest (SEQUENCE).
type ListNotificationRequest struct {
	ProfileManagementOperation *NotificationEvent `asn1:"tag:1,context,implicit,optional" json:"ProfileManagementOperation,omitempty"`
	ExtCount_                  int64              `asn1:"-" json:"-"`
	ExtPresent_                []bool             `asn1:"-" json:"-"`
	ExtData_                   [][]byte           `asn1:"-" json:"-"`
}

// ListNotificationResponse choice constants.
const (
	ListNotificationResponseChoiceNotificationMetadataList     = 1
	ListNotificationResponseChoiceListNotificationsResultError = 2
)

// ListNotificationResponse represents the ASN.1 CHOICE type ListNotificationResponse.
type ListNotificationResponse struct {
	Choice                       int
	NotificationMetadataList     ListNotificationResponseNotificationMetadataList           `json:"NotificationMetadataList,omitempty"`
	ListNotificationsResultError *ListNotificationResponseListNotificationsResultErrorValue `json:"ListNotificationsResultError,omitempty"`
}

// NewListNotificationResponseNotificationMetadataList creates a ListNotificationResponse with the notificationMetadataList alternative.
func NewListNotificationResponseNotificationMetadataList(v ListNotificationResponseNotificationMetadataList) ListNotificationResponse {
	return ListNotificationResponse{
		Choice:                   ListNotificationResponseChoiceNotificationMetadataList,
		NotificationMetadataList: v,
	}
}

// NewListNotificationResponseListNotificationsResultError creates a ListNotificationResponse with the listNotificationsResultError alternative.
func NewListNotificationResponseListNotificationsResultError(v ListNotificationResponseListNotificationsResultErrorValue) ListNotificationResponse {
	return ListNotificationResponse{
		Choice:                       ListNotificationResponseChoiceListNotificationsResultError,
		ListNotificationsResultError: &v,
	}
}

// NotificationMetadata represents the ASN.1 type NotificationMetadata (SEQUENCE).
type NotificationMetadata struct {
	SeqNumber                  *big.Int          `asn1:"tag:0,context,implicit"`
	ProfileManagementOperation NotificationEvent `asn1:"tag:1,context,implicit"`
	NotificationAddress        string            `asn1:""`
	Iccid                      *Iccid            `asn1:",optional" json:"Iccid,omitempty"`
	ExtCount_                  int64             `asn1:"-" json:"-"`
	ExtPresent_                []bool            `asn1:"-" json:"-"`
	ExtData_                   [][]byte          `asn1:"-" json:"-"`
}

// RetrieveNotificationsListRequest represents the ASN.1 type RetrieveNotificationsListRequest (SEQUENCE).
type RetrieveNotificationsListRequest struct {
	SearchCriteria *RetrieveNotificationsListRequestSearchCriteria `asn1:"tag:0,context,explicit,optional" json:"SearchCriteria,omitempty"`
	ExtCount_      int64                                           `asn1:"-" json:"-"`
	ExtPresent_    []bool                                          `asn1:"-" json:"-"`
	ExtData_       [][]byte                                        `asn1:"-" json:"-"`
}

// RetrieveNotificationsListResponse choice constants.
const (
	RetrieveNotificationsListResponseChoiceNotificationList             = 1
	RetrieveNotificationsListResponseChoiceNotificationsListResultError = 2
)

// RetrieveNotificationsListResponse represents the ASN.1 CHOICE type RetrieveNotificationsListResponse.
type RetrieveNotificationsListResponse struct {
	Choice                       int
	NotificationList             RetrieveNotificationsListResponseNotificationList                   `json:"NotificationList,omitempty"`
	NotificationsListResultError *RetrieveNotificationsListResponseNotificationsListResultErrorValue `json:"NotificationsListResultError,omitempty"`
}

// NewRetrieveNotificationsListResponseNotificationList creates a RetrieveNotificationsListResponse with the notificationList alternative.
func NewRetrieveNotificationsListResponseNotificationList(v RetrieveNotificationsListResponseNotificationList) RetrieveNotificationsListResponse {
	return RetrieveNotificationsListResponse{
		Choice:           RetrieveNotificationsListResponseChoiceNotificationList,
		NotificationList: v,
	}
}

// NewRetrieveNotificationsListResponseNotificationsListResultError creates a RetrieveNotificationsListResponse with the notificationsListResultError alternative.
func NewRetrieveNotificationsListResponseNotificationsListResultError(v RetrieveNotificationsListResponseNotificationsListResultErrorValue) RetrieveNotificationsListResponse {
	return RetrieveNotificationsListResponse{
		Choice:                       RetrieveNotificationsListResponseChoiceNotificationsListResultError,
		NotificationsListResultError: &v,
	}
}

// PendingNotification choice constants.
const (
	PendingNotificationChoiceProfileInstallationResult = 1
	PendingNotificationChoiceOtherSignedNotification   = 2
)

// PendingNotification represents the ASN.1 CHOICE type PendingNotification.
type PendingNotification struct {
	Choice                    int
	ProfileInstallationResult *ProfileInstallationResult `json:"ProfileInstallationResult,omitempty"`
	OtherSignedNotification   *OtherSignedNotification   `json:"OtherSignedNotification,omitempty"`
}

// NewPendingNotificationProfileInstallationResult creates a PendingNotification with the profileInstallationResult alternative.
func NewPendingNotificationProfileInstallationResult(v ProfileInstallationResult) PendingNotification {
	return PendingNotification{
		Choice:                    PendingNotificationChoiceProfileInstallationResult,
		ProfileInstallationResult: &v,
	}
}

// NewPendingNotificationOtherSignedNotification creates a PendingNotification with the otherSignedNotification alternative.
func NewPendingNotificationOtherSignedNotification(v OtherSignedNotification) PendingNotification {
	return PendingNotification{
		Choice:                  PendingNotificationChoiceOtherSignedNotification,
		OtherSignedNotification: &v,
	}
}

// OtherSignedNotification represents the ASN.1 type OtherSignedNotification (SEQUENCE).
type OtherSignedNotification struct {
	TbsOtherNotification       NotificationMetadata `asn1:""`
	EuiccNotificationSignature []byte               `asn1:"tag:55,application,implicit"`
	EuiccCertificate           Certificate          `asn1:""`
	EumCertificate             Certificate          `asn1:""`
	ExtCount_                  int64                `asn1:"-" json:"-"`
	ExtPresent_                []bool               `asn1:"-" json:"-"`
	ExtData_                   [][]byte             `asn1:"-" json:"-"`
}

// NotificationSentRequest represents the ASN.1 type NotificationSentRequest (SEQUENCE).
type NotificationSentRequest struct {
	SeqNumber   *big.Int `asn1:"tag:0,context,implicit"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// NotificationSentResponse represents the ASN.1 type NotificationSentResponse (SEQUENCE).
type NotificationSentResponse struct {
	DeleteNotificationStatus NotificationSentResponseDeleteNotificationStatusValue `asn1:"tag:0,context,implicit"`
	ExtCount_                int64                                                 `asn1:"-" json:"-"`
	ExtPresent_              []bool                                                `asn1:"-" json:"-"`
	ExtData_                 [][]byte                                              `asn1:"-" json:"-"`
}

// LoadCRLRequest represents the ASN.1 type LoadCRLRequest (SEQUENCE).
type LoadCRLRequest struct {
	Crl         CertificateList `asn1:"tag:0,context,implicit"`
	ExtCount_   int64           `asn1:"-" json:"-"`
	ExtPresent_ []bool          `asn1:"-" json:"-"`
	ExtData_    [][]byte        `asn1:"-" json:"-"`
}

// LoadCRLResponse choice constants.
const (
	LoadCRLResponseChoiceLoadCRLResponseOk    = 1
	LoadCRLResponseChoiceLoadCRLResponseError = 2
)

// LoadCRLResponse represents the ASN.1 CHOICE type LoadCRLResponse.
type LoadCRLResponse struct {
	Choice               int
	LoadCRLResponseOk    *LoadCRLResponseOk    `json:"LoadCRLResponseOk,omitempty"`
	LoadCRLResponseError *LoadCRLResponseError `json:"LoadCRLResponseError,omitempty"`
}

// NewLoadCRLResponseLoadCRLResponseOk creates a LoadCRLResponse with the loadCRLResponseOk alternative.
func NewLoadCRLResponseLoadCRLResponseOk(v LoadCRLResponseOk) LoadCRLResponse {
	return LoadCRLResponse{
		Choice:            LoadCRLResponseChoiceLoadCRLResponseOk,
		LoadCRLResponseOk: &v,
	}
}

// NewLoadCRLResponseLoadCRLResponseError creates a LoadCRLResponse with the loadCRLResponseError alternative.
func NewLoadCRLResponseLoadCRLResponseError(v LoadCRLResponseError) LoadCRLResponse {
	return LoadCRLResponse{
		Choice:               LoadCRLResponseChoiceLoadCRLResponseError,
		LoadCRLResponseError: &v,
	}
}

// LoadCRLResponseOk represents the ASN.1 type LoadCRLResponseOk (SEQUENCE).
type LoadCRLResponseOk struct {
	MissingParts       LoadCRLResponseOkMissingParts `asn1:"tag:0,context,implicit,optional" json:"MissingParts,omitempty"`
	MissingPartsIndef_ bool                          `asn1:"-" json:"-"`
	ExtCount_          int64                         `asn1:"-" json:"-"`
	ExtPresent_        []bool                        `asn1:"-" json:"-"`
	ExtData_           [][]byte                      `asn1:"-" json:"-"`
}

// LoadCRLResponseError represents the arbitrary-width ASN.1 INTEGER type LoadCRLResponseError with named numbers.
type LoadCRLResponseError struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	LoadCRLResponseErrorInvalidSignatureDecimal        = "1"
	LoadCRLResponseErrorInvalidSignature               = 1
	LoadCRLResponseErrorInvalidCRLFormatDecimal        = "2"
	LoadCRLResponseErrorInvalidCRLFormat               = 2
	LoadCRLResponseErrorNotEnoughMemorySpaceDecimal    = "3"
	LoadCRLResponseErrorNotEnoughMemorySpace           = 3
	LoadCRLResponseErrorVerificationKeyNotFoundDecimal = "4"
	LoadCRLResponseErrorVerificationKeyNotFound        = 4
	LoadCRLResponseErrorFresherCrlAlreadyLoadedDecimal = "5"
	LoadCRLResponseErrorFresherCrlAlreadyLoaded        = 5
	LoadCRLResponseErrorBaseCrlMissingDecimal          = "6"
	LoadCRLResponseErrorBaseCrlMissing                 = 6
	LoadCRLResponseErrorUndefinedErrorDecimal          = "127"
	LoadCRLResponseErrorUndefinedError                 = 127
)

// NewLoadCRLResponseError returns an immutable LoadCRLResponseError containing value.
func NewLoadCRLResponseError(value *big.Int) LoadCRLResponseError {
	return LoadCRLResponseError{value: runtime.CloneBigInt(value)}
}

// NewLoadCRLResponseErrorInt64 returns a LoadCRLResponseError containing value.
func NewLoadCRLResponseErrorInt64(value int64) LoadCRLResponseError {
	return NewLoadCRLResponseError(big.NewInt(value))
}

// LoadCRLResponseErrorInvalidSignatureValue returns the named value invalidSignature.
func LoadCRLResponseErrorInvalidSignatureValue() LoadCRLResponseError {
	return NewLoadCRLResponseError(runtime.MustParseBigIntDecimal(LoadCRLResponseErrorInvalidSignatureDecimal))
}

// LoadCRLResponseErrorInvalidCRLFormatValue returns the named value invalidCRLFormat.
func LoadCRLResponseErrorInvalidCRLFormatValue() LoadCRLResponseError {
	return NewLoadCRLResponseError(runtime.MustParseBigIntDecimal(LoadCRLResponseErrorInvalidCRLFormatDecimal))
}

// LoadCRLResponseErrorNotEnoughMemorySpaceValue returns the named value notEnoughMemorySpace.
func LoadCRLResponseErrorNotEnoughMemorySpaceValue() LoadCRLResponseError {
	return NewLoadCRLResponseError(runtime.MustParseBigIntDecimal(LoadCRLResponseErrorNotEnoughMemorySpaceDecimal))
}

// LoadCRLResponseErrorVerificationKeyNotFoundValue returns the named value verificationKeyNotFound.
func LoadCRLResponseErrorVerificationKeyNotFoundValue() LoadCRLResponseError {
	return NewLoadCRLResponseError(runtime.MustParseBigIntDecimal(LoadCRLResponseErrorVerificationKeyNotFoundDecimal))
}

// LoadCRLResponseErrorFresherCrlAlreadyLoadedValue returns the named value fresherCrlAlreadyLoaded.
func LoadCRLResponseErrorFresherCrlAlreadyLoadedValue() LoadCRLResponseError {
	return NewLoadCRLResponseError(runtime.MustParseBigIntDecimal(LoadCRLResponseErrorFresherCrlAlreadyLoadedDecimal))
}

// LoadCRLResponseErrorBaseCrlMissingValue returns the named value baseCrlMissing.
func LoadCRLResponseErrorBaseCrlMissingValue() LoadCRLResponseError {
	return NewLoadCRLResponseError(runtime.MustParseBigIntDecimal(LoadCRLResponseErrorBaseCrlMissingDecimal))
}

// LoadCRLResponseErrorUndefinedErrorValue returns the named value undefinedError.
func LoadCRLResponseErrorUndefinedErrorValue() LoadCRLResponseError {
	return NewLoadCRLResponseError(runtime.MustParseBigIntDecimal(LoadCRLResponseErrorUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v LoadCRLResponseError) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v LoadCRLResponseError) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v LoadCRLResponseError) Name() (string, bool) {
	switch v.BigInt().String() {
	case LoadCRLResponseErrorInvalidSignatureDecimal:
		return "invalidSignature", true
	case LoadCRLResponseErrorInvalidCRLFormatDecimal:
		return "invalidCRLFormat", true
	case LoadCRLResponseErrorNotEnoughMemorySpaceDecimal:
		return "notEnoughMemorySpace", true
	case LoadCRLResponseErrorVerificationKeyNotFoundDecimal:
		return "verificationKeyNotFound", true
	case LoadCRLResponseErrorFresherCrlAlreadyLoadedDecimal:
		return "fresherCrlAlreadyLoaded", true
	case LoadCRLResponseErrorBaseCrlMissingDecimal:
		return "baseCrlMissing", true
	case LoadCRLResponseErrorUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v LoadCRLResponseError) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v LoadCRLResponseError) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *LoadCRLResponseError) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal LoadCRLResponseError into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewLoadCRLResponseError(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v LoadCRLResponseError) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *LoadCRLResponseError) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal LoadCRLResponseError into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewLoadCRLResponseError(value)
	return nil
}

// AuthenticateServerRequest represents the ASN.1 type AuthenticateServerRequest (SEQUENCE).
type AuthenticateServerRequest struct {
	ServerSigned1       ServerSigned1        `asn1:""`
	ServerSignature1    []byte               `asn1:"tag:55,application,implicit"`
	EuiccCiPKIdToBeUsed SubjectKeyIdentifier `asn1:""`
	ServerCertificate   Certificate          `asn1:""`
	CtxParams1          CtxParams1           `asn1:""`
	ExtCount_           int64                `asn1:"-" json:"-"`
	ExtPresent_         []bool               `asn1:"-" json:"-"`
	ExtData_            [][]byte             `asn1:"-" json:"-"`
}

// ServerSigned1 represents the ASN.1 type ServerSigned1 (SEQUENCE).
type ServerSigned1 struct {
	TransactionId   TransactionId `asn1:"tag:0,context,implicit"`
	EuiccChallenge  Octet16       `asn1:"tag:1,context,implicit"`
	ServerAddress   string        `asn1:"tag:3,context,implicit"`
	ServerChallenge Octet16       `asn1:"tag:4,context,implicit"`
	ExtCount_       int64         `asn1:"-" json:"-"`
	ExtPresent_     []bool        `asn1:"-" json:"-"`
	ExtData_        [][]byte      `asn1:"-" json:"-"`
}

// CtxParams1 choice constants.
const (
	CtxParams1ChoiceCtxParamsForCommonAuthentication = 1
)

// CtxParams1 represents the ASN.1 CHOICE type CtxParams1.
type CtxParams1 struct {
	Choice                           int
	CtxParamsForCommonAuthentication *CtxParamsForCommonAuthentication `json:"CtxParamsForCommonAuthentication,omitempty"`
}

// NewCtxParams1CtxParamsForCommonAuthentication creates a CtxParams1 with the ctxParamsForCommonAuthentication alternative.
func NewCtxParams1CtxParamsForCommonAuthentication(v CtxParamsForCommonAuthentication) CtxParams1 {
	return CtxParams1{
		Choice:                           CtxParams1ChoiceCtxParamsForCommonAuthentication,
		CtxParamsForCommonAuthentication: &v,
	}
}

// CtxParamsForCommonAuthentication represents the ASN.1 type CtxParamsForCommonAuthentication (SEQUENCE).
type CtxParamsForCommonAuthentication struct {
	MatchingId  *string    `asn1:"tag:0,context,implicit,optional" json:"MatchingId,omitempty"`
	DeviceInfo  DeviceInfo `asn1:"tag:1,context,implicit"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// AuthenticateServerResponse choice constants.
const (
	AuthenticateServerResponseChoiceAuthenticateResponseOk    = 1
	AuthenticateServerResponseChoiceAuthenticateResponseError = 2
)

// AuthenticateServerResponse represents the ASN.1 CHOICE type AuthenticateServerResponse.
type AuthenticateServerResponse struct {
	Choice                    int
	AuthenticateResponseOk    *AuthenticateResponseOk    `json:"AuthenticateResponseOk,omitempty"`
	AuthenticateResponseError *AuthenticateResponseError `json:"AuthenticateResponseError,omitempty"`
}

// NewAuthenticateServerResponseAuthenticateResponseOk creates a AuthenticateServerResponse with the authenticateResponseOk alternative.
func NewAuthenticateServerResponseAuthenticateResponseOk(v AuthenticateResponseOk) AuthenticateServerResponse {
	return AuthenticateServerResponse{
		Choice:                 AuthenticateServerResponseChoiceAuthenticateResponseOk,
		AuthenticateResponseOk: &v,
	}
}

// NewAuthenticateServerResponseAuthenticateResponseError creates a AuthenticateServerResponse with the authenticateResponseError alternative.
func NewAuthenticateServerResponseAuthenticateResponseError(v AuthenticateResponseError) AuthenticateServerResponse {
	return AuthenticateServerResponse{
		Choice:                    AuthenticateServerResponseChoiceAuthenticateResponseError,
		AuthenticateResponseError: &v,
	}
}

// AuthenticateResponseOk represents the ASN.1 type AuthenticateResponseOk (SEQUENCE).
type AuthenticateResponseOk struct {
	EuiccSigned1     EuiccSigned1 `asn1:""`
	EuiccSignature1  []byte       `asn1:"tag:55,application,implicit"`
	EuiccCertificate Certificate  `asn1:""`
	EumCertificate   Certificate  `asn1:""`
	ExtCount_        int64        `asn1:"-" json:"-"`
	ExtPresent_      []bool       `asn1:"-" json:"-"`
	ExtData_         [][]byte     `asn1:"-" json:"-"`
}

// EuiccSigned1 represents the ASN.1 type EuiccSigned1 (SEQUENCE).
type EuiccSigned1 struct {
	TransactionId   TransactionId `asn1:"tag:0,context,implicit"`
	ServerAddress   string        `asn1:"tag:3,context,implicit"`
	ServerChallenge Octet16       `asn1:"tag:4,context,implicit"`
	EuiccInfo2      EUICCInfo2    `asn1:"tag:34,context,implicit"`
	CtxParams1      CtxParams1    `asn1:""`
	ExtCount_       int64         `asn1:"-" json:"-"`
	ExtPresent_     []bool        `asn1:"-" json:"-"`
	ExtData_        [][]byte      `asn1:"-" json:"-"`
}

// AuthenticateResponseError represents the ASN.1 type AuthenticateResponseError (SEQUENCE).
type AuthenticateResponseError struct {
	TransactionId         TransactionId         `asn1:"tag:0,context,implicit"`
	AuthenticateErrorCode AuthenticateErrorCode `asn1:""`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	ExtData_              [][]byte              `asn1:"-" json:"-"`
}

// AuthenticateErrorCode represents the arbitrary-width ASN.1 INTEGER type AuthenticateErrorCode with named numbers.
type AuthenticateErrorCode struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	AuthenticateErrorCodeInvalidCertificateDecimal     = "1"
	AuthenticateErrorCodeInvalidCertificate            = 1
	AuthenticateErrorCodeInvalidSignatureDecimal       = "2"
	AuthenticateErrorCodeInvalidSignature              = 2
	AuthenticateErrorCodeUnsupportedCurveDecimal       = "3"
	AuthenticateErrorCodeUnsupportedCurve              = 3
	AuthenticateErrorCodeNoSessionContextDecimal       = "4"
	AuthenticateErrorCodeNoSessionContext              = 4
	AuthenticateErrorCodeInvalidOidDecimal             = "5"
	AuthenticateErrorCodeInvalidOid                    = 5
	AuthenticateErrorCodeEuiccChallengeMismatchDecimal = "6"
	AuthenticateErrorCodeEuiccChallengeMismatch        = 6
	AuthenticateErrorCodeCiPKUnknownDecimal            = "7"
	AuthenticateErrorCodeCiPKUnknown                   = 7
	AuthenticateErrorCodeUndefinedErrorDecimal         = "127"
	AuthenticateErrorCodeUndefinedError                = 127
)

// NewAuthenticateErrorCode returns an immutable AuthenticateErrorCode containing value.
func NewAuthenticateErrorCode(value *big.Int) AuthenticateErrorCode {
	return AuthenticateErrorCode{value: runtime.CloneBigInt(value)}
}

// NewAuthenticateErrorCodeInt64 returns a AuthenticateErrorCode containing value.
func NewAuthenticateErrorCodeInt64(value int64) AuthenticateErrorCode {
	return NewAuthenticateErrorCode(big.NewInt(value))
}

// AuthenticateErrorCodeInvalidCertificateValue returns the named value invalidCertificate.
func AuthenticateErrorCodeInvalidCertificateValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeInvalidCertificateDecimal))
}

// AuthenticateErrorCodeInvalidSignatureValue returns the named value invalidSignature.
func AuthenticateErrorCodeInvalidSignatureValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeInvalidSignatureDecimal))
}

// AuthenticateErrorCodeUnsupportedCurveValue returns the named value unsupportedCurve.
func AuthenticateErrorCodeUnsupportedCurveValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeUnsupportedCurveDecimal))
}

// AuthenticateErrorCodeNoSessionContextValue returns the named value noSessionContext.
func AuthenticateErrorCodeNoSessionContextValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeNoSessionContextDecimal))
}

// AuthenticateErrorCodeInvalidOidValue returns the named value invalidOid.
func AuthenticateErrorCodeInvalidOidValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeInvalidOidDecimal))
}

// AuthenticateErrorCodeEuiccChallengeMismatchValue returns the named value euiccChallengeMismatch.
func AuthenticateErrorCodeEuiccChallengeMismatchValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeEuiccChallengeMismatchDecimal))
}

// AuthenticateErrorCodeCiPKUnknownValue returns the named value ciPKUnknown.
func AuthenticateErrorCodeCiPKUnknownValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeCiPKUnknownDecimal))
}

// AuthenticateErrorCodeUndefinedErrorValue returns the named value undefinedError.
func AuthenticateErrorCodeUndefinedErrorValue() AuthenticateErrorCode {
	return NewAuthenticateErrorCode(runtime.MustParseBigIntDecimal(AuthenticateErrorCodeUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v AuthenticateErrorCode) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v AuthenticateErrorCode) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v AuthenticateErrorCode) Name() (string, bool) {
	switch v.BigInt().String() {
	case AuthenticateErrorCodeInvalidCertificateDecimal:
		return "invalidCertificate", true
	case AuthenticateErrorCodeInvalidSignatureDecimal:
		return "invalidSignature", true
	case AuthenticateErrorCodeUnsupportedCurveDecimal:
		return "unsupportedCurve", true
	case AuthenticateErrorCodeNoSessionContextDecimal:
		return "noSessionContext", true
	case AuthenticateErrorCodeInvalidOidDecimal:
		return "invalidOid", true
	case AuthenticateErrorCodeEuiccChallengeMismatchDecimal:
		return "euiccChallengeMismatch", true
	case AuthenticateErrorCodeCiPKUnknownDecimal:
		return "ciPKUnknown", true
	case AuthenticateErrorCodeUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v AuthenticateErrorCode) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v AuthenticateErrorCode) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *AuthenticateErrorCode) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AuthenticateErrorCode into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewAuthenticateErrorCode(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v AuthenticateErrorCode) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *AuthenticateErrorCode) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AuthenticateErrorCode into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewAuthenticateErrorCode(value)
	return nil
}

// CancelSessionRequest represents the ASN.1 type CancelSessionRequest (SEQUENCE).
type CancelSessionRequest struct {
	TransactionId TransactionId       `asn1:"tag:0,context,implicit"`
	Reason        CancelSessionReason `asn1:"tag:1,context,implicit"`
	ExtCount_     int64               `asn1:"-" json:"-"`
	ExtPresent_   []bool              `asn1:"-" json:"-"`
	ExtData_      [][]byte            `asn1:"-" json:"-"`
}

// CancelSessionReason represents the arbitrary-width ASN.1 INTEGER type CancelSessionReason with named numbers.
type CancelSessionReason struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	CancelSessionReasonEndUserRejectionDecimal      = "0"
	CancelSessionReasonEndUserRejection             = 0
	CancelSessionReasonPostponedDecimal             = "1"
	CancelSessionReasonPostponed                    = 1
	CancelSessionReasonTimeoutDecimal               = "2"
	CancelSessionReasonTimeout                      = 2
	CancelSessionReasonPprNotAllowedDecimal         = "3"
	CancelSessionReasonPprNotAllowed                = 3
	CancelSessionReasonMetadataMismatchDecimal      = "4"
	CancelSessionReasonMetadataMismatch             = 4
	CancelSessionReasonLoadBppExecutionErrorDecimal = "5"
	CancelSessionReasonLoadBppExecutionError        = 5
	CancelSessionReasonUndefinedReasonDecimal       = "127"
	CancelSessionReasonUndefinedReason              = 127
)

// NewCancelSessionReason returns an immutable CancelSessionReason containing value.
func NewCancelSessionReason(value *big.Int) CancelSessionReason {
	return CancelSessionReason{value: runtime.CloneBigInt(value)}
}

// NewCancelSessionReasonInt64 returns a CancelSessionReason containing value.
func NewCancelSessionReasonInt64(value int64) CancelSessionReason {
	return NewCancelSessionReason(big.NewInt(value))
}

// CancelSessionReasonEndUserRejectionValue returns the named value endUserRejection.
func CancelSessionReasonEndUserRejectionValue() CancelSessionReason {
	return NewCancelSessionReason(runtime.MustParseBigIntDecimal(CancelSessionReasonEndUserRejectionDecimal))
}

// CancelSessionReasonPostponedValue returns the named value postponed.
func CancelSessionReasonPostponedValue() CancelSessionReason {
	return NewCancelSessionReason(runtime.MustParseBigIntDecimal(CancelSessionReasonPostponedDecimal))
}

// CancelSessionReasonTimeoutValue returns the named value timeout.
func CancelSessionReasonTimeoutValue() CancelSessionReason {
	return NewCancelSessionReason(runtime.MustParseBigIntDecimal(CancelSessionReasonTimeoutDecimal))
}

// CancelSessionReasonPprNotAllowedValue returns the named value pprNotAllowed.
func CancelSessionReasonPprNotAllowedValue() CancelSessionReason {
	return NewCancelSessionReason(runtime.MustParseBigIntDecimal(CancelSessionReasonPprNotAllowedDecimal))
}

// CancelSessionReasonMetadataMismatchValue returns the named value metadataMismatch.
func CancelSessionReasonMetadataMismatchValue() CancelSessionReason {
	return NewCancelSessionReason(runtime.MustParseBigIntDecimal(CancelSessionReasonMetadataMismatchDecimal))
}

// CancelSessionReasonLoadBppExecutionErrorValue returns the named value loadBppExecutionError.
func CancelSessionReasonLoadBppExecutionErrorValue() CancelSessionReason {
	return NewCancelSessionReason(runtime.MustParseBigIntDecimal(CancelSessionReasonLoadBppExecutionErrorDecimal))
}

// CancelSessionReasonUndefinedReasonValue returns the named value undefinedReason.
func CancelSessionReasonUndefinedReasonValue() CancelSessionReason {
	return NewCancelSessionReason(runtime.MustParseBigIntDecimal(CancelSessionReasonUndefinedReasonDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v CancelSessionReason) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v CancelSessionReason) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v CancelSessionReason) Name() (string, bool) {
	switch v.BigInt().String() {
	case CancelSessionReasonEndUserRejectionDecimal:
		return "endUserRejection", true
	case CancelSessionReasonPostponedDecimal:
		return "postponed", true
	case CancelSessionReasonTimeoutDecimal:
		return "timeout", true
	case CancelSessionReasonPprNotAllowedDecimal:
		return "pprNotAllowed", true
	case CancelSessionReasonMetadataMismatchDecimal:
		return "metadataMismatch", true
	case CancelSessionReasonLoadBppExecutionErrorDecimal:
		return "loadBppExecutionError", true
	case CancelSessionReasonUndefinedReasonDecimal:
		return "undefinedReason", true
	default:
		return "", false
	}
}

func (v CancelSessionReason) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v CancelSessionReason) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *CancelSessionReason) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal CancelSessionReason into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewCancelSessionReason(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v CancelSessionReason) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *CancelSessionReason) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal CancelSessionReason into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewCancelSessionReason(value)
	return nil
}

// CancelSessionResponse choice constants.
const (
	CancelSessionResponseChoiceCancelSessionResponseOk    = 1
	CancelSessionResponseChoiceCancelSessionResponseError = 2
)

// CancelSessionResponse represents the ASN.1 CHOICE type CancelSessionResponse.
type CancelSessionResponse struct {
	Choice                     int
	CancelSessionResponseOk    *CancelSessionResponseOk                              `json:"CancelSessionResponseOk,omitempty"`
	CancelSessionResponseError *CancelSessionResponseCancelSessionResponseErrorValue `json:"CancelSessionResponseError,omitempty"`
}

// NewCancelSessionResponseCancelSessionResponseOk creates a CancelSessionResponse with the cancelSessionResponseOk alternative.
func NewCancelSessionResponseCancelSessionResponseOk(v CancelSessionResponseOk) CancelSessionResponse {
	return CancelSessionResponse{
		Choice:                  CancelSessionResponseChoiceCancelSessionResponseOk,
		CancelSessionResponseOk: &v,
	}
}

// NewCancelSessionResponseCancelSessionResponseError creates a CancelSessionResponse with the cancelSessionResponseError alternative.
func NewCancelSessionResponseCancelSessionResponseError(v CancelSessionResponseCancelSessionResponseErrorValue) CancelSessionResponse {
	return CancelSessionResponse{
		Choice:                     CancelSessionResponseChoiceCancelSessionResponseError,
		CancelSessionResponseError: &v,
	}
}

// CancelSessionResponseOk represents the ASN.1 type CancelSessionResponseOk (SEQUENCE).
type CancelSessionResponseOk struct {
	EuiccCancelSessionSigned    EuiccCancelSessionSigned `asn1:""`
	EuiccCancelSessionSignature []byte                   `asn1:"tag:55,application,implicit"`
	ExtCount_                   int64                    `asn1:"-" json:"-"`
	ExtPresent_                 []bool                   `asn1:"-" json:"-"`
	ExtData_                    [][]byte                 `asn1:"-" json:"-"`
}

// EuiccCancelSessionSigned represents the ASN.1 type EuiccCancelSessionSigned (SEQUENCE).
type EuiccCancelSessionSigned struct {
	TransactionId TransactionId            `asn1:"tag:0,context,implicit"`
	SmdpOid       runtime.ObjectIdentifier `asn1:"tag:1,context,implicit"`
	Reason        CancelSessionReason      `asn1:"tag:2,context,implicit"`
	ExtCount_     int64                    `asn1:"-" json:"-"`
	ExtPresent_   []bool                   `asn1:"-" json:"-"`
	ExtData_      [][]byte                 `asn1:"-" json:"-"`
}

// ProfileInfoListRequest represents the ASN.1 type ProfileInfoListRequest (SEQUENCE).
type ProfileInfoListRequest struct {
	SearchCriteria     *ProfileInfoListRequestSearchCriteria `asn1:"tag:0,context,explicit,optional" json:"SearchCriteria,omitempty"`
	TagList            []byte                                `asn1:"tag:28,application,implicit,optional" json:"TagList,omitempty"`
	IotSpecificTagList []byte                                `asn1:"tag:29,application,implicit,optional" json:"IotSpecificTagList,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// ProfileInfoListResponse choice constants.
const (
	ProfileInfoListResponseChoiceProfileInfoListOk    = 1
	ProfileInfoListResponseChoiceProfileInfoListError = 2
)

// ProfileInfoListResponse represents the ASN.1 CHOICE type ProfileInfoListResponse.
type ProfileInfoListResponse struct {
	Choice               int
	ProfileInfoListOk    ProfileInfoListResponseProfileInfoListOk `json:"ProfileInfoListOk,omitempty"`
	ProfileInfoListError *ProfileInfoListError                    `json:"ProfileInfoListError,omitempty"`
}

// NewProfileInfoListResponseProfileInfoListOk creates a ProfileInfoListResponse with the profileInfoListOk alternative.
func NewProfileInfoListResponseProfileInfoListOk(v ProfileInfoListResponseProfileInfoListOk) ProfileInfoListResponse {
	return ProfileInfoListResponse{
		Choice:            ProfileInfoListResponseChoiceProfileInfoListOk,
		ProfileInfoListOk: v,
	}
}

// NewProfileInfoListResponseProfileInfoListError creates a ProfileInfoListResponse with the profileInfoListError alternative.
func NewProfileInfoListResponseProfileInfoListError(v ProfileInfoListError) ProfileInfoListResponse {
	return ProfileInfoListResponse{
		Choice:               ProfileInfoListResponseChoiceProfileInfoListError,
		ProfileInfoListError: &v,
	}
}

// ProfileInfo represents the ASN.1 type ProfileInfo (SEQUENCE).
type ProfileInfo struct {
	Iccid                                  *Iccid                                   `asn1:",optional" json:"Iccid,omitempty"`
	IsdpAid                                *OctetTo16                               `asn1:"tag:15,application,implicit,optional" json:"IsdpAid,omitempty"`
	ProfileState                           *ProfileState                            `asn1:"tag:112,context,implicit,optional" json:"ProfileState,omitempty"`
	ProfileNickname                        *string                                  `asn1:"tag:16,context,implicit,optional" json:"ProfileNickname,omitempty"`
	ServiceProviderName                    *string                                  `asn1:"tag:17,context,implicit,optional" json:"ServiceProviderName,omitempty"`
	ProfileName                            *string                                  `asn1:"tag:18,context,implicit,optional" json:"ProfileName,omitempty"`
	IconType                               *IconType                                `asn1:"tag:19,context,implicit,optional" json:"IconType,omitempty"`
	Icon                                   []byte                                   `asn1:"tag:20,context,implicit,optional" json:"Icon,omitempty"`
	ProfileClass                           *ProfileClass                            `asn1:"tag:21,context,implicit,optional" json:"ProfileClass,omitempty"`
	NotificationConfigurationInfo          ProfileInfoNotificationConfigurationInfo `asn1:"tag:22,context,implicit,optional" json:"NotificationConfigurationInfo,omitempty"`
	NotificationConfigurationInfoIndef_    bool                                     `asn1:"-" json:"-"`
	ProfileOwner                           *OperatorId                              `asn1:"tag:23,context,implicit,optional" json:"ProfileOwner,omitempty"`
	DpProprietaryData                      *DpProprietaryData                       `asn1:"tag:24,context,implicit,optional" json:"DpProprietaryData,omitempty"`
	ProfilePolicyRules                     *PprIds                                  `asn1:"tag:25,context,implicit,optional" json:"ProfilePolicyRules,omitempty"`
	ServiceSpecificDataStoredInEuicc       VendorSpecificExtension                  `asn1:"tag:34,context,implicit,optional" json:"ServiceSpecificDataStoredInEuicc,omitempty"`
	ServiceSpecificDataStoredInEuiccIndef_ bool                                     `asn1:"-" json:"-"`
	EcallIndication                        *bool                                    `asn1:"tag:123,context,implicit,optional" json:"EcallIndication,omitempty"`
	EcallIndicationRaw_                    byte                                     `asn1:"-" json:"-"`
	FallbackAttribute                      *bool                                    `asn1:"tag:38,context,implicit,optional" json:"FallbackAttribute,omitempty"`
	FallbackAttributeRaw_                  byte                                     `asn1:"-" json:"-"`
	FallbackAllowed                        *bool                                    `asn1:"tag:103,context,implicit,optional" json:"FallbackAllowed,omitempty"`
	FallbackAllowedRaw_                    byte                                     `asn1:"-" json:"-"`
	IotSpecificProfileInfo                 *ProfileInfoIotSpecificProfileInfo       `asn1:"tag:100,context,implicit,optional" json:"IotSpecificProfileInfo,omitempty"`
	ExtCount_                              int64                                    `asn1:"-" json:"-"`
	ExtPresent_                            []bool                                   `asn1:"-" json:"-"`
	ExtData_                               [][]byte                                 `asn1:"-" json:"-"`
}

// IconType represents the arbitrary-width ASN.1 INTEGER type IconType with named numbers.
type IconType struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	IconTypeJpgDecimal = "0"
	IconTypeJpg        = 0
	IconTypePngDecimal = "1"
	IconTypePng        = 1
)

// NewIconType returns an immutable IconType containing value.
func NewIconType(value *big.Int) IconType {
	return IconType{value: runtime.CloneBigInt(value)}
}

// NewIconTypeInt64 returns a IconType containing value.
func NewIconTypeInt64(value int64) IconType {
	return NewIconType(big.NewInt(value))
}

// IconTypeJpgValue returns the named value jpg.
func IconTypeJpgValue() IconType {
	return NewIconType(runtime.MustParseBigIntDecimal(IconTypeJpgDecimal))
}

// IconTypePngValue returns the named value png.
func IconTypePngValue() IconType {
	return NewIconType(runtime.MustParseBigIntDecimal(IconTypePngDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v IconType) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v IconType) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v IconType) Name() (string, bool) {
	switch v.BigInt().String() {
	case IconTypeJpgDecimal:
		return "jpg", true
	case IconTypePngDecimal:
		return "png", true
	default:
		return "", false
	}
}

func (v IconType) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v IconType) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *IconType) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal IconType into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewIconType(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v IconType) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *IconType) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal IconType into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewIconType(value)
	return nil
}

// ProfileState represents the arbitrary-width ASN.1 INTEGER type ProfileState with named numbers.
type ProfileState struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ProfileStateDisabledDecimal = "0"
	ProfileStateDisabled        = 0
	ProfileStateEnabledDecimal  = "1"
	ProfileStateEnabled         = 1
)

// NewProfileState returns an immutable ProfileState containing value.
func NewProfileState(value *big.Int) ProfileState {
	return ProfileState{value: runtime.CloneBigInt(value)}
}

// NewProfileStateInt64 returns a ProfileState containing value.
func NewProfileStateInt64(value int64) ProfileState {
	return NewProfileState(big.NewInt(value))
}

// ProfileStateDisabledValue returns the named value disabled.
func ProfileStateDisabledValue() ProfileState {
	return NewProfileState(runtime.MustParseBigIntDecimal(ProfileStateDisabledDecimal))
}

// ProfileStateEnabledValue returns the named value enabled.
func ProfileStateEnabledValue() ProfileState {
	return NewProfileState(runtime.MustParseBigIntDecimal(ProfileStateEnabledDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ProfileState) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ProfileState) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ProfileState) Name() (string, bool) {
	switch v.BigInt().String() {
	case ProfileStateDisabledDecimal:
		return "disabled", true
	case ProfileStateEnabledDecimal:
		return "enabled", true
	default:
		return "", false
	}
}

func (v ProfileState) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ProfileState) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ProfileState) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ProfileState into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewProfileState(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ProfileState) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ProfileState) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ProfileState into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewProfileState(value)
	return nil
}

// ProfileClass represents the arbitrary-width ASN.1 INTEGER type ProfileClass with named numbers.
type ProfileClass struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ProfileClassTestDecimal         = "0"
	ProfileClassTest                = 0
	ProfileClassProvisioningDecimal = "1"
	ProfileClassProvisioning        = 1
	ProfileClassOperationalDecimal  = "2"
	ProfileClassOperational         = 2
)

// NewProfileClass returns an immutable ProfileClass containing value.
func NewProfileClass(value *big.Int) ProfileClass {
	return ProfileClass{value: runtime.CloneBigInt(value)}
}

// NewProfileClassInt64 returns a ProfileClass containing value.
func NewProfileClassInt64(value int64) ProfileClass {
	return NewProfileClass(big.NewInt(value))
}

// ProfileClassTestValue returns the named value test.
func ProfileClassTestValue() ProfileClass {
	return NewProfileClass(runtime.MustParseBigIntDecimal(ProfileClassTestDecimal))
}

// ProfileClassProvisioningValue returns the named value provisioning.
func ProfileClassProvisioningValue() ProfileClass {
	return NewProfileClass(runtime.MustParseBigIntDecimal(ProfileClassProvisioningDecimal))
}

// ProfileClassOperationalValue returns the named value operational.
func ProfileClassOperationalValue() ProfileClass {
	return NewProfileClass(runtime.MustParseBigIntDecimal(ProfileClassOperationalDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ProfileClass) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ProfileClass) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ProfileClass) Name() (string, bool) {
	switch v.BigInt().String() {
	case ProfileClassTestDecimal:
		return "test", true
	case ProfileClassProvisioningDecimal:
		return "provisioning", true
	case ProfileClassOperationalDecimal:
		return "operational", true
	default:
		return "", false
	}
}

func (v ProfileClass) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ProfileClass) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ProfileClass) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ProfileClass into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewProfileClass(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ProfileClass) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ProfileClass) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ProfileClass into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewProfileClass(value)
	return nil
}

// ProfileInfoListError represents the arbitrary-width ASN.1 INTEGER type ProfileInfoListError with named numbers.
type ProfileInfoListError struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ProfileInfoListErrorIncorrectInputValuesDecimal = "1"
	ProfileInfoListErrorIncorrectInputValues        = 1
	ProfileInfoListErrorUndefinedErrorDecimal       = "127"
	ProfileInfoListErrorUndefinedError              = 127
)

// NewProfileInfoListError returns an immutable ProfileInfoListError containing value.
func NewProfileInfoListError(value *big.Int) ProfileInfoListError {
	return ProfileInfoListError{value: runtime.CloneBigInt(value)}
}

// NewProfileInfoListErrorInt64 returns a ProfileInfoListError containing value.
func NewProfileInfoListErrorInt64(value int64) ProfileInfoListError {
	return NewProfileInfoListError(big.NewInt(value))
}

// ProfileInfoListErrorIncorrectInputValuesValue returns the named value incorrectInputValues.
func ProfileInfoListErrorIncorrectInputValuesValue() ProfileInfoListError {
	return NewProfileInfoListError(runtime.MustParseBigIntDecimal(ProfileInfoListErrorIncorrectInputValuesDecimal))
}

// ProfileInfoListErrorUndefinedErrorValue returns the named value undefinedError.
func ProfileInfoListErrorUndefinedErrorValue() ProfileInfoListError {
	return NewProfileInfoListError(runtime.MustParseBigIntDecimal(ProfileInfoListErrorUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ProfileInfoListError) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ProfileInfoListError) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ProfileInfoListError) Name() (string, bool) {
	switch v.BigInt().String() {
	case ProfileInfoListErrorIncorrectInputValuesDecimal:
		return "incorrectInputValues", true
	case ProfileInfoListErrorUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v ProfileInfoListError) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ProfileInfoListError) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ProfileInfoListError) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ProfileInfoListError into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewProfileInfoListError(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ProfileInfoListError) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ProfileInfoListError) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ProfileInfoListError into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewProfileInfoListError(value)
	return nil
}

// EnableProfileRequest represents the ASN.1 type EnableProfileRequest (SEQUENCE).
type EnableProfileRequest struct {
	ProfileIdentifier EnableProfileRequestProfileIdentifier `asn1:"tag:0,context,explicit"`
	RefreshFlag       bool                                  `asn1:"tag:1,context,implicit"`
	RefreshFlagRaw_   byte                                  `asn1:"-" json:"-"`
	ExtCount_         int64                                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                                `asn1:"-" json:"-"`
	ExtData_          [][]byte                              `asn1:"-" json:"-"`
}

// EnableProfileResponse represents the ASN.1 type EnableProfileResponse (SEQUENCE).
type EnableProfileResponse struct {
	EnableResult EnableProfileResponseEnableResultValue `asn1:"tag:0,context,implicit"`
	ExtCount_    int64                                  `asn1:"-" json:"-"`
	ExtPresent_  []bool                                 `asn1:"-" json:"-"`
	ExtData_     [][]byte                               `asn1:"-" json:"-"`
}

// DisableProfileRequest represents the ASN.1 type DisableProfileRequest (SEQUENCE).
type DisableProfileRequest struct {
	ProfileIdentifier DisableProfileRequestProfileIdentifier `asn1:"tag:0,context,explicit"`
	RefreshFlag       bool                                   `asn1:"tag:1,context,implicit"`
	RefreshFlagRaw_   byte                                   `asn1:"-" json:"-"`
	ExtCount_         int64                                  `asn1:"-" json:"-"`
	ExtPresent_       []bool                                 `asn1:"-" json:"-"`
	ExtData_          [][]byte                               `asn1:"-" json:"-"`
}

// DisableProfileResponse represents the ASN.1 type DisableProfileResponse (SEQUENCE).
type DisableProfileResponse struct {
	DisableResult DisableProfileResponseDisableResultValue `asn1:"tag:0,context,implicit"`
	ExtCount_     int64                                    `asn1:"-" json:"-"`
	ExtPresent_   []bool                                   `asn1:"-" json:"-"`
	ExtData_      [][]byte                                 `asn1:"-" json:"-"`
}

// DeleteProfileRequest choice constants.
const (
	DeleteProfileRequestChoiceIsdpAid = 1
	DeleteProfileRequestChoiceIccid   = 2
)

// DeleteProfileRequest represents the ASN.1 CHOICE type DeleteProfileRequest.
type DeleteProfileRequest struct {
	Choice  int
	IsdpAid *OctetTo16 `json:"IsdpAid,omitempty"`
	Iccid   *Iccid     `json:"Iccid,omitempty"`
}

// NewDeleteProfileRequestIsdpAid creates a DeleteProfileRequest with the isdpAid alternative.
func NewDeleteProfileRequestIsdpAid(v OctetTo16) DeleteProfileRequest {
	return DeleteProfileRequest{
		Choice:  DeleteProfileRequestChoiceIsdpAid,
		IsdpAid: &v,
	}
}

// NewDeleteProfileRequestIccid creates a DeleteProfileRequest with the iccid alternative.
func NewDeleteProfileRequestIccid(v Iccid) DeleteProfileRequest {
	return DeleteProfileRequest{
		Choice: DeleteProfileRequestChoiceIccid,
		Iccid:  &v,
	}
}

// DeleteProfileResponse represents the ASN.1 type DeleteProfileResponse (SEQUENCE).
type DeleteProfileResponse struct {
	DeleteResult DeleteProfileResponseDeleteResultValue `asn1:"tag:0,context,implicit"`
	ExtCount_    int64                                  `asn1:"-" json:"-"`
	ExtPresent_  []bool                                 `asn1:"-" json:"-"`
	ExtData_     [][]byte                               `asn1:"-" json:"-"`
}

// EuiccMemoryResetRequest represents the ASN.1 type EuiccMemoryResetRequest (SEQUENCE).
type EuiccMemoryResetRequest struct {
	ResetOptions runtime.BitString `asn1:"tag:2,context,implicit"`
	ExtCount_    int64             `asn1:"-" json:"-"`
	ExtPresent_  []bool            `asn1:"-" json:"-"`
	ExtData_     [][]byte          `asn1:"-" json:"-"`
}

// EuiccMemoryResetResponse represents the ASN.1 type EuiccMemoryResetResponse (SEQUENCE).
type EuiccMemoryResetResponse struct {
	ResetResult EuiccMemoryResetResponseResetResultValue `asn1:"tag:0,context,implicit"`
	ExtCount_   int64                                    `asn1:"-" json:"-"`
	ExtPresent_ []bool                                   `asn1:"-" json:"-"`
	ExtData_    [][]byte                                 `asn1:"-" json:"-"`
}

// GetEuiccDataRequest represents the ASN.1 type GetEuiccDataRequest (SEQUENCE).
type GetEuiccDataRequest struct {
	TagList     Octet1   `asn1:"tag:28,application,implicit"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// GetEuiccDataResponse represents the ASN.1 type GetEuiccDataResponse (SEQUENCE).
type GetEuiccDataResponse struct {
	EidValue    Octet16  `asn1:"tag:26,application,implicit"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// SetNicknameRequest represents the ASN.1 type SetNicknameRequest (SEQUENCE).
type SetNicknameRequest struct {
	Iccid           Iccid    `asn1:""`
	ProfileNickname string   `asn1:"tag:16,context,implicit"`
	ExtCount_       int64    `asn1:"-" json:"-"`
	ExtPresent_     []bool   `asn1:"-" json:"-"`
	ExtData_        [][]byte `asn1:"-" json:"-"`
}

// SetNicknameResponse represents the ASN.1 type SetNicknameResponse (SEQUENCE).
type SetNicknameResponse struct {
	SetNicknameResult SetNicknameResponseSetNicknameResultValue `asn1:"tag:0,context,implicit"`
	ExtCount_         int64                                     `asn1:"-" json:"-"`
	ExtPresent_       []bool                                    `asn1:"-" json:"-"`
	ExtData_          [][]byte                                  `asn1:"-" json:"-"`
}

// GetRatRequest represents the ASN.1 type GetRatRequest (SEQUENCE).
type GetRatRequest struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// GetRatResponse represents the ASN.1 type GetRatResponse (SEQUENCE).
type GetRatResponse struct {
	Rat         RulesAuthorisationTable `asn1:"tag:0,context,implicit"`
	RatIndef_   bool                    `asn1:"-" json:"-"`
	ExtCount_   int64                   `asn1:"-" json:"-"`
	ExtPresent_ []bool                  `asn1:"-" json:"-"`
	ExtData_    [][]byte                `asn1:"-" json:"-"`
}

// RulesAuthorisationTable represents the ASN.1 type RulesAuthorisationTable (SEQUENCE_OF).
type RulesAuthorisationTable = []ProfilePolicyAuthorisationRule

// ProfilePolicyAuthorisationRule represents the ASN.1 type ProfilePolicyAuthorisationRule (SEQUENCE).
type ProfilePolicyAuthorisationRule struct {
	PprIds                 PprIds                                         `asn1:"tag:0,context,implicit"`
	AllowedOperators       ProfilePolicyAuthorisationRuleAllowedOperators `asn1:"tag:1,context,implicit"`
	AllowedOperatorsIndef_ bool                                           `asn1:"-" json:"-"`
	PprFlags               runtime.BitString                              `asn1:"tag:2,context,implicit"`
	ExtCount_              int64                                          `asn1:"-" json:"-"`
	ExtPresent_            []bool                                         `asn1:"-" json:"-"`
	ExtData_               [][]byte                                       `asn1:"-" json:"-"`
}

// RemoteProfileProvisioningRequest choice constants.
const (
	RemoteProfileProvisioningRequestChoiceInitiateAuthenticationRequest = 1
	RemoteProfileProvisioningRequestChoiceAuthenticateClientRequest     = 2
	RemoteProfileProvisioningRequestChoiceGetBoundProfilePackageRequest = 3
	RemoteProfileProvisioningRequestChoiceCancelSessionRequestEs9       = 4
	RemoteProfileProvisioningRequestChoiceHandleNotification            = 5
)

// RemoteProfileProvisioningRequest represents the ASN.1 CHOICE type RemoteProfileProvisioningRequest.
type RemoteProfileProvisioningRequest struct {
	Choice                        int
	InitiateAuthenticationRequest *InitiateAuthenticationRequest `json:"InitiateAuthenticationRequest,omitempty"`
	AuthenticateClientRequest     *AuthenticateClientRequest     `json:"AuthenticateClientRequest,omitempty"`
	GetBoundProfilePackageRequest *GetBoundProfilePackageRequest `json:"GetBoundProfilePackageRequest,omitempty"`
	CancelSessionRequestEs9       *CancelSessionRequestEs9       `json:"CancelSessionRequestEs9,omitempty"`
	HandleNotification            *HandleNotification            `json:"HandleNotification,omitempty"`
}

// NewRemoteProfileProvisioningRequestInitiateAuthenticationRequest creates a RemoteProfileProvisioningRequest with the initiateAuthenticationRequest alternative.
func NewRemoteProfileProvisioningRequestInitiateAuthenticationRequest(v InitiateAuthenticationRequest) RemoteProfileProvisioningRequest {
	return RemoteProfileProvisioningRequest{
		Choice:                        RemoteProfileProvisioningRequestChoiceInitiateAuthenticationRequest,
		InitiateAuthenticationRequest: &v,
	}
}

// NewRemoteProfileProvisioningRequestAuthenticateClientRequest creates a RemoteProfileProvisioningRequest with the authenticateClientRequest alternative.
func NewRemoteProfileProvisioningRequestAuthenticateClientRequest(v AuthenticateClientRequest) RemoteProfileProvisioningRequest {
	return RemoteProfileProvisioningRequest{
		Choice:                    RemoteProfileProvisioningRequestChoiceAuthenticateClientRequest,
		AuthenticateClientRequest: &v,
	}
}

// NewRemoteProfileProvisioningRequestGetBoundProfilePackageRequest creates a RemoteProfileProvisioningRequest with the getBoundProfilePackageRequest alternative.
func NewRemoteProfileProvisioningRequestGetBoundProfilePackageRequest(v GetBoundProfilePackageRequest) RemoteProfileProvisioningRequest {
	return RemoteProfileProvisioningRequest{
		Choice:                        RemoteProfileProvisioningRequestChoiceGetBoundProfilePackageRequest,
		GetBoundProfilePackageRequest: &v,
	}
}

// NewRemoteProfileProvisioningRequestCancelSessionRequestEs9 creates a RemoteProfileProvisioningRequest with the cancelSessionRequestEs9 alternative.
func NewRemoteProfileProvisioningRequestCancelSessionRequestEs9(v CancelSessionRequestEs9) RemoteProfileProvisioningRequest {
	return RemoteProfileProvisioningRequest{
		Choice:                  RemoteProfileProvisioningRequestChoiceCancelSessionRequestEs9,
		CancelSessionRequestEs9: &v,
	}
}

// NewRemoteProfileProvisioningRequestHandleNotification creates a RemoteProfileProvisioningRequest with the handleNotification alternative.
func NewRemoteProfileProvisioningRequestHandleNotification(v HandleNotification) RemoteProfileProvisioningRequest {
	return RemoteProfileProvisioningRequest{
		Choice:             RemoteProfileProvisioningRequestChoiceHandleNotification,
		HandleNotification: &v,
	}
}

// RemoteProfileProvisioningResponse choice constants.
const (
	RemoteProfileProvisioningResponseChoiceInitiateAuthenticationResponse = 1
	RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs9  = 2
	RemoteProfileProvisioningResponseChoiceGetBoundProfilePackageResponse = 3
	RemoteProfileProvisioningResponseChoiceCancelSessionResponseEs9       = 4
	RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs11 = 5
)

// RemoteProfileProvisioningResponse represents the ASN.1 CHOICE type RemoteProfileProvisioningResponse.
type RemoteProfileProvisioningResponse struct {
	Choice                         int
	InitiateAuthenticationResponse *InitiateAuthenticationResponse `json:"InitiateAuthenticationResponse,omitempty"`
	AuthenticateClientResponseEs9  *AuthenticateClientResponseEs9  `json:"AuthenticateClientResponseEs9,omitempty"`
	GetBoundProfilePackageResponse *GetBoundProfilePackageResponse `json:"GetBoundProfilePackageResponse,omitempty"`
	CancelSessionResponseEs9       *CancelSessionResponseEs9       `json:"CancelSessionResponseEs9,omitempty"`
	AuthenticateClientResponseEs11 *AuthenticateClientResponseEs11 `json:"AuthenticateClientResponseEs11,omitempty"`
}

// NewRemoteProfileProvisioningResponseInitiateAuthenticationResponse creates a RemoteProfileProvisioningResponse with the initiateAuthenticationResponse alternative.
func NewRemoteProfileProvisioningResponseInitiateAuthenticationResponse(v InitiateAuthenticationResponse) RemoteProfileProvisioningResponse {
	return RemoteProfileProvisioningResponse{
		Choice:                         RemoteProfileProvisioningResponseChoiceInitiateAuthenticationResponse,
		InitiateAuthenticationResponse: &v,
	}
}

// NewRemoteProfileProvisioningResponseAuthenticateClientResponseEs9 creates a RemoteProfileProvisioningResponse with the authenticateClientResponseEs9 alternative.
func NewRemoteProfileProvisioningResponseAuthenticateClientResponseEs9(v AuthenticateClientResponseEs9) RemoteProfileProvisioningResponse {
	return RemoteProfileProvisioningResponse{
		Choice:                        RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs9,
		AuthenticateClientResponseEs9: &v,
	}
}

// NewRemoteProfileProvisioningResponseGetBoundProfilePackageResponse creates a RemoteProfileProvisioningResponse with the getBoundProfilePackageResponse alternative.
func NewRemoteProfileProvisioningResponseGetBoundProfilePackageResponse(v GetBoundProfilePackageResponse) RemoteProfileProvisioningResponse {
	return RemoteProfileProvisioningResponse{
		Choice:                         RemoteProfileProvisioningResponseChoiceGetBoundProfilePackageResponse,
		GetBoundProfilePackageResponse: &v,
	}
}

// NewRemoteProfileProvisioningResponseCancelSessionResponseEs9 creates a RemoteProfileProvisioningResponse with the cancelSessionResponseEs9 alternative.
func NewRemoteProfileProvisioningResponseCancelSessionResponseEs9(v CancelSessionResponseEs9) RemoteProfileProvisioningResponse {
	return RemoteProfileProvisioningResponse{
		Choice:                   RemoteProfileProvisioningResponseChoiceCancelSessionResponseEs9,
		CancelSessionResponseEs9: &v,
	}
}

// NewRemoteProfileProvisioningResponseAuthenticateClientResponseEs11 creates a RemoteProfileProvisioningResponse with the authenticateClientResponseEs11 alternative.
func NewRemoteProfileProvisioningResponseAuthenticateClientResponseEs11(v AuthenticateClientResponseEs11) RemoteProfileProvisioningResponse {
	return RemoteProfileProvisioningResponse{
		Choice:                         RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs11,
		AuthenticateClientResponseEs11: &v,
	}
}

// InitiateAuthenticationRequest represents the ASN.1 type InitiateAuthenticationRequest (SEQUENCE).
type InitiateAuthenticationRequest struct {
	EuiccChallenge Octet16    `asn1:"tag:1,context,implicit"`
	SmdpAddress    string     `asn1:"tag:3,context,implicit"`
	EuiccInfo1     EUICCInfo1 `asn1:""`
	ExtCount_      int64      `asn1:"-" json:"-"`
	ExtPresent_    []bool     `asn1:"-" json:"-"`
	ExtData_       [][]byte   `asn1:"-" json:"-"`
}

// InitiateAuthenticationResponse choice constants.
const (
	InitiateAuthenticationResponseChoiceInitiateAuthenticationOk    = 1
	InitiateAuthenticationResponseChoiceInitiateAuthenticationError = 2
)

// InitiateAuthenticationResponse represents the ASN.1 CHOICE type InitiateAuthenticationResponse.
type InitiateAuthenticationResponse struct {
	Choice                      int
	InitiateAuthenticationOk    *InitiateAuthenticationOkEs9                                    `json:"InitiateAuthenticationOk,omitempty"`
	InitiateAuthenticationError *InitiateAuthenticationResponseInitiateAuthenticationErrorValue `json:"InitiateAuthenticationError,omitempty"`
}

// NewInitiateAuthenticationResponseInitiateAuthenticationOk creates a InitiateAuthenticationResponse with the initiateAuthenticationOk alternative.
func NewInitiateAuthenticationResponseInitiateAuthenticationOk(v InitiateAuthenticationOkEs9) InitiateAuthenticationResponse {
	return InitiateAuthenticationResponse{
		Choice:                   InitiateAuthenticationResponseChoiceInitiateAuthenticationOk,
		InitiateAuthenticationOk: &v,
	}
}

// NewInitiateAuthenticationResponseInitiateAuthenticationError creates a InitiateAuthenticationResponse with the initiateAuthenticationError alternative.
func NewInitiateAuthenticationResponseInitiateAuthenticationError(v InitiateAuthenticationResponseInitiateAuthenticationErrorValue) InitiateAuthenticationResponse {
	return InitiateAuthenticationResponse{
		Choice:                      InitiateAuthenticationResponseChoiceInitiateAuthenticationError,
		InitiateAuthenticationError: &v,
	}
}

// InitiateAuthenticationOkEs9 represents the ASN.1 type InitiateAuthenticationOkEs9 (SEQUENCE).
type InitiateAuthenticationOkEs9 struct {
	TransactionId       TransactionId        `asn1:"tag:0,context,implicit"`
	ServerSigned1       ServerSigned1        `asn1:""`
	ServerSignature1    []byte               `asn1:"tag:55,application,implicit"`
	EuiccCiPKIdToBeUsed SubjectKeyIdentifier `asn1:""`
	ServerCertificate   Certificate          `asn1:""`
	ExtCount_           int64                `asn1:"-" json:"-"`
	ExtPresent_         []bool               `asn1:"-" json:"-"`
	ExtData_            [][]byte             `asn1:"-" json:"-"`
}

// AuthenticateClientRequest represents the ASN.1 type AuthenticateClientRequest (SEQUENCE).
type AuthenticateClientRequest struct {
	TransactionId              TransactionId              `asn1:"tag:0,context,implicit"`
	AuthenticateServerResponse AuthenticateServerResponse `asn1:"tag:56,context,explicit"`
	UseMatchingIdForAcr        *struct{}                  `asn1:",optional" json:"UseMatchingIdForAcr,omitempty"`
	ExtCount_                  int64                      `asn1:"-" json:"-"`
	ExtPresent_                []bool                     `asn1:"-" json:"-"`
	ExtData_                   [][]byte                   `asn1:"-" json:"-"`
}

// AuthenticateClientResponseEs9 choice constants.
const (
	AuthenticateClientResponseEs9ChoiceAuthenticateClientOk    = 1
	AuthenticateClientResponseEs9ChoiceAuthenticateClientError = 2
	AuthenticateClientResponseEs9ChoiceAuthenticateClientOkAcr = 3
)

// AuthenticateClientResponseEs9 represents the ASN.1 CHOICE type AuthenticateClientResponseEs9.
type AuthenticateClientResponseEs9 struct {
	Choice                  int
	AuthenticateClientOk    *AuthenticateClientOk                                      `json:"AuthenticateClientOk,omitempty"`
	AuthenticateClientError *AuthenticateClientResponseEs9AuthenticateClientErrorValue `json:"AuthenticateClientError,omitempty"`
	AuthenticateClientOkAcr *AuthenticateClientOkAcr                                   `json:"AuthenticateClientOkAcr,omitempty"`
}

// NewAuthenticateClientResponseEs9AuthenticateClientOk creates a AuthenticateClientResponseEs9 with the authenticateClientOk alternative.
func NewAuthenticateClientResponseEs9AuthenticateClientOk(v AuthenticateClientOk) AuthenticateClientResponseEs9 {
	return AuthenticateClientResponseEs9{
		Choice:               AuthenticateClientResponseEs9ChoiceAuthenticateClientOk,
		AuthenticateClientOk: &v,
	}
}

// NewAuthenticateClientResponseEs9AuthenticateClientError creates a AuthenticateClientResponseEs9 with the authenticateClientError alternative.
func NewAuthenticateClientResponseEs9AuthenticateClientError(v AuthenticateClientResponseEs9AuthenticateClientErrorValue) AuthenticateClientResponseEs9 {
	return AuthenticateClientResponseEs9{
		Choice:                  AuthenticateClientResponseEs9ChoiceAuthenticateClientError,
		AuthenticateClientError: &v,
	}
}

// NewAuthenticateClientResponseEs9AuthenticateClientOkAcr creates a AuthenticateClientResponseEs9 with the authenticateClientOkAcr alternative.
func NewAuthenticateClientResponseEs9AuthenticateClientOkAcr(v AuthenticateClientOkAcr) AuthenticateClientResponseEs9 {
	return AuthenticateClientResponseEs9{
		Choice:                  AuthenticateClientResponseEs9ChoiceAuthenticateClientOkAcr,
		AuthenticateClientOkAcr: &v,
	}
}

// AuthenticateClientOk represents the ASN.1 type AuthenticateClientOk (SEQUENCE).
type AuthenticateClientOk struct {
	TransactionId   TransactionId        `asn1:"tag:0,context,implicit"`
	ProfileMetaData StoreMetadataRequest `asn1:"tag:37,context,implicit"`
	SmdpSigned2     SmdpSigned2          `asn1:""`
	SmdpSignature2  []byte               `asn1:"tag:55,application,implicit"`
	SmdpCertificate Certificate          `asn1:""`
	ExtCount_       int64                `asn1:"-" json:"-"`
	ExtPresent_     []bool               `asn1:"-" json:"-"`
	ExtData_        [][]byte             `asn1:"-" json:"-"`
}

// AuthenticateClientOkAcr represents the ASN.1 type AuthenticateClientOkAcr (SEQUENCE).
type AuthenticateClientOkAcr struct {
	TransactionId   TransactionId        `asn1:"tag:0,context,implicit"`
	ProfileMetaData StoreMetadataRequest `asn1:"tag:37,context,implicit"`
	ExtCount_       int64                `asn1:"-" json:"-"`
	ExtPresent_     []bool               `asn1:"-" json:"-"`
	ExtData_        [][]byte             `asn1:"-" json:"-"`
}

// GetBoundProfilePackageRequest represents the ASN.1 type GetBoundProfilePackageRequest (SEQUENCE).
type GetBoundProfilePackageRequest struct {
	TransactionId           TransactionId           `asn1:"tag:0,context,implicit"`
	PrepareDownloadResponse PrepareDownloadResponse `asn1:"tag:33,context,explicit"`
	ExtCount_               int64                   `asn1:"-" json:"-"`
	ExtPresent_             []bool                  `asn1:"-" json:"-"`
	ExtData_                [][]byte                `asn1:"-" json:"-"`
}

// GetBoundProfilePackageResponse choice constants.
const (
	GetBoundProfilePackageResponseChoiceGetBoundProfilePackageOk    = 1
	GetBoundProfilePackageResponseChoiceGetBoundProfilePackageError = 2
)

// GetBoundProfilePackageResponse represents the ASN.1 CHOICE type GetBoundProfilePackageResponse.
type GetBoundProfilePackageResponse struct {
	Choice                      int
	GetBoundProfilePackageOk    *GetBoundProfilePackageOk                                       `json:"GetBoundProfilePackageOk,omitempty"`
	GetBoundProfilePackageError *GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue `json:"GetBoundProfilePackageError,omitempty"`
}

// NewGetBoundProfilePackageResponseGetBoundProfilePackageOk creates a GetBoundProfilePackageResponse with the getBoundProfilePackageOk alternative.
func NewGetBoundProfilePackageResponseGetBoundProfilePackageOk(v GetBoundProfilePackageOk) GetBoundProfilePackageResponse {
	return GetBoundProfilePackageResponse{
		Choice:                   GetBoundProfilePackageResponseChoiceGetBoundProfilePackageOk,
		GetBoundProfilePackageOk: &v,
	}
}

// NewGetBoundProfilePackageResponseGetBoundProfilePackageError creates a GetBoundProfilePackageResponse with the getBoundProfilePackageError alternative.
func NewGetBoundProfilePackageResponseGetBoundProfilePackageError(v GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) GetBoundProfilePackageResponse {
	return GetBoundProfilePackageResponse{
		Choice:                      GetBoundProfilePackageResponseChoiceGetBoundProfilePackageError,
		GetBoundProfilePackageError: &v,
	}
}

// GetBoundProfilePackageOk represents the ASN.1 type GetBoundProfilePackageOk (SEQUENCE).
type GetBoundProfilePackageOk struct {
	TransactionId       TransactionId       `asn1:"tag:0,context,implicit"`
	BoundProfilePackage BoundProfilePackage `asn1:"tag:54,context,implicit"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// HandleNotification represents the ASN.1 type HandleNotification (SEQUENCE).
type HandleNotification struct {
	PendingNotification PendingNotification `asn1:"tag:0,context,explicit"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// CancelSessionRequestEs9 represents the ASN.1 type CancelSessionRequestEs9 (SEQUENCE).
type CancelSessionRequestEs9 struct {
	TransactionId         TransactionId         `asn1:"tag:0,context,implicit"`
	CancelSessionResponse CancelSessionResponse `asn1:"tag:1,context,explicit"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	ExtData_              [][]byte              `asn1:"-" json:"-"`
}

// CancelSessionResponseEs9 choice constants.
const (
	CancelSessionResponseEs9ChoiceCancelSessionOk    = 1
	CancelSessionResponseEs9ChoiceCancelSessionError = 2
)

// CancelSessionResponseEs9 represents the ASN.1 CHOICE type CancelSessionResponseEs9.
type CancelSessionResponseEs9 struct {
	Choice             int
	CancelSessionOk    *CancelSessionOk                                 `json:"CancelSessionOk,omitempty"`
	CancelSessionError *CancelSessionResponseEs9CancelSessionErrorValue `json:"CancelSessionError,omitempty"`
}

// NewCancelSessionResponseEs9CancelSessionOk creates a CancelSessionResponseEs9 with the cancelSessionOk alternative.
func NewCancelSessionResponseEs9CancelSessionOk(v CancelSessionOk) CancelSessionResponseEs9 {
	return CancelSessionResponseEs9{
		Choice:          CancelSessionResponseEs9ChoiceCancelSessionOk,
		CancelSessionOk: &v,
	}
}

// NewCancelSessionResponseEs9CancelSessionError creates a CancelSessionResponseEs9 with the cancelSessionError alternative.
func NewCancelSessionResponseEs9CancelSessionError(v CancelSessionResponseEs9CancelSessionErrorValue) CancelSessionResponseEs9 {
	return CancelSessionResponseEs9{
		Choice:             CancelSessionResponseEs9ChoiceCancelSessionError,
		CancelSessionError: &v,
	}
}

// CancelSessionOk represents the ASN.1 type CancelSessionOk (SEQUENCE).
type CancelSessionOk struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// AuthenticateClientResponseEs11 choice constants.
const (
	AuthenticateClientResponseEs11ChoiceAuthenticateClientOk    = 1
	AuthenticateClientResponseEs11ChoiceAuthenticateClientError = 2
)

// AuthenticateClientResponseEs11 represents the ASN.1 CHOICE type AuthenticateClientResponseEs11.
type AuthenticateClientResponseEs11 struct {
	Choice                  int
	AuthenticateClientOk    *AuthenticateClientOkEs11                                   `json:"AuthenticateClientOk,omitempty"`
	AuthenticateClientError *AuthenticateClientResponseEs11AuthenticateClientErrorValue `json:"AuthenticateClientError,omitempty"`
}

// NewAuthenticateClientResponseEs11AuthenticateClientOk creates a AuthenticateClientResponseEs11 with the authenticateClientOk alternative.
func NewAuthenticateClientResponseEs11AuthenticateClientOk(v AuthenticateClientOkEs11) AuthenticateClientResponseEs11 {
	return AuthenticateClientResponseEs11{
		Choice:               AuthenticateClientResponseEs11ChoiceAuthenticateClientOk,
		AuthenticateClientOk: &v,
	}
}

// NewAuthenticateClientResponseEs11AuthenticateClientError creates a AuthenticateClientResponseEs11 with the authenticateClientError alternative.
func NewAuthenticateClientResponseEs11AuthenticateClientError(v AuthenticateClientResponseEs11AuthenticateClientErrorValue) AuthenticateClientResponseEs11 {
	return AuthenticateClientResponseEs11{
		Choice:                  AuthenticateClientResponseEs11ChoiceAuthenticateClientError,
		AuthenticateClientError: &v,
	}
}

// AuthenticateClientOkEs11 represents the ASN.1 type AuthenticateClientOkEs11 (SEQUENCE).
type AuthenticateClientOkEs11 struct {
	TransactionId      TransactionId                        `asn1:"tag:0,context,implicit"`
	EventEntries       AuthenticateClientOkEs11EventEntries `asn1:"tag:1,context,implicit"`
	EventEntriesIndef_ bool                                 `asn1:"-" json:"-"`
	ExtCount_          int64                                `asn1:"-" json:"-"`
	ExtPresent_        []bool                               `asn1:"-" json:"-"`
	ExtData_           [][]byte                             `asn1:"-" json:"-"`
}

// EventEntries represents the ASN.1 type EventEntries (SEQUENCE).
type EventEntries struct {
	EventId          string   `asn1:"tag:0,context,implicit"`
	RspServerAddress string   `asn1:"tag:1,context,implicit"`
	ExtCount_        int64    `asn1:"-" json:"-"`
	ExtPresent_      []bool   `asn1:"-" json:"-"`
	ExtData_         [][]byte `asn1:"-" json:"-"`
}

// BoundProfilePackageFirstSequenceOf87 represents the ASN.1 type BoundProfilePackageFirstSequenceOf87 (SEQUENCE_OF).
type BoundProfilePackageFirstSequenceOf87 = [][]byte

// BoundProfilePackageSequenceOf88 represents the ASN.1 type BoundProfilePackageSequenceOf88 (SEQUENCE_OF).
type BoundProfilePackageSequenceOf88 = [][]byte

// BoundProfilePackageSecondSequenceOf87 represents the ASN.1 type BoundProfilePackageSecondSequenceOf87 (SEQUENCE_OF).
type BoundProfilePackageSecondSequenceOf87 = [][]byte

// BoundProfilePackageSequenceOf86 represents the ASN.1 type BoundProfilePackageSequenceOf86 (SEQUENCE_OF).
type BoundProfilePackageSequenceOf86 = [][]byte

// ProfileInstallationResultDataFinalResult choice constants.
const (
	ProfileInstallationResultDataFinalResultChoiceSuccessResult = 1
	ProfileInstallationResultDataFinalResultChoiceErrorResult   = 2
)

// ProfileInstallationResultDataFinalResult represents the ASN.1 CHOICE type ProfileInstallationResultDataFinalResult.
type ProfileInstallationResultDataFinalResult struct {
	Choice        int
	SuccessResult *SuccessResult `json:"SuccessResult,omitempty"`
	ErrorResult   *ErrorResult   `json:"ErrorResult,omitempty"`
}

// NewProfileInstallationResultDataFinalResultSuccessResult creates a ProfileInstallationResultDataFinalResult with the successResult alternative.
func NewProfileInstallationResultDataFinalResultSuccessResult(v SuccessResult) ProfileInstallationResultDataFinalResult {
	return ProfileInstallationResultDataFinalResult{
		Choice:        ProfileInstallationResultDataFinalResultChoiceSuccessResult,
		SuccessResult: &v,
	}
}

// NewProfileInstallationResultDataFinalResultErrorResult creates a ProfileInstallationResultDataFinalResult with the errorResult alternative.
func NewProfileInstallationResultDataFinalResultErrorResult(v ErrorResult) ProfileInstallationResultDataFinalResult {
	return ProfileInstallationResultDataFinalResult{
		Choice:      ProfileInstallationResultDataFinalResultChoiceErrorResult,
		ErrorResult: &v,
	}
}

// StoreMetadataRequestNotificationConfigurationInfo represents the ASN.1 type StoreMetadataRequestNotificationConfigurationInfo (SEQUENCE_OF).
type StoreMetadataRequestNotificationConfigurationInfo = []NotificationConfigurationInformation

// StoreMetadataRequestIotSpecificMetadata represents the ASN.1 type StoreMetadataRequestIotSpecificMetadata (SEQUENCE).
type StoreMetadataRequestIotSpecificMetadata struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// VendorSpecificExtensionElem represents the ASN.1 type VendorSpecificExtensionElem (SEQUENCE).
type VendorSpecificExtensionElem struct {
	VendorOid          runtime.ObjectIdentifier `asn1:"tag:0,context,implicit"`
	VendorSpecificData runtime.RawValue         `asn1:"tag:1,context,implicit" asn1c:"raw-preserve"`
	ExtCount_          int64                    `asn1:"-" json:"-"`
	ExtPresent_        []bool                   `asn1:"-" json:"-"`
	ExtData_           [][]byte                 `asn1:"-" json:"-"`
}

// LpaeActivationResponseLpaeActivationResultValue represents the arbitrary-width ASN.1 INTEGER type LpaeActivationResponseLpaeActivationResultValue with named numbers.
type LpaeActivationResponseLpaeActivationResultValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	LpaeActivationResponseLpaeActivationResultValueOkDecimal           = "0"
	LpaeActivationResponseLpaeActivationResultValueOk                  = 0
	LpaeActivationResponseLpaeActivationResultValueNotSupportedDecimal = "1"
	LpaeActivationResponseLpaeActivationResultValueNotSupported        = 1
)

// NewLpaeActivationResponseLpaeActivationResultValue returns an immutable LpaeActivationResponseLpaeActivationResultValue containing value.
func NewLpaeActivationResponseLpaeActivationResultValue(value *big.Int) LpaeActivationResponseLpaeActivationResultValue {
	return LpaeActivationResponseLpaeActivationResultValue{value: runtime.CloneBigInt(value)}
}

// NewLpaeActivationResponseLpaeActivationResultValueInt64 returns a LpaeActivationResponseLpaeActivationResultValue containing value.
func NewLpaeActivationResponseLpaeActivationResultValueInt64(value int64) LpaeActivationResponseLpaeActivationResultValue {
	return NewLpaeActivationResponseLpaeActivationResultValue(big.NewInt(value))
}

// LpaeActivationResponseLpaeActivationResultValueOkValue returns the named value ok.
func LpaeActivationResponseLpaeActivationResultValueOkValue() LpaeActivationResponseLpaeActivationResultValue {
	return NewLpaeActivationResponseLpaeActivationResultValue(runtime.MustParseBigIntDecimal(LpaeActivationResponseLpaeActivationResultValueOkDecimal))
}

// LpaeActivationResponseLpaeActivationResultValueNotSupportedValue returns the named value notSupported.
func LpaeActivationResponseLpaeActivationResultValueNotSupportedValue() LpaeActivationResponseLpaeActivationResultValue {
	return NewLpaeActivationResponseLpaeActivationResultValue(runtime.MustParseBigIntDecimal(LpaeActivationResponseLpaeActivationResultValueNotSupportedDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v LpaeActivationResponseLpaeActivationResultValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v LpaeActivationResponseLpaeActivationResultValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v LpaeActivationResponseLpaeActivationResultValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case LpaeActivationResponseLpaeActivationResultValueOkDecimal:
		return "ok", true
	case LpaeActivationResponseLpaeActivationResultValueNotSupportedDecimal:
		return "notSupported", true
	default:
		return "", false
	}
}

func (v LpaeActivationResponseLpaeActivationResultValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v LpaeActivationResponseLpaeActivationResultValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *LpaeActivationResponseLpaeActivationResultValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal LpaeActivationResponseLpaeActivationResultValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewLpaeActivationResponseLpaeActivationResultValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v LpaeActivationResponseLpaeActivationResultValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *LpaeActivationResponseLpaeActivationResultValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal LpaeActivationResponseLpaeActivationResultValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewLpaeActivationResponseLpaeActivationResultValue(value)
	return nil
}

// SetDefaultDpAddressResponseSetDefaultDpAddressResultValue represents the arbitrary-width ASN.1 INTEGER type SetDefaultDpAddressResponseSetDefaultDpAddressResultValue with named numbers.
type SetDefaultDpAddressResponseSetDefaultDpAddressResultValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	SetDefaultDpAddressResponseSetDefaultDpAddressResultValueOkDecimal             = "0"
	SetDefaultDpAddressResponseSetDefaultDpAddressResultValueOk                    = 0
	SetDefaultDpAddressResponseSetDefaultDpAddressResultValueUndefinedErrorDecimal = "127"
	SetDefaultDpAddressResponseSetDefaultDpAddressResultValueUndefinedError        = 127
)

// NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValue returns an immutable SetDefaultDpAddressResponseSetDefaultDpAddressResultValue containing value.
func NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValue(value *big.Int) SetDefaultDpAddressResponseSetDefaultDpAddressResultValue {
	return SetDefaultDpAddressResponseSetDefaultDpAddressResultValue{value: runtime.CloneBigInt(value)}
}

// NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValueInt64 returns a SetDefaultDpAddressResponseSetDefaultDpAddressResultValue containing value.
func NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValueInt64(value int64) SetDefaultDpAddressResponseSetDefaultDpAddressResultValue {
	return NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValue(big.NewInt(value))
}

// SetDefaultDpAddressResponseSetDefaultDpAddressResultValueOkValue returns the named value ok.
func SetDefaultDpAddressResponseSetDefaultDpAddressResultValueOkValue() SetDefaultDpAddressResponseSetDefaultDpAddressResultValue {
	return NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValue(runtime.MustParseBigIntDecimal(SetDefaultDpAddressResponseSetDefaultDpAddressResultValueOkDecimal))
}

// SetDefaultDpAddressResponseSetDefaultDpAddressResultValueUndefinedErrorValue returns the named value undefinedError.
func SetDefaultDpAddressResponseSetDefaultDpAddressResultValueUndefinedErrorValue() SetDefaultDpAddressResponseSetDefaultDpAddressResultValue {
	return NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValue(runtime.MustParseBigIntDecimal(SetDefaultDpAddressResponseSetDefaultDpAddressResultValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case SetDefaultDpAddressResponseSetDefaultDpAddressResultValueOkDecimal:
		return "ok", true
	case SetDefaultDpAddressResponseSetDefaultDpAddressResultValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal SetDefaultDpAddressResponseSetDefaultDpAddressResultValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *SetDefaultDpAddressResponseSetDefaultDpAddressResultValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal SetDefaultDpAddressResponseSetDefaultDpAddressResultValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewSetDefaultDpAddressResponseSetDefaultDpAddressResultValue(value)
	return nil
}

// EUICCInfo1EuiccCiPKIdListForVerification represents the ASN.1 type EUICCInfo1EuiccCiPKIdListForVerification (SEQUENCE_OF).
type EUICCInfo1EuiccCiPKIdListForVerification = []SubjectKeyIdentifier

// EUICCInfo1EuiccCiPKIdListForSigning represents the ASN.1 type EUICCInfo1EuiccCiPKIdListForSigning (SEQUENCE_OF).
type EUICCInfo1EuiccCiPKIdListForSigning = []SubjectKeyIdentifier

// EUICCInfo2EuiccCiPKIdListForVerification represents the ASN.1 type EUICCInfo2EuiccCiPKIdListForVerification (SEQUENCE_OF).
type EUICCInfo2EuiccCiPKIdListForVerification = []SubjectKeyIdentifier

// EUICCInfo2EuiccCiPKIdListForSigning represents the ASN.1 type EUICCInfo2EuiccCiPKIdListForSigning (SEQUENCE_OF).
type EUICCInfo2EuiccCiPKIdListForSigning = []SubjectKeyIdentifier

// EUICCInfo2EuiccCategoryValue represents the arbitrary-width ASN.1 INTEGER type EUICCInfo2EuiccCategoryValue with named numbers.
type EUICCInfo2EuiccCategoryValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	EUICCInfo2EuiccCategoryValueOtherDecimal            = "0"
	EUICCInfo2EuiccCategoryValueOther                   = 0
	EUICCInfo2EuiccCategoryValueBasicEuiccDecimal       = "1"
	EUICCInfo2EuiccCategoryValueBasicEuicc              = 1
	EUICCInfo2EuiccCategoryValueMediumEuiccDecimal      = "2"
	EUICCInfo2EuiccCategoryValueMediumEuicc             = 2
	EUICCInfo2EuiccCategoryValueContactlessEuiccDecimal = "3"
	EUICCInfo2EuiccCategoryValueContactlessEuicc        = 3
)

// NewEUICCInfo2EuiccCategoryValue returns an immutable EUICCInfo2EuiccCategoryValue containing value.
func NewEUICCInfo2EuiccCategoryValue(value *big.Int) EUICCInfo2EuiccCategoryValue {
	return EUICCInfo2EuiccCategoryValue{value: runtime.CloneBigInt(value)}
}

// NewEUICCInfo2EuiccCategoryValueInt64 returns a EUICCInfo2EuiccCategoryValue containing value.
func NewEUICCInfo2EuiccCategoryValueInt64(value int64) EUICCInfo2EuiccCategoryValue {
	return NewEUICCInfo2EuiccCategoryValue(big.NewInt(value))
}

// EUICCInfo2EuiccCategoryValueOtherValue returns the named value other.
func EUICCInfo2EuiccCategoryValueOtherValue() EUICCInfo2EuiccCategoryValue {
	return NewEUICCInfo2EuiccCategoryValue(runtime.MustParseBigIntDecimal(EUICCInfo2EuiccCategoryValueOtherDecimal))
}

// EUICCInfo2EuiccCategoryValueBasicEuiccValue returns the named value basicEuicc.
func EUICCInfo2EuiccCategoryValueBasicEuiccValue() EUICCInfo2EuiccCategoryValue {
	return NewEUICCInfo2EuiccCategoryValue(runtime.MustParseBigIntDecimal(EUICCInfo2EuiccCategoryValueBasicEuiccDecimal))
}

// EUICCInfo2EuiccCategoryValueMediumEuiccValue returns the named value mediumEuicc.
func EUICCInfo2EuiccCategoryValueMediumEuiccValue() EUICCInfo2EuiccCategoryValue {
	return NewEUICCInfo2EuiccCategoryValue(runtime.MustParseBigIntDecimal(EUICCInfo2EuiccCategoryValueMediumEuiccDecimal))
}

// EUICCInfo2EuiccCategoryValueContactlessEuiccValue returns the named value contactlessEuicc.
func EUICCInfo2EuiccCategoryValueContactlessEuiccValue() EUICCInfo2EuiccCategoryValue {
	return NewEUICCInfo2EuiccCategoryValue(runtime.MustParseBigIntDecimal(EUICCInfo2EuiccCategoryValueContactlessEuiccDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v EUICCInfo2EuiccCategoryValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v EUICCInfo2EuiccCategoryValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v EUICCInfo2EuiccCategoryValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case EUICCInfo2EuiccCategoryValueOtherDecimal:
		return "other", true
	case EUICCInfo2EuiccCategoryValueBasicEuiccDecimal:
		return "basicEuicc", true
	case EUICCInfo2EuiccCategoryValueMediumEuiccDecimal:
		return "mediumEuicc", true
	case EUICCInfo2EuiccCategoryValueContactlessEuiccDecimal:
		return "contactlessEuicc", true
	default:
		return "", false
	}
}

func (v EUICCInfo2EuiccCategoryValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v EUICCInfo2EuiccCategoryValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *EUICCInfo2EuiccCategoryValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal EUICCInfo2EuiccCategoryValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewEUICCInfo2EuiccCategoryValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v EUICCInfo2EuiccCategoryValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *EUICCInfo2EuiccCategoryValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal EUICCInfo2EuiccCategoryValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewEUICCInfo2EuiccCategoryValue(value)
	return nil
}

// EUICCInfo2AdditionalEuiccProfilePackageVersions represents the ASN.1 type EUICCInfo2AdditionalEuiccProfilePackageVersions (SEQUENCE_OF).
type EUICCInfo2AdditionalEuiccProfilePackageVersions = []VersionType

// EUICCInfo2EuiccCiPKIdListForSigningV3 represents the ASN.1 type EUICCInfo2EuiccCiPKIdListForSigningV3 (SEQUENCE_OF).
type EUICCInfo2EuiccCiPKIdListForSigningV3 = []SubjectKeyIdentifier

// ListNotificationResponseNotificationMetadataList represents the ASN.1 type ListNotificationResponseNotificationMetadataList (SEQUENCE_OF).
type ListNotificationResponseNotificationMetadataList = []NotificationMetadata

// ListNotificationResponseListNotificationsResultErrorValue represents the arbitrary-width ASN.1 INTEGER type ListNotificationResponseListNotificationsResultErrorValue with named numbers.
type ListNotificationResponseListNotificationsResultErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	ListNotificationResponseListNotificationsResultErrorValueUndefinedErrorDecimal = "127"
	ListNotificationResponseListNotificationsResultErrorValueUndefinedError        = 127
)

// NewListNotificationResponseListNotificationsResultErrorValue returns an immutable ListNotificationResponseListNotificationsResultErrorValue containing value.
func NewListNotificationResponseListNotificationsResultErrorValue(value *big.Int) ListNotificationResponseListNotificationsResultErrorValue {
	return ListNotificationResponseListNotificationsResultErrorValue{value: runtime.CloneBigInt(value)}
}

// NewListNotificationResponseListNotificationsResultErrorValueInt64 returns a ListNotificationResponseListNotificationsResultErrorValue containing value.
func NewListNotificationResponseListNotificationsResultErrorValueInt64(value int64) ListNotificationResponseListNotificationsResultErrorValue {
	return NewListNotificationResponseListNotificationsResultErrorValue(big.NewInt(value))
}

// ListNotificationResponseListNotificationsResultErrorValueUndefinedErrorValue returns the named value undefinedError.
func ListNotificationResponseListNotificationsResultErrorValueUndefinedErrorValue() ListNotificationResponseListNotificationsResultErrorValue {
	return NewListNotificationResponseListNotificationsResultErrorValue(runtime.MustParseBigIntDecimal(ListNotificationResponseListNotificationsResultErrorValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v ListNotificationResponseListNotificationsResultErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v ListNotificationResponseListNotificationsResultErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v ListNotificationResponseListNotificationsResultErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case ListNotificationResponseListNotificationsResultErrorValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v ListNotificationResponseListNotificationsResultErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v ListNotificationResponseListNotificationsResultErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *ListNotificationResponseListNotificationsResultErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ListNotificationResponseListNotificationsResultErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewListNotificationResponseListNotificationsResultErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v ListNotificationResponseListNotificationsResultErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *ListNotificationResponseListNotificationsResultErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal ListNotificationResponseListNotificationsResultErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewListNotificationResponseListNotificationsResultErrorValue(value)
	return nil
}

// RetrieveNotificationsListRequestSearchCriteria choice constants.
const (
	RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber                  = 1
	RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation = 2
)

// RetrieveNotificationsListRequestSearchCriteria represents the ASN.1 CHOICE type RetrieveNotificationsListRequestSearchCriteria.
type RetrieveNotificationsListRequestSearchCriteria struct {
	Choice                     int
	SeqNumber                  *big.Int           `json:"SeqNumber,omitempty"`
	ProfileManagementOperation *NotificationEvent `json:"ProfileManagementOperation,omitempty"`
}

// NewRetrieveNotificationsListRequestSearchCriteriaSeqNumber creates a RetrieveNotificationsListRequestSearchCriteria with the seqNumber alternative.
func NewRetrieveNotificationsListRequestSearchCriteriaSeqNumber(v *big.Int) RetrieveNotificationsListRequestSearchCriteria {
	return RetrieveNotificationsListRequestSearchCriteria{
		Choice:    RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber,
		SeqNumber: v,
	}
}

// NewRetrieveNotificationsListRequestSearchCriteriaProfileManagementOperation creates a RetrieveNotificationsListRequestSearchCriteria with the profileManagementOperation alternative.
func NewRetrieveNotificationsListRequestSearchCriteriaProfileManagementOperation(v NotificationEvent) RetrieveNotificationsListRequestSearchCriteria {
	return RetrieveNotificationsListRequestSearchCriteria{
		Choice:                     RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation,
		ProfileManagementOperation: &v,
	}
}

// RetrieveNotificationsListResponseNotificationList represents the ASN.1 type RetrieveNotificationsListResponseNotificationList (SEQUENCE_OF).
type RetrieveNotificationsListResponseNotificationList = []PendingNotification

// RetrieveNotificationsListResponseNotificationsListResultErrorValue represents the arbitrary-width ASN.1 INTEGER type RetrieveNotificationsListResponseNotificationsListResultErrorValue with named numbers.
type RetrieveNotificationsListResponseNotificationsListResultErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	RetrieveNotificationsListResponseNotificationsListResultErrorValueUndefinedErrorDecimal = "127"
	RetrieveNotificationsListResponseNotificationsListResultErrorValueUndefinedError        = 127
)

// NewRetrieveNotificationsListResponseNotificationsListResultErrorValue returns an immutable RetrieveNotificationsListResponseNotificationsListResultErrorValue containing value.
func NewRetrieveNotificationsListResponseNotificationsListResultErrorValue(value *big.Int) RetrieveNotificationsListResponseNotificationsListResultErrorValue {
	return RetrieveNotificationsListResponseNotificationsListResultErrorValue{value: runtime.CloneBigInt(value)}
}

// NewRetrieveNotificationsListResponseNotificationsListResultErrorValueInt64 returns a RetrieveNotificationsListResponseNotificationsListResultErrorValue containing value.
func NewRetrieveNotificationsListResponseNotificationsListResultErrorValueInt64(value int64) RetrieveNotificationsListResponseNotificationsListResultErrorValue {
	return NewRetrieveNotificationsListResponseNotificationsListResultErrorValue(big.NewInt(value))
}

// RetrieveNotificationsListResponseNotificationsListResultErrorValueUndefinedErrorValue returns the named value undefinedError.
func RetrieveNotificationsListResponseNotificationsListResultErrorValueUndefinedErrorValue() RetrieveNotificationsListResponseNotificationsListResultErrorValue {
	return NewRetrieveNotificationsListResponseNotificationsListResultErrorValue(runtime.MustParseBigIntDecimal(RetrieveNotificationsListResponseNotificationsListResultErrorValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v RetrieveNotificationsListResponseNotificationsListResultErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v RetrieveNotificationsListResponseNotificationsListResultErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v RetrieveNotificationsListResponseNotificationsListResultErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case RetrieveNotificationsListResponseNotificationsListResultErrorValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v RetrieveNotificationsListResponseNotificationsListResultErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v RetrieveNotificationsListResponseNotificationsListResultErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *RetrieveNotificationsListResponseNotificationsListResultErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal RetrieveNotificationsListResponseNotificationsListResultErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewRetrieveNotificationsListResponseNotificationsListResultErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v RetrieveNotificationsListResponseNotificationsListResultErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *RetrieveNotificationsListResponseNotificationsListResultErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal RetrieveNotificationsListResponseNotificationsListResultErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewRetrieveNotificationsListResponseNotificationsListResultErrorValue(value)
	return nil
}

// NotificationSentResponseDeleteNotificationStatusValue represents the arbitrary-width ASN.1 INTEGER type NotificationSentResponseDeleteNotificationStatusValue with named numbers.
type NotificationSentResponseDeleteNotificationStatusValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	NotificationSentResponseDeleteNotificationStatusValueOkDecimal              = "0"
	NotificationSentResponseDeleteNotificationStatusValueOk                     = 0
	NotificationSentResponseDeleteNotificationStatusValueNothingToDeleteDecimal = "1"
	NotificationSentResponseDeleteNotificationStatusValueNothingToDelete        = 1
	NotificationSentResponseDeleteNotificationStatusValueUndefinedErrorDecimal  = "127"
	NotificationSentResponseDeleteNotificationStatusValueUndefinedError         = 127
)

// NewNotificationSentResponseDeleteNotificationStatusValue returns an immutable NotificationSentResponseDeleteNotificationStatusValue containing value.
func NewNotificationSentResponseDeleteNotificationStatusValue(value *big.Int) NotificationSentResponseDeleteNotificationStatusValue {
	return NotificationSentResponseDeleteNotificationStatusValue{value: runtime.CloneBigInt(value)}
}

// NewNotificationSentResponseDeleteNotificationStatusValueInt64 returns a NotificationSentResponseDeleteNotificationStatusValue containing value.
func NewNotificationSentResponseDeleteNotificationStatusValueInt64(value int64) NotificationSentResponseDeleteNotificationStatusValue {
	return NewNotificationSentResponseDeleteNotificationStatusValue(big.NewInt(value))
}

// NotificationSentResponseDeleteNotificationStatusValueOkValue returns the named value ok.
func NotificationSentResponseDeleteNotificationStatusValueOkValue() NotificationSentResponseDeleteNotificationStatusValue {
	return NewNotificationSentResponseDeleteNotificationStatusValue(runtime.MustParseBigIntDecimal(NotificationSentResponseDeleteNotificationStatusValueOkDecimal))
}

// NotificationSentResponseDeleteNotificationStatusValueNothingToDeleteValue returns the named value nothingToDelete.
func NotificationSentResponseDeleteNotificationStatusValueNothingToDeleteValue() NotificationSentResponseDeleteNotificationStatusValue {
	return NewNotificationSentResponseDeleteNotificationStatusValue(runtime.MustParseBigIntDecimal(NotificationSentResponseDeleteNotificationStatusValueNothingToDeleteDecimal))
}

// NotificationSentResponseDeleteNotificationStatusValueUndefinedErrorValue returns the named value undefinedError.
func NotificationSentResponseDeleteNotificationStatusValueUndefinedErrorValue() NotificationSentResponseDeleteNotificationStatusValue {
	return NewNotificationSentResponseDeleteNotificationStatusValue(runtime.MustParseBigIntDecimal(NotificationSentResponseDeleteNotificationStatusValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v NotificationSentResponseDeleteNotificationStatusValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v NotificationSentResponseDeleteNotificationStatusValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v NotificationSentResponseDeleteNotificationStatusValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case NotificationSentResponseDeleteNotificationStatusValueOkDecimal:
		return "ok", true
	case NotificationSentResponseDeleteNotificationStatusValueNothingToDeleteDecimal:
		return "nothingToDelete", true
	case NotificationSentResponseDeleteNotificationStatusValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v NotificationSentResponseDeleteNotificationStatusValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v NotificationSentResponseDeleteNotificationStatusValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *NotificationSentResponseDeleteNotificationStatusValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal NotificationSentResponseDeleteNotificationStatusValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewNotificationSentResponseDeleteNotificationStatusValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v NotificationSentResponseDeleteNotificationStatusValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *NotificationSentResponseDeleteNotificationStatusValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal NotificationSentResponseDeleteNotificationStatusValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewNotificationSentResponseDeleteNotificationStatusValue(value)
	return nil
}

// LoadCRLResponseOkMissingParts represents the ASN.1 type LoadCRLResponseOkMissingParts (SEQUENCE_OF).
type LoadCRLResponseOkMissingParts = []*big.Int

// CancelSessionResponseCancelSessionResponseErrorValue represents the arbitrary-width ASN.1 INTEGER type CancelSessionResponseCancelSessionResponseErrorValue with named numbers.
type CancelSessionResponseCancelSessionResponseErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionIdDecimal = "5"
	CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionId        = 5
	CancelSessionResponseCancelSessionResponseErrorValueUndefinedErrorDecimal       = "127"
	CancelSessionResponseCancelSessionResponseErrorValueUndefinedError              = 127
)

// NewCancelSessionResponseCancelSessionResponseErrorValue returns an immutable CancelSessionResponseCancelSessionResponseErrorValue containing value.
func NewCancelSessionResponseCancelSessionResponseErrorValue(value *big.Int) CancelSessionResponseCancelSessionResponseErrorValue {
	return CancelSessionResponseCancelSessionResponseErrorValue{value: runtime.CloneBigInt(value)}
}

// NewCancelSessionResponseCancelSessionResponseErrorValueInt64 returns a CancelSessionResponseCancelSessionResponseErrorValue containing value.
func NewCancelSessionResponseCancelSessionResponseErrorValueInt64(value int64) CancelSessionResponseCancelSessionResponseErrorValue {
	return NewCancelSessionResponseCancelSessionResponseErrorValue(big.NewInt(value))
}

// CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionIdValue returns the named value invalidTransactionId.
func CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionIdValue() CancelSessionResponseCancelSessionResponseErrorValue {
	return NewCancelSessionResponseCancelSessionResponseErrorValue(runtime.MustParseBigIntDecimal(CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionIdDecimal))
}

// CancelSessionResponseCancelSessionResponseErrorValueUndefinedErrorValue returns the named value undefinedError.
func CancelSessionResponseCancelSessionResponseErrorValueUndefinedErrorValue() CancelSessionResponseCancelSessionResponseErrorValue {
	return NewCancelSessionResponseCancelSessionResponseErrorValue(runtime.MustParseBigIntDecimal(CancelSessionResponseCancelSessionResponseErrorValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v CancelSessionResponseCancelSessionResponseErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v CancelSessionResponseCancelSessionResponseErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v CancelSessionResponseCancelSessionResponseErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case CancelSessionResponseCancelSessionResponseErrorValueInvalidTransactionIdDecimal:
		return "invalidTransactionId", true
	case CancelSessionResponseCancelSessionResponseErrorValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v CancelSessionResponseCancelSessionResponseErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v CancelSessionResponseCancelSessionResponseErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *CancelSessionResponseCancelSessionResponseErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal CancelSessionResponseCancelSessionResponseErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewCancelSessionResponseCancelSessionResponseErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v CancelSessionResponseCancelSessionResponseErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *CancelSessionResponseCancelSessionResponseErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal CancelSessionResponseCancelSessionResponseErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewCancelSessionResponseCancelSessionResponseErrorValue(value)
	return nil
}

// ProfileInfoListRequestSearchCriteria choice constants.
const (
	ProfileInfoListRequestSearchCriteriaChoiceIsdpAid      = 1
	ProfileInfoListRequestSearchCriteriaChoiceIccid        = 2
	ProfileInfoListRequestSearchCriteriaChoiceProfileClass = 3
)

// ProfileInfoListRequestSearchCriteria represents the ASN.1 CHOICE type ProfileInfoListRequestSearchCriteria.
type ProfileInfoListRequestSearchCriteria struct {
	Choice       int
	IsdpAid      *OctetTo16    `json:"IsdpAid,omitempty"`
	Iccid        *Iccid        `json:"Iccid,omitempty"`
	ProfileClass *ProfileClass `json:"ProfileClass,omitempty"`
}

// NewProfileInfoListRequestSearchCriteriaIsdpAid creates a ProfileInfoListRequestSearchCriteria with the isdpAid alternative.
func NewProfileInfoListRequestSearchCriteriaIsdpAid(v OctetTo16) ProfileInfoListRequestSearchCriteria {
	return ProfileInfoListRequestSearchCriteria{
		Choice:  ProfileInfoListRequestSearchCriteriaChoiceIsdpAid,
		IsdpAid: &v,
	}
}

// NewProfileInfoListRequestSearchCriteriaIccid creates a ProfileInfoListRequestSearchCriteria with the iccid alternative.
func NewProfileInfoListRequestSearchCriteriaIccid(v Iccid) ProfileInfoListRequestSearchCriteria {
	return ProfileInfoListRequestSearchCriteria{
		Choice: ProfileInfoListRequestSearchCriteriaChoiceIccid,
		Iccid:  &v,
	}
}

// NewProfileInfoListRequestSearchCriteriaProfileClass creates a ProfileInfoListRequestSearchCriteria with the profileClass alternative.
func NewProfileInfoListRequestSearchCriteriaProfileClass(v ProfileClass) ProfileInfoListRequestSearchCriteria {
	return ProfileInfoListRequestSearchCriteria{
		Choice:       ProfileInfoListRequestSearchCriteriaChoiceProfileClass,
		ProfileClass: &v,
	}
}

// ProfileInfoListResponseProfileInfoListOk represents the ASN.1 type ProfileInfoListResponseProfileInfoListOk (SEQUENCE_OF).
type ProfileInfoListResponseProfileInfoListOk = []ProfileInfo

// ProfileInfoNotificationConfigurationInfo represents the ASN.1 type ProfileInfoNotificationConfigurationInfo (SEQUENCE_OF).
type ProfileInfoNotificationConfigurationInfo = []NotificationConfigurationInformation

// ProfileInfoIotSpecificProfileInfo represents the ASN.1 type ProfileInfoIotSpecificProfileInfo (SEQUENCE).
type ProfileInfoIotSpecificProfileInfo struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// EnableProfileRequestProfileIdentifier choice constants.
const (
	EnableProfileRequestProfileIdentifierChoiceIsdpAid = 1
	EnableProfileRequestProfileIdentifierChoiceIccid   = 2
)

// EnableProfileRequestProfileIdentifier represents the ASN.1 CHOICE type EnableProfileRequestProfileIdentifier.
type EnableProfileRequestProfileIdentifier struct {
	Choice  int
	IsdpAid *OctetTo16 `json:"IsdpAid,omitempty"`
	Iccid   *Iccid     `json:"Iccid,omitempty"`
}

// NewEnableProfileRequestProfileIdentifierIsdpAid creates a EnableProfileRequestProfileIdentifier with the isdpAid alternative.
func NewEnableProfileRequestProfileIdentifierIsdpAid(v OctetTo16) EnableProfileRequestProfileIdentifier {
	return EnableProfileRequestProfileIdentifier{
		Choice:  EnableProfileRequestProfileIdentifierChoiceIsdpAid,
		IsdpAid: &v,
	}
}

// NewEnableProfileRequestProfileIdentifierIccid creates a EnableProfileRequestProfileIdentifier with the iccid alternative.
func NewEnableProfileRequestProfileIdentifierIccid(v Iccid) EnableProfileRequestProfileIdentifier {
	return EnableProfileRequestProfileIdentifier{
		Choice: EnableProfileRequestProfileIdentifierChoiceIccid,
		Iccid:  &v,
	}
}

// EnableProfileResponseEnableResultValue represents the arbitrary-width ASN.1 INTEGER type EnableProfileResponseEnableResultValue with named numbers.
type EnableProfileResponseEnableResultValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	EnableProfileResponseEnableResultValueOkDecimal                        = "0"
	EnableProfileResponseEnableResultValueOk                               = 0
	EnableProfileResponseEnableResultValueIccidOrAidNotFoundDecimal        = "1"
	EnableProfileResponseEnableResultValueIccidOrAidNotFound               = 1
	EnableProfileResponseEnableResultValueProfileNotInDisabledStateDecimal = "2"
	EnableProfileResponseEnableResultValueProfileNotInDisabledState        = 2
	EnableProfileResponseEnableResultValueDisallowedByPolicyDecimal        = "3"
	EnableProfileResponseEnableResultValueDisallowedByPolicy               = 3
	EnableProfileResponseEnableResultValueWrongProfileReenablingDecimal    = "4"
	EnableProfileResponseEnableResultValueWrongProfileReenabling           = 4
	EnableProfileResponseEnableResultValueCatBusyDecimal                   = "5"
	EnableProfileResponseEnableResultValueCatBusy                          = 5
	EnableProfileResponseEnableResultValueUndefinedErrorDecimal            = "127"
	EnableProfileResponseEnableResultValueUndefinedError                   = 127
)

// NewEnableProfileResponseEnableResultValue returns an immutable EnableProfileResponseEnableResultValue containing value.
func NewEnableProfileResponseEnableResultValue(value *big.Int) EnableProfileResponseEnableResultValue {
	return EnableProfileResponseEnableResultValue{value: runtime.CloneBigInt(value)}
}

// NewEnableProfileResponseEnableResultValueInt64 returns a EnableProfileResponseEnableResultValue containing value.
func NewEnableProfileResponseEnableResultValueInt64(value int64) EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(big.NewInt(value))
}

// EnableProfileResponseEnableResultValueOkValue returns the named value ok.
func EnableProfileResponseEnableResultValueOkValue() EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(runtime.MustParseBigIntDecimal(EnableProfileResponseEnableResultValueOkDecimal))
}

// EnableProfileResponseEnableResultValueIccidOrAidNotFoundValue returns the named value iccidOrAidNotFound.
func EnableProfileResponseEnableResultValueIccidOrAidNotFoundValue() EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(runtime.MustParseBigIntDecimal(EnableProfileResponseEnableResultValueIccidOrAidNotFoundDecimal))
}

// EnableProfileResponseEnableResultValueProfileNotInDisabledStateValue returns the named value profileNotInDisabledState.
func EnableProfileResponseEnableResultValueProfileNotInDisabledStateValue() EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(runtime.MustParseBigIntDecimal(EnableProfileResponseEnableResultValueProfileNotInDisabledStateDecimal))
}

// EnableProfileResponseEnableResultValueDisallowedByPolicyValue returns the named value disallowedByPolicy.
func EnableProfileResponseEnableResultValueDisallowedByPolicyValue() EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(runtime.MustParseBigIntDecimal(EnableProfileResponseEnableResultValueDisallowedByPolicyDecimal))
}

// EnableProfileResponseEnableResultValueWrongProfileReenablingValue returns the named value wrongProfileReenabling.
func EnableProfileResponseEnableResultValueWrongProfileReenablingValue() EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(runtime.MustParseBigIntDecimal(EnableProfileResponseEnableResultValueWrongProfileReenablingDecimal))
}

// EnableProfileResponseEnableResultValueCatBusyValue returns the named value catBusy.
func EnableProfileResponseEnableResultValueCatBusyValue() EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(runtime.MustParseBigIntDecimal(EnableProfileResponseEnableResultValueCatBusyDecimal))
}

// EnableProfileResponseEnableResultValueUndefinedErrorValue returns the named value undefinedError.
func EnableProfileResponseEnableResultValueUndefinedErrorValue() EnableProfileResponseEnableResultValue {
	return NewEnableProfileResponseEnableResultValue(runtime.MustParseBigIntDecimal(EnableProfileResponseEnableResultValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v EnableProfileResponseEnableResultValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v EnableProfileResponseEnableResultValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v EnableProfileResponseEnableResultValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case EnableProfileResponseEnableResultValueOkDecimal:
		return "ok", true
	case EnableProfileResponseEnableResultValueIccidOrAidNotFoundDecimal:
		return "iccidOrAidNotFound", true
	case EnableProfileResponseEnableResultValueProfileNotInDisabledStateDecimal:
		return "profileNotInDisabledState", true
	case EnableProfileResponseEnableResultValueDisallowedByPolicyDecimal:
		return "disallowedByPolicy", true
	case EnableProfileResponseEnableResultValueWrongProfileReenablingDecimal:
		return "wrongProfileReenabling", true
	case EnableProfileResponseEnableResultValueCatBusyDecimal:
		return "catBusy", true
	case EnableProfileResponseEnableResultValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v EnableProfileResponseEnableResultValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v EnableProfileResponseEnableResultValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *EnableProfileResponseEnableResultValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal EnableProfileResponseEnableResultValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewEnableProfileResponseEnableResultValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v EnableProfileResponseEnableResultValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *EnableProfileResponseEnableResultValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal EnableProfileResponseEnableResultValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewEnableProfileResponseEnableResultValue(value)
	return nil
}

// DisableProfileRequestProfileIdentifier choice constants.
const (
	DisableProfileRequestProfileIdentifierChoiceIsdpAid = 1
	DisableProfileRequestProfileIdentifierChoiceIccid   = 2
)

// DisableProfileRequestProfileIdentifier represents the ASN.1 CHOICE type DisableProfileRequestProfileIdentifier.
type DisableProfileRequestProfileIdentifier struct {
	Choice  int
	IsdpAid *OctetTo16 `json:"IsdpAid,omitempty"`
	Iccid   *Iccid     `json:"Iccid,omitempty"`
}

// NewDisableProfileRequestProfileIdentifierIsdpAid creates a DisableProfileRequestProfileIdentifier with the isdpAid alternative.
func NewDisableProfileRequestProfileIdentifierIsdpAid(v OctetTo16) DisableProfileRequestProfileIdentifier {
	return DisableProfileRequestProfileIdentifier{
		Choice:  DisableProfileRequestProfileIdentifierChoiceIsdpAid,
		IsdpAid: &v,
	}
}

// NewDisableProfileRequestProfileIdentifierIccid creates a DisableProfileRequestProfileIdentifier with the iccid alternative.
func NewDisableProfileRequestProfileIdentifierIccid(v Iccid) DisableProfileRequestProfileIdentifier {
	return DisableProfileRequestProfileIdentifier{
		Choice: DisableProfileRequestProfileIdentifierChoiceIccid,
		Iccid:  &v,
	}
}

// DisableProfileResponseDisableResultValue represents the arbitrary-width ASN.1 INTEGER type DisableProfileResponseDisableResultValue with named numbers.
type DisableProfileResponseDisableResultValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	DisableProfileResponseDisableResultValueOkDecimal                       = "0"
	DisableProfileResponseDisableResultValueOk                              = 0
	DisableProfileResponseDisableResultValueIccidOrAidNotFoundDecimal       = "1"
	DisableProfileResponseDisableResultValueIccidOrAidNotFound              = 1
	DisableProfileResponseDisableResultValueProfileNotInEnabledStateDecimal = "2"
	DisableProfileResponseDisableResultValueProfileNotInEnabledState        = 2
	DisableProfileResponseDisableResultValueDisallowedByPolicyDecimal       = "3"
	DisableProfileResponseDisableResultValueDisallowedByPolicy              = 3
	DisableProfileResponseDisableResultValueCatBusyDecimal                  = "5"
	DisableProfileResponseDisableResultValueCatBusy                         = 5
	DisableProfileResponseDisableResultValueUndefinedErrorDecimal           = "127"
	DisableProfileResponseDisableResultValueUndefinedError                  = 127
)

// NewDisableProfileResponseDisableResultValue returns an immutable DisableProfileResponseDisableResultValue containing value.
func NewDisableProfileResponseDisableResultValue(value *big.Int) DisableProfileResponseDisableResultValue {
	return DisableProfileResponseDisableResultValue{value: runtime.CloneBigInt(value)}
}

// NewDisableProfileResponseDisableResultValueInt64 returns a DisableProfileResponseDisableResultValue containing value.
func NewDisableProfileResponseDisableResultValueInt64(value int64) DisableProfileResponseDisableResultValue {
	return NewDisableProfileResponseDisableResultValue(big.NewInt(value))
}

// DisableProfileResponseDisableResultValueOkValue returns the named value ok.
func DisableProfileResponseDisableResultValueOkValue() DisableProfileResponseDisableResultValue {
	return NewDisableProfileResponseDisableResultValue(runtime.MustParseBigIntDecimal(DisableProfileResponseDisableResultValueOkDecimal))
}

// DisableProfileResponseDisableResultValueIccidOrAidNotFoundValue returns the named value iccidOrAidNotFound.
func DisableProfileResponseDisableResultValueIccidOrAidNotFoundValue() DisableProfileResponseDisableResultValue {
	return NewDisableProfileResponseDisableResultValue(runtime.MustParseBigIntDecimal(DisableProfileResponseDisableResultValueIccidOrAidNotFoundDecimal))
}

// DisableProfileResponseDisableResultValueProfileNotInEnabledStateValue returns the named value profileNotInEnabledState.
func DisableProfileResponseDisableResultValueProfileNotInEnabledStateValue() DisableProfileResponseDisableResultValue {
	return NewDisableProfileResponseDisableResultValue(runtime.MustParseBigIntDecimal(DisableProfileResponseDisableResultValueProfileNotInEnabledStateDecimal))
}

// DisableProfileResponseDisableResultValueDisallowedByPolicyValue returns the named value disallowedByPolicy.
func DisableProfileResponseDisableResultValueDisallowedByPolicyValue() DisableProfileResponseDisableResultValue {
	return NewDisableProfileResponseDisableResultValue(runtime.MustParseBigIntDecimal(DisableProfileResponseDisableResultValueDisallowedByPolicyDecimal))
}

// DisableProfileResponseDisableResultValueCatBusyValue returns the named value catBusy.
func DisableProfileResponseDisableResultValueCatBusyValue() DisableProfileResponseDisableResultValue {
	return NewDisableProfileResponseDisableResultValue(runtime.MustParseBigIntDecimal(DisableProfileResponseDisableResultValueCatBusyDecimal))
}

// DisableProfileResponseDisableResultValueUndefinedErrorValue returns the named value undefinedError.
func DisableProfileResponseDisableResultValueUndefinedErrorValue() DisableProfileResponseDisableResultValue {
	return NewDisableProfileResponseDisableResultValue(runtime.MustParseBigIntDecimal(DisableProfileResponseDisableResultValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v DisableProfileResponseDisableResultValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v DisableProfileResponseDisableResultValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v DisableProfileResponseDisableResultValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case DisableProfileResponseDisableResultValueOkDecimal:
		return "ok", true
	case DisableProfileResponseDisableResultValueIccidOrAidNotFoundDecimal:
		return "iccidOrAidNotFound", true
	case DisableProfileResponseDisableResultValueProfileNotInEnabledStateDecimal:
		return "profileNotInEnabledState", true
	case DisableProfileResponseDisableResultValueDisallowedByPolicyDecimal:
		return "disallowedByPolicy", true
	case DisableProfileResponseDisableResultValueCatBusyDecimal:
		return "catBusy", true
	case DisableProfileResponseDisableResultValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v DisableProfileResponseDisableResultValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v DisableProfileResponseDisableResultValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *DisableProfileResponseDisableResultValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DisableProfileResponseDisableResultValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewDisableProfileResponseDisableResultValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v DisableProfileResponseDisableResultValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *DisableProfileResponseDisableResultValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DisableProfileResponseDisableResultValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewDisableProfileResponseDisableResultValue(value)
	return nil
}

// DeleteProfileResponseDeleteResultValue represents the arbitrary-width ASN.1 INTEGER type DeleteProfileResponseDeleteResultValue with named numbers.
type DeleteProfileResponseDeleteResultValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	DeleteProfileResponseDeleteResultValueOkDecimal                        = "0"
	DeleteProfileResponseDeleteResultValueOk                               = 0
	DeleteProfileResponseDeleteResultValueIccidOrAidNotFoundDecimal        = "1"
	DeleteProfileResponseDeleteResultValueIccidOrAidNotFound               = 1
	DeleteProfileResponseDeleteResultValueProfileNotInDisabledStateDecimal = "2"
	DeleteProfileResponseDeleteResultValueProfileNotInDisabledState        = 2
	DeleteProfileResponseDeleteResultValueDisallowedByPolicyDecimal        = "3"
	DeleteProfileResponseDeleteResultValueDisallowedByPolicy               = 3
	DeleteProfileResponseDeleteResultValueUndefinedErrorDecimal            = "127"
	DeleteProfileResponseDeleteResultValueUndefinedError                   = 127
)

// NewDeleteProfileResponseDeleteResultValue returns an immutable DeleteProfileResponseDeleteResultValue containing value.
func NewDeleteProfileResponseDeleteResultValue(value *big.Int) DeleteProfileResponseDeleteResultValue {
	return DeleteProfileResponseDeleteResultValue{value: runtime.CloneBigInt(value)}
}

// NewDeleteProfileResponseDeleteResultValueInt64 returns a DeleteProfileResponseDeleteResultValue containing value.
func NewDeleteProfileResponseDeleteResultValueInt64(value int64) DeleteProfileResponseDeleteResultValue {
	return NewDeleteProfileResponseDeleteResultValue(big.NewInt(value))
}

// DeleteProfileResponseDeleteResultValueOkValue returns the named value ok.
func DeleteProfileResponseDeleteResultValueOkValue() DeleteProfileResponseDeleteResultValue {
	return NewDeleteProfileResponseDeleteResultValue(runtime.MustParseBigIntDecimal(DeleteProfileResponseDeleteResultValueOkDecimal))
}

// DeleteProfileResponseDeleteResultValueIccidOrAidNotFoundValue returns the named value iccidOrAidNotFound.
func DeleteProfileResponseDeleteResultValueIccidOrAidNotFoundValue() DeleteProfileResponseDeleteResultValue {
	return NewDeleteProfileResponseDeleteResultValue(runtime.MustParseBigIntDecimal(DeleteProfileResponseDeleteResultValueIccidOrAidNotFoundDecimal))
}

// DeleteProfileResponseDeleteResultValueProfileNotInDisabledStateValue returns the named value profileNotInDisabledState.
func DeleteProfileResponseDeleteResultValueProfileNotInDisabledStateValue() DeleteProfileResponseDeleteResultValue {
	return NewDeleteProfileResponseDeleteResultValue(runtime.MustParseBigIntDecimal(DeleteProfileResponseDeleteResultValueProfileNotInDisabledStateDecimal))
}

// DeleteProfileResponseDeleteResultValueDisallowedByPolicyValue returns the named value disallowedByPolicy.
func DeleteProfileResponseDeleteResultValueDisallowedByPolicyValue() DeleteProfileResponseDeleteResultValue {
	return NewDeleteProfileResponseDeleteResultValue(runtime.MustParseBigIntDecimal(DeleteProfileResponseDeleteResultValueDisallowedByPolicyDecimal))
}

// DeleteProfileResponseDeleteResultValueUndefinedErrorValue returns the named value undefinedError.
func DeleteProfileResponseDeleteResultValueUndefinedErrorValue() DeleteProfileResponseDeleteResultValue {
	return NewDeleteProfileResponseDeleteResultValue(runtime.MustParseBigIntDecimal(DeleteProfileResponseDeleteResultValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v DeleteProfileResponseDeleteResultValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v DeleteProfileResponseDeleteResultValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v DeleteProfileResponseDeleteResultValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case DeleteProfileResponseDeleteResultValueOkDecimal:
		return "ok", true
	case DeleteProfileResponseDeleteResultValueIccidOrAidNotFoundDecimal:
		return "iccidOrAidNotFound", true
	case DeleteProfileResponseDeleteResultValueProfileNotInDisabledStateDecimal:
		return "profileNotInDisabledState", true
	case DeleteProfileResponseDeleteResultValueDisallowedByPolicyDecimal:
		return "disallowedByPolicy", true
	case DeleteProfileResponseDeleteResultValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v DeleteProfileResponseDeleteResultValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v DeleteProfileResponseDeleteResultValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *DeleteProfileResponseDeleteResultValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DeleteProfileResponseDeleteResultValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewDeleteProfileResponseDeleteResultValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v DeleteProfileResponseDeleteResultValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *DeleteProfileResponseDeleteResultValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DeleteProfileResponseDeleteResultValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewDeleteProfileResponseDeleteResultValue(value)
	return nil
}

// EuiccMemoryResetResponseResetResultValue represents the arbitrary-width ASN.1 INTEGER type EuiccMemoryResetResponseResetResultValue with named numbers.
type EuiccMemoryResetResponseResetResultValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	EuiccMemoryResetResponseResetResultValueOkDecimal              = "0"
	EuiccMemoryResetResponseResetResultValueOk                     = 0
	EuiccMemoryResetResponseResetResultValueNothingToDeleteDecimal = "1"
	EuiccMemoryResetResponseResetResultValueNothingToDelete        = 1
	EuiccMemoryResetResponseResetResultValueCatBusyDecimal         = "5"
	EuiccMemoryResetResponseResetResultValueCatBusy                = 5
	EuiccMemoryResetResponseResetResultValueUndefinedErrorDecimal  = "127"
	EuiccMemoryResetResponseResetResultValueUndefinedError         = 127
)

// NewEuiccMemoryResetResponseResetResultValue returns an immutable EuiccMemoryResetResponseResetResultValue containing value.
func NewEuiccMemoryResetResponseResetResultValue(value *big.Int) EuiccMemoryResetResponseResetResultValue {
	return EuiccMemoryResetResponseResetResultValue{value: runtime.CloneBigInt(value)}
}

// NewEuiccMemoryResetResponseResetResultValueInt64 returns a EuiccMemoryResetResponseResetResultValue containing value.
func NewEuiccMemoryResetResponseResetResultValueInt64(value int64) EuiccMemoryResetResponseResetResultValue {
	return NewEuiccMemoryResetResponseResetResultValue(big.NewInt(value))
}

// EuiccMemoryResetResponseResetResultValueOkValue returns the named value ok.
func EuiccMemoryResetResponseResetResultValueOkValue() EuiccMemoryResetResponseResetResultValue {
	return NewEuiccMemoryResetResponseResetResultValue(runtime.MustParseBigIntDecimal(EuiccMemoryResetResponseResetResultValueOkDecimal))
}

// EuiccMemoryResetResponseResetResultValueNothingToDeleteValue returns the named value nothingToDelete.
func EuiccMemoryResetResponseResetResultValueNothingToDeleteValue() EuiccMemoryResetResponseResetResultValue {
	return NewEuiccMemoryResetResponseResetResultValue(runtime.MustParseBigIntDecimal(EuiccMemoryResetResponseResetResultValueNothingToDeleteDecimal))
}

// EuiccMemoryResetResponseResetResultValueCatBusyValue returns the named value catBusy.
func EuiccMemoryResetResponseResetResultValueCatBusyValue() EuiccMemoryResetResponseResetResultValue {
	return NewEuiccMemoryResetResponseResetResultValue(runtime.MustParseBigIntDecimal(EuiccMemoryResetResponseResetResultValueCatBusyDecimal))
}

// EuiccMemoryResetResponseResetResultValueUndefinedErrorValue returns the named value undefinedError.
func EuiccMemoryResetResponseResetResultValueUndefinedErrorValue() EuiccMemoryResetResponseResetResultValue {
	return NewEuiccMemoryResetResponseResetResultValue(runtime.MustParseBigIntDecimal(EuiccMemoryResetResponseResetResultValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v EuiccMemoryResetResponseResetResultValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v EuiccMemoryResetResponseResetResultValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v EuiccMemoryResetResponseResetResultValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case EuiccMemoryResetResponseResetResultValueOkDecimal:
		return "ok", true
	case EuiccMemoryResetResponseResetResultValueNothingToDeleteDecimal:
		return "nothingToDelete", true
	case EuiccMemoryResetResponseResetResultValueCatBusyDecimal:
		return "catBusy", true
	case EuiccMemoryResetResponseResetResultValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v EuiccMemoryResetResponseResetResultValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v EuiccMemoryResetResponseResetResultValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *EuiccMemoryResetResponseResetResultValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal EuiccMemoryResetResponseResetResultValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewEuiccMemoryResetResponseResetResultValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v EuiccMemoryResetResponseResetResultValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *EuiccMemoryResetResponseResetResultValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal EuiccMemoryResetResponseResetResultValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewEuiccMemoryResetResponseResetResultValue(value)
	return nil
}

// SetNicknameResponseSetNicknameResultValue represents the arbitrary-width ASN.1 INTEGER type SetNicknameResponseSetNicknameResultValue with named numbers.
type SetNicknameResponseSetNicknameResultValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	SetNicknameResponseSetNicknameResultValueOkDecimal             = "0"
	SetNicknameResponseSetNicknameResultValueOk                    = 0
	SetNicknameResponseSetNicknameResultValueIccidNotFoundDecimal  = "1"
	SetNicknameResponseSetNicknameResultValueIccidNotFound         = 1
	SetNicknameResponseSetNicknameResultValueUndefinedErrorDecimal = "127"
	SetNicknameResponseSetNicknameResultValueUndefinedError        = 127
)

// NewSetNicknameResponseSetNicknameResultValue returns an immutable SetNicknameResponseSetNicknameResultValue containing value.
func NewSetNicknameResponseSetNicknameResultValue(value *big.Int) SetNicknameResponseSetNicknameResultValue {
	return SetNicknameResponseSetNicknameResultValue{value: runtime.CloneBigInt(value)}
}

// NewSetNicknameResponseSetNicknameResultValueInt64 returns a SetNicknameResponseSetNicknameResultValue containing value.
func NewSetNicknameResponseSetNicknameResultValueInt64(value int64) SetNicknameResponseSetNicknameResultValue {
	return NewSetNicknameResponseSetNicknameResultValue(big.NewInt(value))
}

// SetNicknameResponseSetNicknameResultValueOkValue returns the named value ok.
func SetNicknameResponseSetNicknameResultValueOkValue() SetNicknameResponseSetNicknameResultValue {
	return NewSetNicknameResponseSetNicknameResultValue(runtime.MustParseBigIntDecimal(SetNicknameResponseSetNicknameResultValueOkDecimal))
}

// SetNicknameResponseSetNicknameResultValueIccidNotFoundValue returns the named value iccidNotFound.
func SetNicknameResponseSetNicknameResultValueIccidNotFoundValue() SetNicknameResponseSetNicknameResultValue {
	return NewSetNicknameResponseSetNicknameResultValue(runtime.MustParseBigIntDecimal(SetNicknameResponseSetNicknameResultValueIccidNotFoundDecimal))
}

// SetNicknameResponseSetNicknameResultValueUndefinedErrorValue returns the named value undefinedError.
func SetNicknameResponseSetNicknameResultValueUndefinedErrorValue() SetNicknameResponseSetNicknameResultValue {
	return NewSetNicknameResponseSetNicknameResultValue(runtime.MustParseBigIntDecimal(SetNicknameResponseSetNicknameResultValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v SetNicknameResponseSetNicknameResultValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v SetNicknameResponseSetNicknameResultValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v SetNicknameResponseSetNicknameResultValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case SetNicknameResponseSetNicknameResultValueOkDecimal:
		return "ok", true
	case SetNicknameResponseSetNicknameResultValueIccidNotFoundDecimal:
		return "iccidNotFound", true
	case SetNicknameResponseSetNicknameResultValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v SetNicknameResponseSetNicknameResultValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v SetNicknameResponseSetNicknameResultValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *SetNicknameResponseSetNicknameResultValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal SetNicknameResponseSetNicknameResultValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewSetNicknameResponseSetNicknameResultValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v SetNicknameResponseSetNicknameResultValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *SetNicknameResponseSetNicknameResultValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal SetNicknameResponseSetNicknameResultValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewSetNicknameResponseSetNicknameResultValue(value)
	return nil
}

// ProfilePolicyAuthorisationRuleAllowedOperators represents the ASN.1 type ProfilePolicyAuthorisationRuleAllowedOperators (SEQUENCE_OF).
type ProfilePolicyAuthorisationRuleAllowedOperators = []OperatorId

// InitiateAuthenticationResponseInitiateAuthenticationErrorValue represents the arbitrary-width ASN.1 INTEGER type InitiateAuthenticationResponseInitiateAuthenticationErrorValue with named numbers.
type InitiateAuthenticationResponseInitiateAuthenticationErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	InitiateAuthenticationResponseInitiateAuthenticationErrorValueInvalidDpAddressDecimal             = "1"
	InitiateAuthenticationResponseInitiateAuthenticationErrorValueInvalidDpAddress                    = 1
	InitiateAuthenticationResponseInitiateAuthenticationErrorValueEuiccVersionNotSupportedByDpDecimal = "2"
	InitiateAuthenticationResponseInitiateAuthenticationErrorValueEuiccVersionNotSupportedByDp        = 2
	InitiateAuthenticationResponseInitiateAuthenticationErrorValueCiPKIdNotSupportedDecimal           = "3"
	InitiateAuthenticationResponseInitiateAuthenticationErrorValueCiPKIdNotSupported                  = 3
)

// NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue returns an immutable InitiateAuthenticationResponseInitiateAuthenticationErrorValue containing value.
func NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue(value *big.Int) InitiateAuthenticationResponseInitiateAuthenticationErrorValue {
	return InitiateAuthenticationResponseInitiateAuthenticationErrorValue{value: runtime.CloneBigInt(value)}
}

// NewInitiateAuthenticationResponseInitiateAuthenticationErrorValueInt64 returns a InitiateAuthenticationResponseInitiateAuthenticationErrorValue containing value.
func NewInitiateAuthenticationResponseInitiateAuthenticationErrorValueInt64(value int64) InitiateAuthenticationResponseInitiateAuthenticationErrorValue {
	return NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue(big.NewInt(value))
}

// InitiateAuthenticationResponseInitiateAuthenticationErrorValueInvalidDpAddressValue returns the named value invalidDpAddress.
func InitiateAuthenticationResponseInitiateAuthenticationErrorValueInvalidDpAddressValue() InitiateAuthenticationResponseInitiateAuthenticationErrorValue {
	return NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue(runtime.MustParseBigIntDecimal(InitiateAuthenticationResponseInitiateAuthenticationErrorValueInvalidDpAddressDecimal))
}

// InitiateAuthenticationResponseInitiateAuthenticationErrorValueEuiccVersionNotSupportedByDpValue returns the named value euiccVersionNotSupportedByDp.
func InitiateAuthenticationResponseInitiateAuthenticationErrorValueEuiccVersionNotSupportedByDpValue() InitiateAuthenticationResponseInitiateAuthenticationErrorValue {
	return NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue(runtime.MustParseBigIntDecimal(InitiateAuthenticationResponseInitiateAuthenticationErrorValueEuiccVersionNotSupportedByDpDecimal))
}

// InitiateAuthenticationResponseInitiateAuthenticationErrorValueCiPKIdNotSupportedValue returns the named value ciPKIdNotSupported.
func InitiateAuthenticationResponseInitiateAuthenticationErrorValueCiPKIdNotSupportedValue() InitiateAuthenticationResponseInitiateAuthenticationErrorValue {
	return NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue(runtime.MustParseBigIntDecimal(InitiateAuthenticationResponseInitiateAuthenticationErrorValueCiPKIdNotSupportedDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v InitiateAuthenticationResponseInitiateAuthenticationErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v InitiateAuthenticationResponseInitiateAuthenticationErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v InitiateAuthenticationResponseInitiateAuthenticationErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case InitiateAuthenticationResponseInitiateAuthenticationErrorValueInvalidDpAddressDecimal:
		return "invalidDpAddress", true
	case InitiateAuthenticationResponseInitiateAuthenticationErrorValueEuiccVersionNotSupportedByDpDecimal:
		return "euiccVersionNotSupportedByDp", true
	case InitiateAuthenticationResponseInitiateAuthenticationErrorValueCiPKIdNotSupportedDecimal:
		return "ciPKIdNotSupported", true
	default:
		return "", false
	}
}

func (v InitiateAuthenticationResponseInitiateAuthenticationErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v InitiateAuthenticationResponseInitiateAuthenticationErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *InitiateAuthenticationResponseInitiateAuthenticationErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal InitiateAuthenticationResponseInitiateAuthenticationErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v InitiateAuthenticationResponseInitiateAuthenticationErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *InitiateAuthenticationResponseInitiateAuthenticationErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal InitiateAuthenticationResponseInitiateAuthenticationErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewInitiateAuthenticationResponseInitiateAuthenticationErrorValue(value)
	return nil
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValue represents the arbitrary-width ASN.1 INTEGER type AuthenticateClientResponseEs9AuthenticateClientErrorValue with named numbers.
type AuthenticateClientResponseEs9AuthenticateClientErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateInvalidDecimal   = "1"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateInvalid          = 1
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateExpiredDecimal   = "2"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateExpired          = 2
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateInvalidDecimal = "3"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateInvalid        = 3
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateExpiredDecimal = "4"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateExpired        = 4
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccSignatureInvalidDecimal   = "5"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccSignatureInvalid          = 5
	AuthenticateClientResponseEs9AuthenticateClientErrorValueMatchingIdRefusedDecimal       = "6"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueMatchingIdRefused              = 6
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEidMismatchDecimal             = "7"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueEidMismatch                    = 7
	AuthenticateClientResponseEs9AuthenticateClientErrorValueNoEligibleProfileDecimal       = "8"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueNoEligibleProfile              = 8
	AuthenticateClientResponseEs9AuthenticateClientErrorValueCiPKUnknownDecimal             = "9"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueCiPKUnknown                    = 9
	AuthenticateClientResponseEs9AuthenticateClientErrorValueInvalidTransactionIdDecimal    = "10"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueInvalidTransactionId           = 10
	AuthenticateClientResponseEs9AuthenticateClientErrorValueInsufficientMemoryDecimal      = "11"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueInsufficientMemory             = 11
	AuthenticateClientResponseEs9AuthenticateClientErrorValueDownloadOrderExpiredDecimal    = "18"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueDownloadOrderExpired           = 18
	AuthenticateClientResponseEs9AuthenticateClientErrorValueUndefinedErrorDecimal          = "127"
	AuthenticateClientResponseEs9AuthenticateClientErrorValueUndefinedError                 = 127
)

// NewAuthenticateClientResponseEs9AuthenticateClientErrorValue returns an immutable AuthenticateClientResponseEs9AuthenticateClientErrorValue containing value.
func NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(value *big.Int) AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return AuthenticateClientResponseEs9AuthenticateClientErrorValue{value: runtime.CloneBigInt(value)}
}

// NewAuthenticateClientResponseEs9AuthenticateClientErrorValueInt64 returns a AuthenticateClientResponseEs9AuthenticateClientErrorValue containing value.
func NewAuthenticateClientResponseEs9AuthenticateClientErrorValueInt64(value int64) AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(big.NewInt(value))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateInvalidValue returns the named value eumCertificateInvalid.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateInvalidValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateInvalidDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateExpiredValue returns the named value eumCertificateExpired.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateExpiredValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateExpiredDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateInvalidValue returns the named value euiccCertificateInvalid.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateInvalidValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateInvalidDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateExpiredValue returns the named value euiccCertificateExpired.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateExpiredValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateExpiredDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccSignatureInvalidValue returns the named value euiccSignatureInvalid.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccSignatureInvalidValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccSignatureInvalidDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueMatchingIdRefusedValue returns the named value matchingIdRefused.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueMatchingIdRefusedValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueMatchingIdRefusedDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueEidMismatchValue returns the named value eidMismatch.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueEidMismatchValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueEidMismatchDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueNoEligibleProfileValue returns the named value noEligibleProfile.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueNoEligibleProfileValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueNoEligibleProfileDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueCiPKUnknownValue returns the named value ciPKUnknown.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueCiPKUnknownValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueCiPKUnknownDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueInvalidTransactionIdValue returns the named value invalidTransactionId.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueInvalidTransactionIdValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueInvalidTransactionIdDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueInsufficientMemoryValue returns the named value insufficientMemory.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueInsufficientMemoryValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueInsufficientMemoryDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueDownloadOrderExpiredValue returns the named value downloadOrderExpired.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueDownloadOrderExpiredValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueDownloadOrderExpiredDecimal))
}

// AuthenticateClientResponseEs9AuthenticateClientErrorValueUndefinedErrorValue returns the named value undefinedError.
func AuthenticateClientResponseEs9AuthenticateClientErrorValueUndefinedErrorValue() AuthenticateClientResponseEs9AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs9AuthenticateClientErrorValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v AuthenticateClientResponseEs9AuthenticateClientErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v AuthenticateClientResponseEs9AuthenticateClientErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v AuthenticateClientResponseEs9AuthenticateClientErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateInvalidDecimal:
		return "eumCertificateInvalid", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueEumCertificateExpiredDecimal:
		return "eumCertificateExpired", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateInvalidDecimal:
		return "euiccCertificateInvalid", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccCertificateExpiredDecimal:
		return "euiccCertificateExpired", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueEuiccSignatureInvalidDecimal:
		return "euiccSignatureInvalid", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueMatchingIdRefusedDecimal:
		return "matchingIdRefused", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueEidMismatchDecimal:
		return "eidMismatch", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueNoEligibleProfileDecimal:
		return "noEligibleProfile", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueCiPKUnknownDecimal:
		return "ciPKUnknown", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueInvalidTransactionIdDecimal:
		return "invalidTransactionId", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueInsufficientMemoryDecimal:
		return "insufficientMemory", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueDownloadOrderExpiredDecimal:
		return "downloadOrderExpired", true
	case AuthenticateClientResponseEs9AuthenticateClientErrorValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v AuthenticateClientResponseEs9AuthenticateClientErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v AuthenticateClientResponseEs9AuthenticateClientErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *AuthenticateClientResponseEs9AuthenticateClientErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AuthenticateClientResponseEs9AuthenticateClientErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v AuthenticateClientResponseEs9AuthenticateClientErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *AuthenticateClientResponseEs9AuthenticateClientErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AuthenticateClientResponseEs9AuthenticateClientErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewAuthenticateClientResponseEs9AuthenticateClientErrorValue(value)
	return nil
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue represents the arbitrary-width ASN.1 INTEGER type GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue with named numbers.
type GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueEuiccSignatureInvalidDecimal           = "1"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueEuiccSignatureInvalid                  = 1
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeMissingDecimal         = "2"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeMissing                = 2
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRefusedDecimal         = "3"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRefused                = 3
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRetriesExceededDecimal = "4"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRetriesExceeded        = 4
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueBppRebindingRefusedDecimal             = "5"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueBppRebindingRefused                    = 5
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueDeprecatedDecimal                      = "6"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueDeprecated                             = 6
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInvalidTransactionIdDecimal            = "95"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInvalidTransactionId                   = 95
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueUndefinedErrorDecimal                  = "127"
	GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueUndefinedError                         = 127
)

// NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue returns an immutable GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue containing value.
func NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(value *big.Int) GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue{value: runtime.CloneBigInt(value)}
}

// NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInt64 returns a GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue containing value.
func NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInt64(value int64) GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(big.NewInt(value))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueEuiccSignatureInvalidValue returns the named value euiccSignatureInvalid.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueEuiccSignatureInvalidValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueEuiccSignatureInvalidDecimal))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeMissingValue returns the named value confirmationCodeMissing.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeMissingValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeMissingDecimal))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRefusedValue returns the named value confirmationCodeRefused.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRefusedValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRefusedDecimal))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRetriesExceededValue returns the named value confirmationCodeRetriesExceeded.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRetriesExceededValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRetriesExceededDecimal))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueBppRebindingRefusedValue returns the named value bppRebindingRefused.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueBppRebindingRefusedValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueBppRebindingRefusedDecimal))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueDeprecatedValue returns the named value deprecated.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueDeprecatedValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueDeprecatedDecimal))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInvalidTransactionIdValue returns the named value invalidTransactionId.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInvalidTransactionIdValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInvalidTransactionIdDecimal))
}

// GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueUndefinedErrorValue returns the named value undefinedError.
func GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueUndefinedErrorValue() GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue {
	return NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(runtime.MustParseBigIntDecimal(GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueEuiccSignatureInvalidDecimal:
		return "euiccSignatureInvalid", true
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeMissingDecimal:
		return "confirmationCodeMissing", true
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRefusedDecimal:
		return "confirmationCodeRefused", true
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueConfirmationCodeRetriesExceededDecimal:
		return "confirmationCodeRetriesExceeded", true
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueBppRebindingRefusedDecimal:
		return "bppRebindingRefused", true
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueDeprecatedDecimal:
		return "deprecated", true
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueInvalidTransactionIdDecimal:
		return "invalidTransactionId", true
	case GetBoundProfilePackageResponseGetBoundProfilePackageErrorValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewGetBoundProfilePackageResponseGetBoundProfilePackageErrorValue(value)
	return nil
}

// CancelSessionResponseEs9CancelSessionErrorValue represents the arbitrary-width ASN.1 INTEGER type CancelSessionResponseEs9CancelSessionErrorValue with named numbers.
type CancelSessionResponseEs9CancelSessionErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	CancelSessionResponseEs9CancelSessionErrorValueInvalidTransactionIdDecimal  = "1"
	CancelSessionResponseEs9CancelSessionErrorValueInvalidTransactionId         = 1
	CancelSessionResponseEs9CancelSessionErrorValueEuiccSignatureInvalidDecimal = "2"
	CancelSessionResponseEs9CancelSessionErrorValueEuiccSignatureInvalid        = 2
	CancelSessionResponseEs9CancelSessionErrorValueUndefinedErrorDecimal        = "127"
	CancelSessionResponseEs9CancelSessionErrorValueUndefinedError               = 127
)

// NewCancelSessionResponseEs9CancelSessionErrorValue returns an immutable CancelSessionResponseEs9CancelSessionErrorValue containing value.
func NewCancelSessionResponseEs9CancelSessionErrorValue(value *big.Int) CancelSessionResponseEs9CancelSessionErrorValue {
	return CancelSessionResponseEs9CancelSessionErrorValue{value: runtime.CloneBigInt(value)}
}

// NewCancelSessionResponseEs9CancelSessionErrorValueInt64 returns a CancelSessionResponseEs9CancelSessionErrorValue containing value.
func NewCancelSessionResponseEs9CancelSessionErrorValueInt64(value int64) CancelSessionResponseEs9CancelSessionErrorValue {
	return NewCancelSessionResponseEs9CancelSessionErrorValue(big.NewInt(value))
}

// CancelSessionResponseEs9CancelSessionErrorValueInvalidTransactionIdValue returns the named value invalidTransactionId.
func CancelSessionResponseEs9CancelSessionErrorValueInvalidTransactionIdValue() CancelSessionResponseEs9CancelSessionErrorValue {
	return NewCancelSessionResponseEs9CancelSessionErrorValue(runtime.MustParseBigIntDecimal(CancelSessionResponseEs9CancelSessionErrorValueInvalidTransactionIdDecimal))
}

// CancelSessionResponseEs9CancelSessionErrorValueEuiccSignatureInvalidValue returns the named value euiccSignatureInvalid.
func CancelSessionResponseEs9CancelSessionErrorValueEuiccSignatureInvalidValue() CancelSessionResponseEs9CancelSessionErrorValue {
	return NewCancelSessionResponseEs9CancelSessionErrorValue(runtime.MustParseBigIntDecimal(CancelSessionResponseEs9CancelSessionErrorValueEuiccSignatureInvalidDecimal))
}

// CancelSessionResponseEs9CancelSessionErrorValueUndefinedErrorValue returns the named value undefinedError.
func CancelSessionResponseEs9CancelSessionErrorValueUndefinedErrorValue() CancelSessionResponseEs9CancelSessionErrorValue {
	return NewCancelSessionResponseEs9CancelSessionErrorValue(runtime.MustParseBigIntDecimal(CancelSessionResponseEs9CancelSessionErrorValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v CancelSessionResponseEs9CancelSessionErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v CancelSessionResponseEs9CancelSessionErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v CancelSessionResponseEs9CancelSessionErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case CancelSessionResponseEs9CancelSessionErrorValueInvalidTransactionIdDecimal:
		return "invalidTransactionId", true
	case CancelSessionResponseEs9CancelSessionErrorValueEuiccSignatureInvalidDecimal:
		return "euiccSignatureInvalid", true
	case CancelSessionResponseEs9CancelSessionErrorValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v CancelSessionResponseEs9CancelSessionErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v CancelSessionResponseEs9CancelSessionErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *CancelSessionResponseEs9CancelSessionErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal CancelSessionResponseEs9CancelSessionErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewCancelSessionResponseEs9CancelSessionErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v CancelSessionResponseEs9CancelSessionErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *CancelSessionResponseEs9CancelSessionErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal CancelSessionResponseEs9CancelSessionErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewCancelSessionResponseEs9CancelSessionErrorValue(value)
	return nil
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValue represents the arbitrary-width ASN.1 INTEGER type AuthenticateClientResponseEs11AuthenticateClientErrorValue with named numbers.
type AuthenticateClientResponseEs11AuthenticateClientErrorValue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateInvalidDecimal   = "1"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateInvalid          = 1
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateExpiredDecimal   = "2"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateExpired          = 2
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateInvalidDecimal = "3"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateInvalid        = 3
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateExpiredDecimal = "4"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateExpired        = 4
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccSignatureInvalidDecimal   = "5"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccSignatureInvalid          = 5
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEventIdUnknownDecimal          = "6"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueEventIdUnknown                 = 6
	AuthenticateClientResponseEs11AuthenticateClientErrorValueInvalidTransactionIdDecimal    = "7"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueInvalidTransactionId           = 7
	AuthenticateClientResponseEs11AuthenticateClientErrorValueUndefinedErrorDecimal          = "127"
	AuthenticateClientResponseEs11AuthenticateClientErrorValueUndefinedError                 = 127
)

// NewAuthenticateClientResponseEs11AuthenticateClientErrorValue returns an immutable AuthenticateClientResponseEs11AuthenticateClientErrorValue containing value.
func NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(value *big.Int) AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return AuthenticateClientResponseEs11AuthenticateClientErrorValue{value: runtime.CloneBigInt(value)}
}

// NewAuthenticateClientResponseEs11AuthenticateClientErrorValueInt64 returns a AuthenticateClientResponseEs11AuthenticateClientErrorValue containing value.
func NewAuthenticateClientResponseEs11AuthenticateClientErrorValueInt64(value int64) AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(big.NewInt(value))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateInvalidValue returns the named value eumCertificateInvalid.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateInvalidValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateInvalidDecimal))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateExpiredValue returns the named value eumCertificateExpired.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateExpiredValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateExpiredDecimal))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateInvalidValue returns the named value euiccCertificateInvalid.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateInvalidValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateInvalidDecimal))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateExpiredValue returns the named value euiccCertificateExpired.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateExpiredValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateExpiredDecimal))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccSignatureInvalidValue returns the named value euiccSignatureInvalid.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccSignatureInvalidValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccSignatureInvalidDecimal))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueEventIdUnknownValue returns the named value eventIdUnknown.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueEventIdUnknownValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueEventIdUnknownDecimal))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueInvalidTransactionIdValue returns the named value invalidTransactionId.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueInvalidTransactionIdValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueInvalidTransactionIdDecimal))
}

// AuthenticateClientResponseEs11AuthenticateClientErrorValueUndefinedErrorValue returns the named value undefinedError.
func AuthenticateClientResponseEs11AuthenticateClientErrorValueUndefinedErrorValue() AuthenticateClientResponseEs11AuthenticateClientErrorValue {
	return NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(runtime.MustParseBigIntDecimal(AuthenticateClientResponseEs11AuthenticateClientErrorValueUndefinedErrorDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v AuthenticateClientResponseEs11AuthenticateClientErrorValue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v AuthenticateClientResponseEs11AuthenticateClientErrorValue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v AuthenticateClientResponseEs11AuthenticateClientErrorValue) Name() (string, bool) {
	switch v.BigInt().String() {
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateInvalidDecimal:
		return "eumCertificateInvalid", true
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueEumCertificateExpiredDecimal:
		return "eumCertificateExpired", true
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateInvalidDecimal:
		return "euiccCertificateInvalid", true
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccCertificateExpiredDecimal:
		return "euiccCertificateExpired", true
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueEuiccSignatureInvalidDecimal:
		return "euiccSignatureInvalid", true
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueEventIdUnknownDecimal:
		return "eventIdUnknown", true
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueInvalidTransactionIdDecimal:
		return "invalidTransactionId", true
	case AuthenticateClientResponseEs11AuthenticateClientErrorValueUndefinedErrorDecimal:
		return "undefinedError", true
	default:
		return "", false
	}
}

func (v AuthenticateClientResponseEs11AuthenticateClientErrorValue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v AuthenticateClientResponseEs11AuthenticateClientErrorValue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *AuthenticateClientResponseEs11AuthenticateClientErrorValue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AuthenticateClientResponseEs11AuthenticateClientErrorValue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v AuthenticateClientResponseEs11AuthenticateClientErrorValue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *AuthenticateClientResponseEs11AuthenticateClientErrorValue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal AuthenticateClientResponseEs11AuthenticateClientErrorValue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewAuthenticateClientResponseEs11AuthenticateClientErrorValue(value)
	return nil
}

// AuthenticateClientOkEs11EventEntries represents the ASN.1 type AuthenticateClientOkEs11EventEntries (SEQUENCE_OF).
type AuthenticateClientOkEs11EventEntries = []EventEntries

// MarshalBER encodes OperatorId to BER format.
func (v *OperatorId) MarshalBER() ([]byte, error) {
	var children []byte
	enc_mccmnc := ber.EncodeOctetString(v.MccMnc)
	enc_mccmnc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_mccmnc)
	children = append(children, enc_mccmnc...)
	if v.Gid1 != nil {
		enc_gid1 := ber.EncodeOctetString(v.Gid1)
		enc_gid1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_gid1)
		children = append(children, enc_gid1...)
	}
	if v.Gid2 != nil {
		enc_gid2 := ber.EncodeOctetString(v.Gid2)
		enc_gid2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_gid2)
		children = append(children, enc_gid2...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes OperatorId to DER format.
func (v *OperatorId) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes OperatorId from BER/DER format.
func (v *OperatorId) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OperatorId SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OperatorId", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode mccMnc
	if offset >= len(content) {
		return fmt.Errorf("missing required field mccMnc")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for mccMnc, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_mccmnc, rawVal_mccmnc, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding mccMnc: %w", err)
	}
	v.MccMnc = rawVal_mccmnc
	offset += n_mccmnc
	// Decode gid1
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_gid1, rawVal_gid1, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gid1: %w", err)
				}
				tmp_gid1 := rawVal_gid1
				v.Gid1 = tmp_gid1
				offset += n_gid1
			}
		}
	}
	// Decode gid2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_gid2, rawVal_gid2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gid2: %w", err)
				}
				tmp_gid2 := rawVal_gid2
				v.Gid2 = tmp_gid2
				offset += n_gid2
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OperatorId", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes BoundProfilePackage to BER format.
func (v *BoundProfilePackage) MarshalBER() ([]byte, error) {
	var children []byte
	enc_initialisesecurechannelrequest, err := v.InitialiseSecureChannelRequest.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding initialiseSecureChannelRequest: %w", err)
	}
	children = append(children, enc_initialisesecurechannelrequest...)
	enc_firstsequenceof87, err := MarshalBERBoundProfilePackageFirstSequenceOf87(v.FirstSequenceOf87)
	if err != nil {
		return nil, fmt.Errorf("encoding firstSequenceOf87: %w", err)
	}
	if v.FirstSequenceOf87Indef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_firstsequenceof87)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_firstsequenceof87 = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_firstsequenceof87 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_firstsequenceof87)
	}
	children = append(children, enc_firstsequenceof87...)
	enc_sequenceof88, err := MarshalBERBoundProfilePackageSequenceOf88(v.SequenceOf88)
	if err != nil {
		return nil, fmt.Errorf("encoding sequenceOf88: %w", err)
	}
	if v.SequenceOf88Indef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_sequenceof88)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_sequenceof88 = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
	} else {
		enc_sequenceof88 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_sequenceof88)
	}
	children = append(children, enc_sequenceof88...)
	if v.SecondSequenceOf87 != nil {
		enc_secondsequenceof87, err := MarshalBERBoundProfilePackageSecondSequenceOf87(v.SecondSequenceOf87)
		if err != nil {
			return nil, fmt.Errorf("encoding secondSequenceOf87: %w", err)
		}
		if v.SecondSequenceOf87Indef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_secondsequenceof87)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_secondsequenceof87 = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_secondsequenceof87 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_secondsequenceof87)
		}
		children = append(children, enc_secondsequenceof87...)
	}
	enc_sequenceof86, err := MarshalBERBoundProfilePackageSequenceOf86(v.SequenceOf86)
	if err != nil {
		return nil, fmt.Errorf("encoding sequenceOf86: %w", err)
	}
	if v.SequenceOf86Indef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_sequenceof86)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_sequenceof86 = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
	} else {
		enc_sequenceof86 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_sequenceof86)
	}
	children = append(children, enc_sequenceof86...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 54, Constructed: true}, children), nil
}

// MarshalDER encodes BoundProfilePackage to DER format.
func (v *BoundProfilePackage) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.FirstSequenceOf87Indef_ = false
	derValue.SequenceOf88Indef_ = false
	derValue.SecondSequenceOf87Indef_ = false
	derValue.SequenceOf86Indef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes BoundProfilePackage from BER/DER format.
func (v *BoundProfilePackage) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding BoundProfilePackage: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 54 || !decodedTag.Constructed {
		return fmt.Errorf("decoding BoundProfilePackage: %w: expected tag [CONTEXT 54], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BoundProfilePackage", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode initialiseSecureChannelRequest
	if offset >= len(content) {
		return fmt.Errorf("missing required field initialiseSecureChannelRequest")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 35 {
			return fmt.Errorf("expected tag [%s %d] for initialiseSecureChannelRequest, got %s", "CONTEXT", 35, reqTag_)
		}
	}
	// Decode nested SEQUENCE (InitialiseSecureChannelRequest)
	_, n_initialisesecurechannelrequest, _, tlvErr_initialisesecurechannelrequest := ber.DecodeTLV(content[offset:])
	if tlvErr_initialisesecurechannelrequest != nil {
		return fmt.Errorf("decoding initialiseSecureChannelRequest: %w", tlvErr_initialisesecurechannelrequest)
	}
	if unmErr := v.InitialiseSecureChannelRequest.UnmarshalBER(content[offset : offset+n_initialisesecurechannelrequest]); unmErr != nil {
		return fmt.Errorf("decoding initialiseSecureChannelRequest: %w", unmErr)
	}
	offset += n_initialisesecurechannelrequest
	// Decode firstSequenceOf87
	if offset >= len(content) {
		return fmt.Errorf("missing required field firstSequenceOf87")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for firstSequenceOf87, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.FirstSequenceOf87Indef_ = false
	_, n_firstsequenceof87, rawVal_firstsequenceof87, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding firstSequenceOf87: %w", err)
	}
	reconstructed_firstsequenceof87 := ber.EncodeSequence(rawVal_firstsequenceof87)
	dec_firstsequenceof87, unmErr := UnmarshalBERBoundProfilePackageFirstSequenceOf87(reconstructed_firstsequenceof87)
	if unmErr != nil {
		return fmt.Errorf("decoding firstSequenceOf87: %w", unmErr)
	}
	v.FirstSequenceOf87 = dec_firstsequenceof87
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.FirstSequenceOf87Indef_ = true
		}
	}
	offset += n_firstsequenceof87
	// Decode sequenceOf88
	if offset >= len(content) {
		return fmt.Errorf("missing required field sequenceOf88")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for sequenceOf88, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	v.SequenceOf88Indef_ = false
	_, n_sequenceof88, rawVal_sequenceof88, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sequenceOf88: %w", err)
	}
	reconstructed_sequenceof88 := ber.EncodeSequence(rawVal_sequenceof88)
	dec_sequenceof88, unmErr := UnmarshalBERBoundProfilePackageSequenceOf88(reconstructed_sequenceof88)
	if unmErr != nil {
		return fmt.Errorf("decoding sequenceOf88: %w", unmErr)
	}
	v.SequenceOf88 = dec_sequenceof88
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.SequenceOf88Indef_ = true
		}
	}
	offset += n_sequenceof88
	// Decode secondSequenceOf87
	v.SecondSequenceOf87Indef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_secondsequenceof87, rawVal_secondsequenceof87, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding secondSequenceOf87: %w", err)
				}
				reconstructed_secondsequenceof87 := ber.EncodeSequence(rawVal_secondsequenceof87)
				dec_secondsequenceof87, unmErr := UnmarshalBERBoundProfilePackageSecondSequenceOf87(reconstructed_secondsequenceof87)
				if unmErr != nil {
					return fmt.Errorf("decoding secondSequenceOf87: %w", unmErr)
				}
				v.SecondSequenceOf87 = dec_secondsequenceof87
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.SecondSequenceOf87Indef_ = true
					}
				}
				offset += n_secondsequenceof87
			}
		}
	}
	// Decode sequenceOf86
	if offset >= len(content) {
		return fmt.Errorf("missing required field sequenceOf86")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for sequenceOf86, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	v.SequenceOf86Indef_ = false
	_, n_sequenceof86, rawVal_sequenceof86, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sequenceOf86: %w", err)
	}
	reconstructed_sequenceof86 := ber.EncodeSequence(rawVal_sequenceof86)
	dec_sequenceof86, unmErr := UnmarshalBERBoundProfilePackageSequenceOf86(reconstructed_sequenceof86)
	if unmErr != nil {
		return fmt.Errorf("decoding sequenceOf86: %w", unmErr)
	}
	v.SequenceOf86 = dec_sequenceof86
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.SequenceOf86Indef_ = true
		}
	}
	offset += n_sequenceof86
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BoundProfilePackage", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProfileInstallationResult to BER format.
func (v *ProfileInstallationResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profileinstallationresultdata, err := v.ProfileInstallationResultData.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding profileInstallationResultData: %w", err)
	}
	children = append(children, enc_profileinstallationresultdata...)
	enc_euiccsignpir := ber.EncodeOctetString([]byte(v.EuiccSignPIR))
	enc_euiccsignpir = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignpir)
	children = append(children, enc_euiccsignpir...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 55, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileInstallationResult to DER format.
func (v *ProfileInstallationResult) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInstallationResult from BER/DER format.
func (v *ProfileInstallationResult) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInstallationResult: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 55 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInstallationResult: %w: expected tag [CONTEXT 55], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInstallationResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileInstallationResultData
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileInstallationResultData")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 39 {
			return fmt.Errorf("expected tag [%s %d] for profileInstallationResultData, got %s", "CONTEXT", 39, reqTag_)
		}
	}
	// Decode nested SEQUENCE (ProfileInstallationResultData)
	_, n_profileinstallationresultdata, _, tlvErr_profileinstallationresultdata := ber.DecodeTLV(content[offset:])
	if tlvErr_profileinstallationresultdata != nil {
		return fmt.Errorf("decoding profileInstallationResultData: %w", tlvErr_profileinstallationresultdata)
	}
	if unmErr := v.ProfileInstallationResultData.UnmarshalBER(content[offset : offset+n_profileinstallationresultdata]); unmErr != nil {
		return fmt.Errorf("decoding profileInstallationResultData: %w", unmErr)
	}
	offset += n_profileinstallationresultdata
	// Decode euiccSignPIR
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignPIR")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignPIR, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignpir, rawVal_euiccsignpir, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignPIR: %w", err)
	}
	v.EuiccSignPIR = EuiccSignPIR(rawVal_euiccsignpir)
	offset += n_euiccsignpir
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProfileInstallationResult", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProfileInstallationResultData to BER format.
func (v *ProfileInstallationResultData) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_notificationmetadata, err := v.NotificationMetadata.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding notificationMetadata: %w", err)
	}
	children = append(children, enc_notificationmetadata...)
	enc_smdpoid := ber.EncodeObjectIdentifier([]uint64(v.SmdpOid))
	children = append(children, enc_smdpoid...)
	enc_finalresult, err := v.FinalResult.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding finalResult: %w", err)
	}
	enc_finalresult = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_finalresult)
	children = append(children, enc_finalresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 39, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileInstallationResultData to DER format.
func (v *ProfileInstallationResultData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInstallationResultData from BER/DER format.
func (v *ProfileInstallationResultData) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInstallationResultData: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 39 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInstallationResultData: %w: expected tag [CONTEXT 39], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInstallationResultData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode notificationMetadata
	if offset >= len(content) {
		return fmt.Errorf("missing required field notificationMetadata")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 47 {
			return fmt.Errorf("expected tag [%s %d] for notificationMetadata, got %s", "CONTEXT", 47, reqTag_)
		}
	}
	// Decode nested SEQUENCE (NotificationMetadata)
	_, n_notificationmetadata, _, tlvErr_notificationmetadata := ber.DecodeTLV(content[offset:])
	if tlvErr_notificationmetadata != nil {
		return fmt.Errorf("decoding notificationMetadata: %w", tlvErr_notificationmetadata)
	}
	if unmErr := v.NotificationMetadata.UnmarshalBER(content[offset : offset+n_notificationmetadata]); unmErr != nil {
		return fmt.Errorf("decoding notificationMetadata: %w", unmErr)
	}
	offset += n_notificationmetadata
	// Decode smdpOid
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpOid")
	}
	val_smdpoid, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpOid: %w", err)
	}
	v.SmdpOid = runtime.ObjectIdentifier(val_smdpoid)
	offset += n
	// Decode finalResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field finalResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for finalResult, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_finalresult, innerData_finalresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding finalResult: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.FinalResult.UnmarshalBER(innerData_finalresult); unmErr != nil {
		return fmt.Errorf("decoding finalResult: %w", unmErr)
	}
	offset += n_finalresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProfileInstallationResultData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SuccessResult to BER format.
func (v *SuccessResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_aid := ber.EncodeOctetString(v.Aid)
	enc_aid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_aid)
	children = append(children, enc_aid...)
	enc_simaresponse := ber.EncodeOctetString(v.SimaResponse)
	children = append(children, enc_simaresponse...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SuccessResult to DER format.
func (v *SuccessResult) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SuccessResult from BER/DER format.
func (v *SuccessResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SuccessResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SuccessResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode aid
	if offset >= len(content) {
		return fmt.Errorf("missing required field aid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 15 {
			return fmt.Errorf("expected tag [%s %d] for aid, got %s", "APPLICATION", 15, reqTag_)
		}
	}
	_, n_aid, rawVal_aid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding aid: %w", err)
	}
	v.Aid = rawVal_aid
	offset += n_aid
	// Decode simaResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field simaResponse")
	}
	val_simaresponse, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding simaResponse: %w", err)
	}
	v.SimaResponse = val_simaresponse
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SuccessResult", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ErrorResult to BER format.
func (v *ErrorResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_bppcommandid := ber.EncodeBigInt((v.BppCommandId).BigInt())
	enc_bppcommandid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_bppcommandid)
	children = append(children, enc_bppcommandid...)
	enc_errorreason := ber.EncodeBigInt((v.ErrorReason).BigInt())
	enc_errorreason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_errorreason)
	children = append(children, enc_errorreason...)
	if v.SimaResponse != nil {
		enc_simaresponse := ber.EncodeOctetString(v.SimaResponse)
		enc_simaresponse = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_simaresponse)
		children = append(children, enc_simaresponse...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ErrorResult to DER format.
func (v *ErrorResult) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ErrorResult from BER/DER format.
func (v *ErrorResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ErrorResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ErrorResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode bppCommandId
	if offset >= len(content) {
		return fmt.Errorf("missing required field bppCommandId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for bppCommandId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_bppcommandid, rawVal_bppcommandid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding bppCommandId: %w", err)
	}
	decVal_bppcommandid, intErr := ber.DecodeBigIntValue(rawVal_bppcommandid)
	if intErr != nil {
		return fmt.Errorf("decoding bppCommandId: %w", intErr)
	}
	var named_bppcommandid BppCommandId
	if namedErr := named_bppcommandid.UnmarshalText([]byte(decVal_bppcommandid.String())); namedErr != nil {
		return fmt.Errorf("decoding bppCommandId: %w", namedErr)
	}
	v.BppCommandId = named_bppcommandid
	offset += n_bppcommandid
	// Decode errorReason
	if offset >= len(content) {
		return fmt.Errorf("missing required field errorReason")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for errorReason, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_errorreason, rawVal_errorreason, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding errorReason: %w", err)
	}
	decVal_errorreason, intErr := ber.DecodeBigIntValue(rawVal_errorreason)
	if intErr != nil {
		return fmt.Errorf("decoding errorReason: %w", intErr)
	}
	var named_errorreason ErrorReason
	if namedErr := named_errorreason.UnmarshalText([]byte(decVal_errorreason.String())); namedErr != nil {
		return fmt.Errorf("decoding errorReason: %w", namedErr)
	}
	v.ErrorReason = named_errorreason
	offset += n_errorreason
	// Decode simaResponse
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_simaresponse, rawVal_simaresponse, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding simaResponse: %w", err)
				}
				tmp_simaresponse := rawVal_simaresponse
				v.SimaResponse = tmp_simaresponse
				offset += n_simaresponse
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ErrorResult", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeviceInfo to BER format.
func (v *DeviceInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_tac := ber.EncodeOctetString([]byte(v.Tac))
	enc_tac = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_tac)
	children = append(children, enc_tac...)
	enc_devicecapabilities, err := v.DeviceCapabilities.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding deviceCapabilities: %w", err)
	}
	enc_devicecapabilities = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_devicecapabilities)
	children = append(children, enc_devicecapabilities...)
	if v.Imei != nil {
		enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		enc_imei = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_imei)
		children = append(children, enc_imei...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DeviceInfo to DER format.
func (v *DeviceInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeviceInfo from BER/DER format.
func (v *DeviceInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeviceInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeviceInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode tac
	if offset >= len(content) {
		return fmt.Errorf("missing required field tac")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for tac, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_tac, rawVal_tac, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding tac: %w", err)
	}
	v.Tac = Octet4(rawVal_tac)
	offset += n_tac
	// Decode deviceCapabilities
	if offset >= len(content) {
		return fmt.Errorf("missing required field deviceCapabilities")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for deviceCapabilities, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_devicecapabilities, rawVal_devicecapabilities, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deviceCapabilities: %w", err)
	}
	reconstructed_devicecapabilities := ber.EncodeSequence(rawVal_devicecapabilities)
	if unmErr := v.DeviceCapabilities.UnmarshalBER(reconstructed_devicecapabilities); unmErr != nil {
		return fmt.Errorf("decoding deviceCapabilities: %w", unmErr)
	}
	offset += n_devicecapabilities
	// Decode imei
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_imei, rawVal_imei, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imei: %w", err)
				}
				tmp_imei := Octet8(rawVal_imei)
				v.Imei = &tmp_imei
				offset += n_imei
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeviceInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeviceCapabilities to BER format.
func (v *DeviceCapabilities) MarshalBER() ([]byte, error) {
	var children []byte
	if v.GsmSupportedRelease != nil {
		enc_gsmsupportedrelease := ber.EncodeOctetString([]byte(*v.GsmSupportedRelease))
		enc_gsmsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_gsmsupportedrelease)
		children = append(children, enc_gsmsupportedrelease...)
	}
	if v.UtranSupportedRelease != nil {
		enc_utransupportedrelease := ber.EncodeOctetString([]byte(*v.UtranSupportedRelease))
		enc_utransupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_utransupportedrelease)
		children = append(children, enc_utransupportedrelease...)
	}
	if v.Cdma2000onexSupportedRelease != nil {
		enc_cdma2000onexsupportedrelease := ber.EncodeOctetString([]byte(*v.Cdma2000onexSupportedRelease))
		enc_cdma2000onexsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_cdma2000onexsupportedrelease)
		children = append(children, enc_cdma2000onexsupportedrelease...)
	}
	if v.Cdma2000hrpdSupportedRelease != nil {
		enc_cdma2000hrpdsupportedrelease := ber.EncodeOctetString([]byte(*v.Cdma2000hrpdSupportedRelease))
		enc_cdma2000hrpdsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_cdma2000hrpdsupportedrelease)
		children = append(children, enc_cdma2000hrpdsupportedrelease...)
	}
	if v.Cdma2000ehrpdSupportedRelease != nil {
		enc_cdma2000ehrpdsupportedrelease := ber.EncodeOctetString([]byte(*v.Cdma2000ehrpdSupportedRelease))
		enc_cdma2000ehrpdsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_cdma2000ehrpdsupportedrelease)
		children = append(children, enc_cdma2000ehrpdsupportedrelease...)
	}
	if v.EutranEpcSupportedRelease != nil {
		enc_eutranepcsupportedrelease := ber.EncodeOctetString([]byte(*v.EutranEpcSupportedRelease))
		enc_eutranepcsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_eutranepcsupportedrelease)
		children = append(children, enc_eutranepcsupportedrelease...)
	}
	if v.ContactlessSupportedRelease != nil {
		enc_contactlesssupportedrelease := ber.EncodeOctetString([]byte(*v.ContactlessSupportedRelease))
		enc_contactlesssupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_contactlesssupportedrelease)
		children = append(children, enc_contactlesssupportedrelease...)
	}
	if v.RspCrlSupportedVersion != nil {
		enc_rspcrlsupportedversion := ber.EncodeOctetString([]byte(*v.RspCrlSupportedVersion))
		enc_rspcrlsupportedversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_rspcrlsupportedversion)
		children = append(children, enc_rspcrlsupportedversion...)
	}
	if v.NrEpcSupportedRelease != nil {
		enc_nrepcsupportedrelease := ber.EncodeOctetString([]byte(*v.NrEpcSupportedRelease))
		enc_nrepcsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_nrepcsupportedrelease)
		children = append(children, enc_nrepcsupportedrelease...)
	}
	if v.Nr5gcSupportedRelease != nil {
		enc_nr5gcsupportedrelease := ber.EncodeOctetString([]byte(*v.Nr5gcSupportedRelease))
		enc_nr5gcsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_nr5gcsupportedrelease)
		children = append(children, enc_nr5gcsupportedrelease...)
	}
	if v.Eutran5gcSupportedRelease != nil {
		enc_eutran5gcsupportedrelease := ber.EncodeOctetString([]byte(*v.Eutran5gcSupportedRelease))
		enc_eutran5gcsupportedrelease = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_eutran5gcsupportedrelease)
		children = append(children, enc_eutran5gcsupportedrelease...)
	}
	if v.LpaSvn != nil {
		enc_lpasvn := ber.EncodeOctetString([]byte(*v.LpaSvn))
		enc_lpasvn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_lpasvn)
		children = append(children, enc_lpasvn...)
	}
	if v.CatSupportedClasses != nil {
		enc_catsupportedclasses := ber.EncodeBitString(v.CatSupportedClasses.Bytes, (8-(v.CatSupportedClasses.BitLength%8))%8)
		enc_catsupportedclasses = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_catsupportedclasses)
		children = append(children, enc_catsupportedclasses...)
	}
	if v.EuiccFormFactorType != nil {
		enc_euiccformfactortype := ber.EncodeBigInt(v.EuiccFormFactorType)
		enc_euiccformfactortype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_euiccformfactortype)
		children = append(children, enc_euiccformfactortype...)
	}
	if v.DeviceAdditionalFeatureSupport != nil {
		enc_deviceadditionalfeaturesupport, err := v.DeviceAdditionalFeatureSupport.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding deviceAdditionalFeatureSupport: %w", err)
		}
		enc_deviceadditionalfeaturesupport = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, true, enc_deviceadditionalfeaturesupport)
		children = append(children, enc_deviceadditionalfeaturesupport...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DeviceCapabilities to DER format.
func (v *DeviceCapabilities) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeviceCapabilities from BER/DER format.
func (v *DeviceCapabilities) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeviceCapabilities SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeviceCapabilities", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode gsmSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_gsmsupportedrelease, rawVal_gsmsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gsmSupportedRelease: %w", err)
				}
				tmp_gsmsupportedrelease := VersionType(rawVal_gsmsupportedrelease)
				v.GsmSupportedRelease = &tmp_gsmsupportedrelease
				offset += n_gsmsupportedrelease
			}
		}
	}
	// Decode utranSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_utransupportedrelease, rawVal_utransupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranSupportedRelease: %w", err)
				}
				tmp_utransupportedrelease := VersionType(rawVal_utransupportedrelease)
				v.UtranSupportedRelease = &tmp_utransupportedrelease
				offset += n_utransupportedrelease
			}
		}
	}
	// Decode cdma2000onexSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_cdma2000onexsupportedrelease, rawVal_cdma2000onexsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cdma2000onexSupportedRelease: %w", err)
				}
				tmp_cdma2000onexsupportedrelease := VersionType(rawVal_cdma2000onexsupportedrelease)
				v.Cdma2000onexSupportedRelease = &tmp_cdma2000onexsupportedrelease
				offset += n_cdma2000onexsupportedrelease
			}
		}
	}
	// Decode cdma2000hrpdSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_cdma2000hrpdsupportedrelease, rawVal_cdma2000hrpdsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cdma2000hrpdSupportedRelease: %w", err)
				}
				tmp_cdma2000hrpdsupportedrelease := VersionType(rawVal_cdma2000hrpdsupportedrelease)
				v.Cdma2000hrpdSupportedRelease = &tmp_cdma2000hrpdsupportedrelease
				offset += n_cdma2000hrpdsupportedrelease
			}
		}
	}
	// Decode cdma2000ehrpdSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_cdma2000ehrpdsupportedrelease, rawVal_cdma2000ehrpdsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cdma2000ehrpdSupportedRelease: %w", err)
				}
				tmp_cdma2000ehrpdsupportedrelease := VersionType(rawVal_cdma2000ehrpdsupportedrelease)
				v.Cdma2000ehrpdSupportedRelease = &tmp_cdma2000ehrpdsupportedrelease
				offset += n_cdma2000ehrpdsupportedrelease
			}
		}
	}
	// Decode eutranEpcSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_eutranepcsupportedrelease, rawVal_eutranepcsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eutranEpcSupportedRelease: %w", err)
				}
				tmp_eutranepcsupportedrelease := VersionType(rawVal_eutranepcsupportedrelease)
				v.EutranEpcSupportedRelease = &tmp_eutranepcsupportedrelease
				offset += n_eutranepcsupportedrelease
			}
		}
	}
	// Decode contactlessSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_contactlesssupportedrelease, rawVal_contactlesssupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding contactlessSupportedRelease: %w", err)
				}
				tmp_contactlesssupportedrelease := VersionType(rawVal_contactlesssupportedrelease)
				v.ContactlessSupportedRelease = &tmp_contactlesssupportedrelease
				offset += n_contactlesssupportedrelease
			}
		}
	}
	// Decode rspCrlSupportedVersion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_rspcrlsupportedversion, rawVal_rspcrlsupportedversion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rspCrlSupportedVersion: %w", err)
				}
				tmp_rspcrlsupportedversion := VersionType(rawVal_rspcrlsupportedversion)
				v.RspCrlSupportedVersion = &tmp_rspcrlsupportedversion
				offset += n_rspcrlsupportedversion
			}
		}
	}
	// Decode nrEpcSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_nrepcsupportedrelease, rawVal_nrepcsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nrEpcSupportedRelease: %w", err)
				}
				tmp_nrepcsupportedrelease := VersionType(rawVal_nrepcsupportedrelease)
				v.NrEpcSupportedRelease = &tmp_nrepcsupportedrelease
				offset += n_nrepcsupportedrelease
			}
		}
	}
	// Decode nr5gcSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_nr5gcsupportedrelease, rawVal_nr5gcsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nr5gcSupportedRelease: %w", err)
				}
				tmp_nr5gcsupportedrelease := VersionType(rawVal_nr5gcsupportedrelease)
				v.Nr5gcSupportedRelease = &tmp_nr5gcsupportedrelease
				offset += n_nr5gcsupportedrelease
			}
		}
	}
	// Decode eutran5gcSupportedRelease
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_eutran5gcsupportedrelease, rawVal_eutran5gcsupportedrelease, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eutran5gcSupportedRelease: %w", err)
				}
				tmp_eutran5gcsupportedrelease := VersionType(rawVal_eutran5gcsupportedrelease)
				v.Eutran5gcSupportedRelease = &tmp_eutran5gcsupportedrelease
				offset += n_eutran5gcsupportedrelease
			}
		}
	}
	// Decode lpaSvn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_lpasvn, rawVal_lpasvn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lpaSvn: %w", err)
				}
				tmp_lpasvn := VersionType(rawVal_lpasvn)
				v.LpaSvn = &tmp_lpasvn
				offset += n_lpasvn
			}
		}
	}
	// Decode catSupportedClasses
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_catsupportedclasses, rawVal_catsupportedclasses, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding catSupportedClasses: %w", err)
				}
				bsBytes_catsupportedclasses, bsUnused_catsupportedclasses, bsErr := ber.DecodeBitStringValue(rawVal_catsupportedclasses)
				if bsErr != nil {
					return fmt.Errorf("decoding catSupportedClasses: %w", bsErr)
				}
				tmp_catsupportedclasses := runtime.BitString{Bytes: bsBytes_catsupportedclasses, BitLength: len(bsBytes_catsupportedclasses)*8 - bsUnused_catsupportedclasses}
				v.CatSupportedClasses = &tmp_catsupportedclasses
				offset += n_catsupportedclasses
			}
		}
	}
	// Decode euiccFormFactorType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_euiccformfactortype, rawVal_euiccformfactortype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccFormFactorType: %w", err)
				}
				decVal_euiccformfactortype, intErr := ber.DecodeBigIntValue(rawVal_euiccformfactortype)
				if intErr != nil {
					return fmt.Errorf("decoding euiccFormFactorType: %w", intErr)
				}
				v.EuiccFormFactorType = decVal_euiccformfactortype
				offset += n_euiccformfactortype
			}
		}
	}
	// Decode deviceAdditionalFeatureSupport
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_deviceadditionalfeaturesupport, rawVal_deviceadditionalfeaturesupport, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deviceAdditionalFeatureSupport: %w", err)
				}
				reconstructed_deviceadditionalfeaturesupport := ber.EncodeSequence(rawVal_deviceadditionalfeaturesupport)
				var dec_deviceadditionalfeaturesupport DeviceAdditionalFeatureSupport
				if unmErr := dec_deviceadditionalfeaturesupport.UnmarshalBER(reconstructed_deviceadditionalfeaturesupport); unmErr != nil {
					return fmt.Errorf("decoding deviceAdditionalFeatureSupport: %w", unmErr)
				}
				v.DeviceAdditionalFeatureSupport = &dec_deviceadditionalfeaturesupport
				offset += n_deviceadditionalfeaturesupport
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeviceCapabilities", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeviceAdditionalFeatureSupport to BER format.
func (v *DeviceAdditionalFeatureSupport) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NaiSupport != nil {
		enc_naisupport := ber.EncodeOctetString([]byte(*v.NaiSupport))
		enc_naisupport = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_naisupport)
		children = append(children, enc_naisupport...)
	}
	if v.GroupOfDeviceManufacturerOid != nil {
		enc_groupofdevicemanufactureroid := ber.EncodeObjectIdentifier([]uint64(v.GroupOfDeviceManufacturerOid))
		enc_groupofdevicemanufactureroid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_groupofdevicemanufactureroid)
		children = append(children, enc_groupofdevicemanufactureroid...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DeviceAdditionalFeatureSupport to DER format.
func (v *DeviceAdditionalFeatureSupport) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeviceAdditionalFeatureSupport from BER/DER format.
func (v *DeviceAdditionalFeatureSupport) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeviceAdditionalFeatureSupport SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeviceAdditionalFeatureSupport", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode naiSupport
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_naisupport, rawVal_naisupport, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding naiSupport: %w", err)
				}
				tmp_naisupport := VersionType(rawVal_naisupport)
				v.NaiSupport = &tmp_naisupport
				offset += n_naisupport
			}
		}
	}
	// Decode groupOfDeviceManufacturerOid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_groupofdevicemanufactureroid, rawVal_groupofdevicemanufactureroid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding groupOfDeviceManufacturerOid: %w", err)
				}
				decVal_groupofdevicemanufactureroid, oidErr := ber.DecodeOIDValue(rawVal_groupofdevicemanufactureroid)
				if oidErr != nil {
					return fmt.Errorf("decoding groupOfDeviceManufacturerOid: %w", oidErr)
				}
				tmp_groupofdevicemanufactureroid := runtime.ObjectIdentifier(decVal_groupofdevicemanufactureroid)
				v.GroupOfDeviceManufacturerOid = tmp_groupofdevicemanufactureroid
				offset += n_groupofdevicemanufactureroid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeviceAdditionalFeatureSupport", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSegmentedCrlList encodes a SegmentedCrlList list to BER.
func MarshalBERSegmentedCrlList(list SegmentedCrlList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSegmentedCrlList decodes a SegmentedCrlList list from BER.
func UnmarshalBERSegmentedCrlList(data []byte) (SegmentedCrlList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SegmentedCrlList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SegmentedCrlList", Cause: ber.ErrExtraData}
	}
	var result SegmentedCrlList
	offset := 0
	for offset < len(content) {
		var elem CertificateList
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ActivationCodeRetrievalInfo to BER format.
func (v *ActivationCodeRetrievalInfo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ActivationCodeRetrievalInfoChoiceActivationCodeForProfileRedownload:
		if v.ActivationCodeForProfileRedownload == nil {
			return nil, fmt.Errorf("choice ActivationCodeRetrievalInfo: activationCodeForProfileRedownload is nil")
		}
		enc_0 := ber.EncodeStringTag(12, *v.ActivationCodeForProfileRedownload)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_0)
		return enc_0, nil
	case ActivationCodeRetrievalInfoChoiceActivationCodeRetrievalAvailable:
		if v.ActivationCodeRetrievalAvailable == nil {
			return nil, fmt.Errorf("choice ActivationCodeRetrievalInfo: activationCodeRetrievalAvailable is nil")
		}
		enc_1 := ber.EncodeBoolean(*v.ActivationCodeRetrievalAvailable)
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_1)
		return enc_1, nil
	case ActivationCodeRetrievalInfoChoiceRetryDelay:
		if v.RetryDelay == nil {
			return nil, fmt.Errorf("choice ActivationCodeRetrievalInfo: retryDelay is nil")
		}
		enc_2 := ber.EncodeBigInt(v.RetryDelay)
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ActivationCodeRetrievalInfo", v.Choice)
	}
}

// MarshalDER encodes ActivationCodeRetrievalInfo to DER format.
func (v *ActivationCodeRetrievalInfo) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ActivationCodeRetrievalInfo from BER/DER format.
func (v *ActivationCodeRetrievalInfo) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ActivationCodeRetrievalInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ActivationCodeRetrievalInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ActivationCodeRetrievalInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivationCodeRetrievalInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ActivationCodeRetrievalInfoChoiceActivationCodeForProfileRedownload
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding activationCodeForProfileRedownload: %w", tlvErr)
		}
		decVal := ber.DecodeStringValue(rawVal)
		v.ActivationCodeForProfileRedownload = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ActivationCodeRetrievalInfoChoiceActivationCodeRetrievalAvailable
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding activationCodeRetrievalAvailable: %w", tlvErr)
		}
		decVal, boolErr := ber.DecodeBooleanValue(rawVal)
		if boolErr != nil {
			return fmt.Errorf("decoding activationCodeRetrievalAvailable: %w", boolErr)
		}
		v.ActivationCodeRetrievalAvailable = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ActivationCodeRetrievalInfoChoiceRetryDelay
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding retryDelay: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding retryDelay: %w", intErr)
		}
		v.RetryDelay = decVal
	} else {
		return fmt.Errorf("unknown tag %s for ActivationCodeRetrievalInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes UpdateMetadataRequest to BER format.
func (v *UpdateMetadataRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ServiceProviderName != nil {
		enc_serviceprovidername := ber.EncodeStringTag(12, *v.ServiceProviderName)
		enc_serviceprovidername = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_serviceprovidername)
		children = append(children, enc_serviceprovidername...)
	}
	if v.ProfileName != nil {
		enc_profilename := ber.EncodeStringTag(12, *v.ProfileName)
		enc_profilename = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_profilename)
		children = append(children, enc_profilename...)
	}
	if v.IconType != nil {
		enc_icontype := ber.EncodeBigInt((*v.IconType).BigInt())
		enc_icontype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_icontype)
		children = append(children, enc_icontype...)
	}
	if v.Icon != nil {
		enc_icon := ber.EncodeOctetString(v.Icon)
		enc_icon = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_icon)
		children = append(children, enc_icon...)
	}
	if v.ProfilePolicyRules != nil {
		enc_profilepolicyrules := ber.EncodeBitString(v.ProfilePolicyRules.Bytes, (8-(v.ProfilePolicyRules.BitLength%8))%8)
		enc_profilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_profilepolicyrules)
		children = append(children, enc_profilepolicyrules...)
	}
	if v.ServiceSpecificDataStoredInEuicc != nil {
		enc_servicespecificdatastoredineuicc, err := MarshalBERVendorSpecificExtension(v.ServiceSpecificDataStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatastoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatastoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 34}, seqContent_)
		} else {
			enc_servicespecificdatastoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 34, true, enc_servicespecificdatastoredineuicc)
		}
		children = append(children, enc_servicespecificdatastoredineuicc...)
	}
	if v.Reserved103 != nil {
		var enc_reserved103 []byte
		if v.Reserved103Raw_ != 0 {
			enc_reserved103 = ber.EncodeBooleanRaw(v.Reserved103Raw_)
		} else {
			enc_reserved103 = ber.EncodeBoolean(*v.Reserved103)
		}
		enc_reserved103 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 103, false, enc_reserved103)
		children = append(children, enc_reserved103...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 42, Constructed: true}, children), nil
}

// MarshalDER encodes UpdateMetadataRequest to DER format.
func (v *UpdateMetadataRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ServiceSpecificDataStoredInEuiccIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes UpdateMetadataRequest from BER/DER format.
func (v *UpdateMetadataRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding UpdateMetadataRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 42 || !decodedTag.Constructed {
		return fmt.Errorf("decoding UpdateMetadataRequest: %w: expected tag [CONTEXT 42], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UpdateMetadataRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode serviceProviderName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_serviceprovidername, rawVal_serviceprovidername, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceProviderName: %w", err)
				}
				decVal_serviceprovidername := ber.DecodeStringValue(rawVal_serviceprovidername)
				v.ServiceProviderName = &decVal_serviceprovidername
				offset += n_serviceprovidername
			}
		}
	}
	// Decode profileName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_profilename, rawVal_profilename, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileName: %w", err)
				}
				decVal_profilename := ber.DecodeStringValue(rawVal_profilename)
				v.ProfileName = &decVal_profilename
				offset += n_profilename
			}
		}
	}
	// Decode iconType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_icontype, rawVal_icontype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iconType: %w", err)
				}
				decVal_icontype, intErr := ber.DecodeBigIntValue(rawVal_icontype)
				if intErr != nil {
					return fmt.Errorf("decoding iconType: %w", intErr)
				}
				var named_icontype IconType
				if namedErr := named_icontype.UnmarshalText([]byte(decVal_icontype.String())); namedErr != nil {
					return fmt.Errorf("decoding iconType: %w", namedErr)
				}
				v.IconType = &named_icontype
				offset += n_icontype
			}
		}
	}
	// Decode icon
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_icon, rawVal_icon, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding icon: %w", err)
				}
				tmp_icon := rawVal_icon
				v.Icon = tmp_icon
				offset += n_icon
			}
		}
	}
	// Decode profilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_profilepolicyrules, rawVal_profilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", err)
				}
				bsBytes_profilepolicyrules, bsUnused_profilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_profilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", bsErr)
				}
				tmp_profilepolicyrules := runtime.BitString{Bytes: bsBytes_profilepolicyrules, BitLength: len(bsBytes_profilepolicyrules)*8 - bsUnused_profilepolicyrules}
				v.ProfilePolicyRules = &tmp_profilepolicyrules
				offset += n_profilepolicyrules
			}
		}
	}
	// Decode serviceSpecificDataStoredInEuicc
	v.ServiceSpecificDataStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 34 {
				_, n_servicespecificdatastoredineuicc, rawVal_servicespecificdatastoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatastoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatastoredineuicc)
				dec_servicespecificdatastoredineuicc, unmErr := UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatastoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataStoredInEuicc = dec_servicespecificdatastoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatastoredineuicc
			}
		}
	}
	// Decode reserved103
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 103 {
				_, n_reserved103, rawVal_reserved103, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reserved103: %w", err)
				}
				decVal_reserved103, boolErr := ber.DecodeBooleanValue(rawVal_reserved103)
				if boolErr != nil {
					return fmt.Errorf("decoding reserved103: %w", boolErr)
				}
				if len(rawVal_reserved103) == 1 {
					v.Reserved103Raw_ = rawVal_reserved103[0]
				}
				v.Reserved103 = &decVal_reserved103
				offset += n_reserved103
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UpdateMetadataRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InitialiseSecureChannelRequest to BER format.
func (v *InitialiseSecureChannelRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_remoteopid := ber.EncodeBigInt((v.RemoteOpId).BigInt())
	enc_remoteopid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_remoteopid)
	children = append(children, enc_remoteopid...)
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_controlreftemplate, err := v.ControlRefTemplate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding controlRefTemplate: %w", err)
	}
	enc_controlreftemplate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_controlreftemplate)
	children = append(children, enc_controlreftemplate...)
	enc_smdpotpk := ber.EncodeOctetString(v.SmdpOtpk)
	enc_smdpotpk = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 73, false, enc_smdpotpk)
	children = append(children, enc_smdpotpk...)
	enc_smdpsign := ber.EncodeOctetString(v.SmdpSign)
	enc_smdpsign = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_smdpsign)
	children = append(children, enc_smdpsign...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 35, Constructed: true}, children), nil
}

// MarshalDER encodes InitialiseSecureChannelRequest to DER format.
func (v *InitialiseSecureChannelRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes InitialiseSecureChannelRequest from BER/DER format.
func (v *InitialiseSecureChannelRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding InitialiseSecureChannelRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 35 || !decodedTag.Constructed {
		return fmt.Errorf("decoding InitialiseSecureChannelRequest: %w: expected tag [CONTEXT 35], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InitialiseSecureChannelRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode remoteOpId
	if offset >= len(content) {
		return fmt.Errorf("missing required field remoteOpId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for remoteOpId, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_remoteopid, rawVal_remoteopid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding remoteOpId: %w", err)
	}
	decVal_remoteopid, intErr := ber.DecodeBigIntValue(rawVal_remoteopid)
	if intErr != nil {
		return fmt.Errorf("decoding remoteOpId: %w", intErr)
	}
	var named_remoteopid RemoteOpId
	if namedErr := named_remoteopid.UnmarshalText([]byte(decVal_remoteopid.String())); namedErr != nil {
		return fmt.Errorf("decoding remoteOpId: %w", namedErr)
	}
	v.RemoteOpId = named_remoteopid
	offset += n_remoteopid
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode controlRefTemplate
	if offset >= len(content) {
		return fmt.Errorf("missing required field controlRefTemplate")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 6 {
			return fmt.Errorf("expected tag [%s %d] for controlRefTemplate, got %s", "CONTEXT", 6, reqTag_)
		}
	}
	_, n_controlreftemplate, rawVal_controlreftemplate, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding controlRefTemplate: %w", err)
	}
	reconstructed_controlreftemplate := ber.EncodeSequence(rawVal_controlreftemplate)
	if unmErr := v.ControlRefTemplate.UnmarshalBER(reconstructed_controlreftemplate); unmErr != nil {
		return fmt.Errorf("decoding controlRefTemplate: %w", unmErr)
	}
	offset += n_controlreftemplate
	// Decode smdpOtpk
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpOtpk")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 73 {
			return fmt.Errorf("expected tag [%s %d] for smdpOtpk, got %s", "APPLICATION", 73, reqTag_)
		}
	}
	_, n_smdpotpk, rawVal_smdpotpk, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpOtpk: %w", err)
	}
	v.SmdpOtpk = rawVal_smdpotpk
	offset += n_smdpotpk
	// Decode smdpSign
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpSign")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for smdpSign, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_smdpsign, rawVal_smdpsign, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpSign: %w", err)
	}
	v.SmdpSign = rawVal_smdpsign
	offset += n_smdpsign
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InitialiseSecureChannelRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ControlRefTemplate to BER format.
func (v *ControlRefTemplate) MarshalBER() ([]byte, error) {
	var children []byte
	enc_keytype := ber.EncodeOctetString([]byte(v.KeyType))
	enc_keytype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_keytype)
	children = append(children, enc_keytype...)
	enc_keylen := ber.EncodeOctetString([]byte(v.KeyLen))
	enc_keylen = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_keylen)
	children = append(children, enc_keylen...)
	enc_hostid := ber.EncodeOctetString([]byte(v.HostId))
	enc_hostid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_hostid)
	children = append(children, enc_hostid...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ControlRefTemplate to DER format.
func (v *ControlRefTemplate) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ControlRefTemplate from BER/DER format.
func (v *ControlRefTemplate) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ControlRefTemplate SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ControlRefTemplate", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode keyType
	if offset >= len(content) {
		return fmt.Errorf("missing required field keyType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for keyType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_keytype, rawVal_keytype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding keyType: %w", err)
	}
	v.KeyType = Octet1(rawVal_keytype)
	offset += n_keytype
	// Decode keyLen
	if offset >= len(content) {
		return fmt.Errorf("missing required field keyLen")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for keyLen, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_keylen, rawVal_keylen, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding keyLen: %w", err)
	}
	v.KeyLen = Octet1(rawVal_keylen)
	offset += n_keylen
	// Decode hostId
	if offset >= len(content) {
		return fmt.Errorf("missing required field hostId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for hostId, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_hostid, rawVal_hostid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding hostId: %w", err)
	}
	v.HostId = OctetTo16(rawVal_hostid)
	offset += n_hostid
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ControlRefTemplate", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ConfigureISDPRequest to BER format.
func (v *ConfigureISDPRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.DpProprietaryData != nil {
		enc_dpproprietarydata, err := v.DpProprietaryData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dpProprietaryData: %w", err)
		}
		enc_dpproprietarydata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, true, enc_dpproprietarydata)
		children = append(children, enc_dpproprietarydata...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 36, Constructed: true}, children), nil
}

// MarshalDER encodes ConfigureISDPRequest to DER format.
func (v *ConfigureISDPRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ConfigureISDPRequest from BER/DER format.
func (v *ConfigureISDPRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ConfigureISDPRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 36 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ConfigureISDPRequest: %w: expected tag [CONTEXT 36], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ConfigureISDPRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dpProprietaryData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				_, n_dpproprietarydata, rawVal_dpproprietarydata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dpProprietaryData: %w", err)
				}
				reconstructed_dpproprietarydata := ber.EncodeSequence(rawVal_dpproprietarydata)
				var dec_dpproprietarydata DpProprietaryData
				if unmErr := dec_dpproprietarydata.UnmarshalBER(reconstructed_dpproprietarydata); unmErr != nil {
					return fmt.Errorf("decoding dpProprietaryData: %w", unmErr)
				}
				v.DpProprietaryData = &dec_dpproprietarydata
				offset += n_dpproprietarydata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ConfigureISDPRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DpProprietaryData to BER format.
func (v *DpProprietaryData) MarshalBER() ([]byte, error) {
	var children []byte
	enc_dpoid := ber.EncodeObjectIdentifier([]uint64(v.DpOid))
	enc_dpoid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_dpoid)
	children = append(children, enc_dpoid...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DpProprietaryData to DER format.
func (v *DpProprietaryData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DpProprietaryData from BER/DER format.
func (v *DpProprietaryData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DpProprietaryData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DpProprietaryData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dpOid
	if offset >= len(content) {
		return fmt.Errorf("missing required field dpOid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for dpOid, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_dpoid, rawVal_dpoid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dpOid: %w", err)
	}
	decVal_dpoid, oidErr := ber.DecodeOIDValue(rawVal_dpoid)
	if oidErr != nil {
		return fmt.Errorf("decoding dpOid: %w", oidErr)
	}
	v.DpOid = runtime.ObjectIdentifier(decVal_dpoid)
	offset += n_dpoid
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DpProprietaryData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes StoreMetadataRequest to BER format.
func (v *StoreMetadataRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iccid := ber.EncodeOctetString([]byte(v.Iccid))
	enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
	children = append(children, enc_iccid...)
	enc_serviceprovidername := ber.EncodeStringTag(12, v.ServiceProviderName)
	enc_serviceprovidername = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_serviceprovidername)
	children = append(children, enc_serviceprovidername...)
	enc_profilename := ber.EncodeStringTag(12, v.ProfileName)
	enc_profilename = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_profilename)
	children = append(children, enc_profilename...)
	if v.IconType != nil {
		enc_icontype := ber.EncodeBigInt((*v.IconType).BigInt())
		enc_icontype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_icontype)
		children = append(children, enc_icontype...)
	}
	if v.Icon != nil {
		enc_icon := ber.EncodeOctetString(v.Icon)
		enc_icon = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_icon)
		children = append(children, enc_icon...)
	}
	if v.ProfileClass != nil {
		enc_profileclass := ber.EncodeBigInt((*v.ProfileClass).BigInt())
		enc_profileclass = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_profileclass)
		children = append(children, enc_profileclass...)
	}
	if v.NotificationConfigurationInfo != nil {
		enc_notificationconfigurationinfo, err := MarshalBERStoreMetadataRequestNotificationConfigurationInfo(v.NotificationConfigurationInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationConfigurationInfo: %w", err)
		}
		if v.NotificationConfigurationInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_notificationconfigurationinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_notificationconfigurationinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 22}, seqContent_)
		} else {
			enc_notificationconfigurationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, true, enc_notificationconfigurationinfo)
		}
		children = append(children, enc_notificationconfigurationinfo...)
	}
	if v.ProfileOwner != nil {
		enc_profileowner, err := v.ProfileOwner.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileOwner: %w", err)
		}
		enc_profileowner = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, true, enc_profileowner)
		children = append(children, enc_profileowner...)
	}
	if v.ProfilePolicyRules != nil {
		enc_profilepolicyrules := ber.EncodeBitString(v.ProfilePolicyRules.Bytes, (8-(v.ProfilePolicyRules.BitLength%8))%8)
		enc_profilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_profilepolicyrules)
		children = append(children, enc_profilepolicyrules...)
	}
	if v.ServiceSpecificDataStoredInEuicc != nil {
		enc_servicespecificdatastoredineuicc, err := MarshalBERVendorSpecificExtension(v.ServiceSpecificDataStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatastoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatastoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 34}, seqContent_)
		} else {
			enc_servicespecificdatastoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 34, true, enc_servicespecificdatastoredineuicc)
		}
		children = append(children, enc_servicespecificdatastoredineuicc...)
	}
	if v.ServiceSpecificDataNotStoredInEuicc != nil {
		enc_servicespecificdatanotstoredineuicc, err := MarshalBERVendorSpecificExtension(v.ServiceSpecificDataNotStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataNotStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataNotStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatanotstoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatanotstoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 35}, seqContent_)
		} else {
			enc_servicespecificdatanotstoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 35, true, enc_servicespecificdatanotstoredineuicc)
		}
		children = append(children, enc_servicespecificdatanotstoredineuicc...)
	}
	if v.EcallIndication != nil {
		var enc_ecallindication []byte
		if v.EcallIndicationRaw_ != 0 {
			enc_ecallindication = ber.EncodeBooleanRaw(v.EcallIndicationRaw_)
		} else {
			enc_ecallindication = ber.EncodeBoolean(*v.EcallIndication)
		}
		enc_ecallindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 123, false, enc_ecallindication)
		children = append(children, enc_ecallindication...)
	}
	if v.FallbackAllowed != nil {
		var enc_fallbackallowed []byte
		if v.FallbackAllowedRaw_ != 0 {
			enc_fallbackallowed = ber.EncodeBooleanRaw(v.FallbackAllowedRaw_)
		} else {
			enc_fallbackallowed = ber.EncodeBoolean(*v.FallbackAllowed)
		}
		enc_fallbackallowed = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 103, false, enc_fallbackallowed)
		children = append(children, enc_fallbackallowed...)
	}
	if v.IotSpecificMetadata != nil {
		enc_iotspecificmetadata, err := v.IotSpecificMetadata.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding iotSpecificMetadata: %w", err)
		}
		enc_iotspecificmetadata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 100, true, enc_iotspecificmetadata)
		children = append(children, enc_iotspecificmetadata...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 37, Constructed: true}, children), nil
}

// MarshalDER encodes StoreMetadataRequest to DER format.
func (v *StoreMetadataRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NotificationConfigurationInfoIndef_ = false
	derValue.ServiceSpecificDataStoredInEuiccIndef_ = false
	derValue.ServiceSpecificDataNotStoredInEuiccIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes StoreMetadataRequest from BER/DER format.
func (v *StoreMetadataRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding StoreMetadataRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 37 || !decodedTag.Constructed {
		return fmt.Errorf("decoding StoreMetadataRequest: %w: expected tag [CONTEXT 37], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "StoreMetadataRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset >= len(content) {
		return fmt.Errorf("missing required field iccid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for iccid, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iccid: %w", err)
	}
	v.Iccid = Iccid(rawVal_iccid)
	offset += n_iccid
	// Decode serviceProviderName
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceProviderName")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 17 {
			return fmt.Errorf("expected tag [%s %d] for serviceProviderName, got %s", "CONTEXT", 17, reqTag_)
		}
	}
	_, n_serviceprovidername, rawVal_serviceprovidername, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceProviderName: %w", err)
	}
	decVal_serviceprovidername := ber.DecodeStringValue(rawVal_serviceprovidername)
	v.ServiceProviderName = decVal_serviceprovidername
	offset += n_serviceprovidername
	// Decode profileName
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileName")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 18 {
			return fmt.Errorf("expected tag [%s %d] for profileName, got %s", "CONTEXT", 18, reqTag_)
		}
	}
	_, n_profilename, rawVal_profilename, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileName: %w", err)
	}
	decVal_profilename := ber.DecodeStringValue(rawVal_profilename)
	v.ProfileName = decVal_profilename
	offset += n_profilename
	// Decode iconType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_icontype, rawVal_icontype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iconType: %w", err)
				}
				decVal_icontype, intErr := ber.DecodeBigIntValue(rawVal_icontype)
				if intErr != nil {
					return fmt.Errorf("decoding iconType: %w", intErr)
				}
				var named_icontype IconType
				if namedErr := named_icontype.UnmarshalText([]byte(decVal_icontype.String())); namedErr != nil {
					return fmt.Errorf("decoding iconType: %w", namedErr)
				}
				v.IconType = &named_icontype
				offset += n_icontype
			}
		}
	}
	// Decode icon
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_icon, rawVal_icon, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding icon: %w", err)
				}
				tmp_icon := rawVal_icon
				v.Icon = tmp_icon
				offset += n_icon
			}
		}
	}
	// Decode profileClass
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_profileclass, rawVal_profileclass, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileClass: %w", err)
				}
				decVal_profileclass, intErr := ber.DecodeBigIntValue(rawVal_profileclass)
				if intErr != nil {
					return fmt.Errorf("decoding profileClass: %w", intErr)
				}
				var named_profileclass ProfileClass
				if namedErr := named_profileclass.UnmarshalText([]byte(decVal_profileclass.String())); namedErr != nil {
					return fmt.Errorf("decoding profileClass: %w", namedErr)
				}
				v.ProfileClass = &named_profileclass
				offset += n_profileclass
			}
		}
	}
	// Decode notificationConfigurationInfo
	v.NotificationConfigurationInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				_, n_notificationconfigurationinfo, rawVal_notificationconfigurationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", err)
				}
				reconstructed_notificationconfigurationinfo := ber.EncodeSequence(rawVal_notificationconfigurationinfo)
				dec_notificationconfigurationinfo, unmErr := UnmarshalBERStoreMetadataRequestNotificationConfigurationInfo(reconstructed_notificationconfigurationinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", unmErr)
				}
				v.NotificationConfigurationInfo = dec_notificationconfigurationinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.NotificationConfigurationInfoIndef_ = true
					}
				}
				offset += n_notificationconfigurationinfo
			}
		}
	}
	// Decode profileOwner
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				_, n_profileowner, rawVal_profileowner, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileOwner: %w", err)
				}
				reconstructed_profileowner := ber.EncodeSequence(rawVal_profileowner)
				var dec_profileowner OperatorId
				if unmErr := dec_profileowner.UnmarshalBER(reconstructed_profileowner); unmErr != nil {
					return fmt.Errorf("decoding profileOwner: %w", unmErr)
				}
				v.ProfileOwner = &dec_profileowner
				offset += n_profileowner
			}
		}
	}
	// Decode profilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_profilepolicyrules, rawVal_profilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", err)
				}
				bsBytes_profilepolicyrules, bsUnused_profilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_profilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", bsErr)
				}
				tmp_profilepolicyrules := runtime.BitString{Bytes: bsBytes_profilepolicyrules, BitLength: len(bsBytes_profilepolicyrules)*8 - bsUnused_profilepolicyrules}
				v.ProfilePolicyRules = &tmp_profilepolicyrules
				offset += n_profilepolicyrules
			}
		}
	}
	// Decode serviceSpecificDataStoredInEuicc
	v.ServiceSpecificDataStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 34 {
				_, n_servicespecificdatastoredineuicc, rawVal_servicespecificdatastoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatastoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatastoredineuicc)
				dec_servicespecificdatastoredineuicc, unmErr := UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatastoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataStoredInEuicc = dec_servicespecificdatastoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatastoredineuicc
			}
		}
	}
	// Decode serviceSpecificDataNotStoredInEuicc
	v.ServiceSpecificDataNotStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 35 {
				_, n_servicespecificdatanotstoredineuicc, rawVal_servicespecificdatanotstoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataNotStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatanotstoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatanotstoredineuicc)
				dec_servicespecificdatanotstoredineuicc, unmErr := UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatanotstoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataNotStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataNotStoredInEuicc = dec_servicespecificdatanotstoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataNotStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatanotstoredineuicc
			}
		}
	}
	// Decode ecallIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 123 {
				_, n_ecallindication, rawVal_ecallindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ecallIndication: %w", err)
				}
				decVal_ecallindication, boolErr := ber.DecodeBooleanValue(rawVal_ecallindication)
				if boolErr != nil {
					return fmt.Errorf("decoding ecallIndication: %w", boolErr)
				}
				if len(rawVal_ecallindication) == 1 {
					v.EcallIndicationRaw_ = rawVal_ecallindication[0]
				}
				v.EcallIndication = &decVal_ecallindication
				offset += n_ecallindication
			}
		}
	}
	// Decode fallbackAllowed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 103 {
				_, n_fallbackallowed, rawVal_fallbackallowed, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", err)
				}
				decVal_fallbackallowed, boolErr := ber.DecodeBooleanValue(rawVal_fallbackallowed)
				if boolErr != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", boolErr)
				}
				if len(rawVal_fallbackallowed) == 1 {
					v.FallbackAllowedRaw_ = rawVal_fallbackallowed[0]
				}
				v.FallbackAllowed = &decVal_fallbackallowed
				offset += n_fallbackallowed
			}
		}
	}
	// Decode iotSpecificMetadata
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 100 {
				_, n_iotspecificmetadata, rawVal_iotspecificmetadata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iotSpecificMetadata: %w", err)
				}
				reconstructed_iotspecificmetadata := ber.EncodeSequence(rawVal_iotspecificmetadata)
				var dec_iotspecificmetadata StoreMetadataRequestIotSpecificMetadata
				if unmErr := dec_iotspecificmetadata.UnmarshalBER(reconstructed_iotspecificmetadata); unmErr != nil {
					return fmt.Errorf("decoding iotSpecificMetadata: %w", unmErr)
				}
				v.IotSpecificMetadata = &dec_iotspecificmetadata
				offset += n_iotspecificmetadata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "StoreMetadataRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NotificationConfigurationInformation to BER format.
func (v *NotificationConfigurationInformation) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profilemanagementoperation := ber.EncodeBitString(v.ProfileManagementOperation.Bytes, (8-(v.ProfileManagementOperation.BitLength%8))%8)
	enc_profilemanagementoperation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_profilemanagementoperation)
	children = append(children, enc_profilemanagementoperation...)
	enc_notificationaddress := ber.EncodeStringTag(12, v.NotificationAddress)
	enc_notificationaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_notificationaddress)
	children = append(children, enc_notificationaddress...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes NotificationConfigurationInformation to DER format.
func (v *NotificationConfigurationInformation) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NotificationConfigurationInformation from BER/DER format.
func (v *NotificationConfigurationInformation) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NotificationConfigurationInformation SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NotificationConfigurationInformation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileManagementOperation
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileManagementOperation")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for profileManagementOperation, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_profilemanagementoperation, rawVal_profilemanagementoperation, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileManagementOperation: %w", err)
	}
	bsBytes_profilemanagementoperation, bsUnused_profilemanagementoperation, bsErr := ber.DecodeBitStringValue(rawVal_profilemanagementoperation)
	if bsErr != nil {
		return fmt.Errorf("decoding profileManagementOperation: %w", bsErr)
	}
	v.ProfileManagementOperation = runtime.BitString{Bytes: bsBytes_profilemanagementoperation, BitLength: len(bsBytes_profilemanagementoperation)*8 - bsUnused_profilemanagementoperation}
	offset += n_profilemanagementoperation
	// Decode notificationAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field notificationAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for notificationAddress, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_notificationaddress, rawVal_notificationaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding notificationAddress: %w", err)
	}
	decVal_notificationaddress := ber.DecodeStringValue(rawVal_notificationaddress)
	v.NotificationAddress = decVal_notificationaddress
	offset += n_notificationaddress
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NotificationConfigurationInformation", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERVendorSpecificExtension encodes a VendorSpecificExtension list to BER.
func MarshalBERVendorSpecificExtension(list VendorSpecificExtension) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERVendorSpecificExtension decodes a VendorSpecificExtension list from BER.
func UnmarshalBERVendorSpecificExtension(data []byte) (VendorSpecificExtension, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding VendorSpecificExtension: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "VendorSpecificExtension", Cause: ber.ErrExtraData}
	}
	var result VendorSpecificExtension
	offset := 0
	for offset < len(content) {
		var elem VendorSpecificExtensionElem
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ReplaceSessionKeysRequest to BER format.
func (v *ReplaceSessionKeysRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_initialmacchainingvalue := ber.EncodeOctetString(v.InitialMacChainingValue)
	enc_initialmacchainingvalue = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_initialmacchainingvalue)
	children = append(children, enc_initialmacchainingvalue...)
	enc_ppkenc := ber.EncodeOctetString(v.PpkEnc)
	enc_ppkenc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ppkenc)
	children = append(children, enc_ppkenc...)
	enc_ppkcmac := ber.EncodeOctetString(v.PpkCmac)
	enc_ppkcmac = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_ppkcmac)
	children = append(children, enc_ppkcmac...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 38, Constructed: true}, children), nil
}

// MarshalDER encodes ReplaceSessionKeysRequest to DER format.
func (v *ReplaceSessionKeysRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ReplaceSessionKeysRequest from BER/DER format.
func (v *ReplaceSessionKeysRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReplaceSessionKeysRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 38 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ReplaceSessionKeysRequest: %w: expected tag [CONTEXT 38], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReplaceSessionKeysRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode initialMacChainingValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field initialMacChainingValue")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for initialMacChainingValue, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_initialmacchainingvalue, rawVal_initialmacchainingvalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding initialMacChainingValue: %w", err)
	}
	v.InitialMacChainingValue = rawVal_initialmacchainingvalue
	offset += n_initialmacchainingvalue
	// Decode ppkEnc
	if offset >= len(content) {
		return fmt.Errorf("missing required field ppkEnc")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for ppkEnc, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_ppkenc, rawVal_ppkenc, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ppkEnc: %w", err)
	}
	v.PpkEnc = rawVal_ppkenc
	offset += n_ppkenc
	// Decode ppkCmac
	if offset >= len(content) {
		return fmt.Errorf("missing required field ppkCmac")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for ppkCmac, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_ppkcmac, rawVal_ppkcmac, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ppkCmac: %w", err)
	}
	v.PpkCmac = rawVal_ppkcmac
	offset += n_ppkcmac
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReplaceSessionKeysRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ISDRProprietaryApplicationTemplate to BER format.
func (v *ISDRProprietaryApplicationTemplate) MarshalBER() ([]byte, error) {
	var children []byte
	enc_svn := ber.EncodeOctetString([]byte(v.Svn))
	enc_svn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_svn)
	children = append(children, enc_svn...)
	if v.LpaeSupport != nil {
		enc_lpaesupport := ber.EncodeBitString(v.LpaeSupport.Bytes, (8-(v.LpaeSupport.BitLength%8))%8)
		children = append(children, enc_lpaesupport...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes ISDRProprietaryApplicationTemplate to DER format.
func (v *ISDRProprietaryApplicationTemplate) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ISDRProprietaryApplicationTemplate from BER/DER format.
func (v *ISDRProprietaryApplicationTemplate) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ISDRProprietaryApplicationTemplate: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ISDRProprietaryApplicationTemplate: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ISDRProprietaryApplicationTemplate", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode svn
	if offset >= len(content) {
		return fmt.Errorf("missing required field svn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for svn, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_svn, rawVal_svn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding svn: %w", err)
	}
	v.Svn = VersionType(rawVal_svn)
	offset += n_svn
	// Decode lpaeSupport
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 3 {
				bsBytes_lpaesupport, bsUnused_lpaesupport, n, err := ber.DecodeBitString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lpaeSupport: %w", err)
				}
				tmp_lpaesupport := runtime.BitString{Bytes: bsBytes_lpaesupport, BitLength: len(bsBytes_lpaesupport)*8 - bsUnused_lpaesupport}
				v.LpaeSupport = &tmp_lpaesupport
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ISDRProprietaryApplicationTemplate", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LpaeActivationRequest to BER format.
func (v *LpaeActivationRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_lpaeoption := ber.EncodeBitString(v.LpaeOption.Bytes, (8-(v.LpaeOption.BitLength%8))%8)
	enc_lpaeoption = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_lpaeoption)
	children = append(children, enc_lpaeoption...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 66, Constructed: true}, children), nil
}

// MarshalDER encodes LpaeActivationRequest to DER format.
func (v *LpaeActivationRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LpaeActivationRequest from BER/DER format.
func (v *LpaeActivationRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding LpaeActivationRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 66 || !decodedTag.Constructed {
		return fmt.Errorf("decoding LpaeActivationRequest: %w: expected tag [CONTEXT 66], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LpaeActivationRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode lpaeOption
	if offset >= len(content) {
		return fmt.Errorf("missing required field lpaeOption")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for lpaeOption, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_lpaeoption, rawVal_lpaeoption, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lpaeOption: %w", err)
	}
	bsBytes_lpaeoption, bsUnused_lpaeoption, bsErr := ber.DecodeBitStringValue(rawVal_lpaeoption)
	if bsErr != nil {
		return fmt.Errorf("decoding lpaeOption: %w", bsErr)
	}
	v.LpaeOption = runtime.BitString{Bytes: bsBytes_lpaeoption, BitLength: len(bsBytes_lpaeoption)*8 - bsUnused_lpaeoption}
	offset += n_lpaeoption
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LpaeActivationRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LpaeActivationResponse to BER format.
func (v *LpaeActivationResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_lpaeactivationresult := ber.EncodeBigInt((v.LpaeActivationResult).BigInt())
	enc_lpaeactivationresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_lpaeactivationresult)
	children = append(children, enc_lpaeactivationresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 66, Constructed: true}, children), nil
}

// MarshalDER encodes LpaeActivationResponse to DER format.
func (v *LpaeActivationResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LpaeActivationResponse from BER/DER format.
func (v *LpaeActivationResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding LpaeActivationResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 66 || !decodedTag.Constructed {
		return fmt.Errorf("decoding LpaeActivationResponse: %w: expected tag [CONTEXT 66], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LpaeActivationResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode lpaeActivationResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field lpaeActivationResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for lpaeActivationResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_lpaeactivationresult, rawVal_lpaeactivationresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lpaeActivationResult: %w", err)
	}
	decVal_lpaeactivationresult, intErr := ber.DecodeBigIntValue(rawVal_lpaeactivationresult)
	if intErr != nil {
		return fmt.Errorf("decoding lpaeActivationResult: %w", intErr)
	}
	var named_lpaeactivationresult LpaeActivationResponseLpaeActivationResultValue
	if namedErr := named_lpaeactivationresult.UnmarshalText([]byte(decVal_lpaeactivationresult.String())); namedErr != nil {
		return fmt.Errorf("decoding lpaeActivationResult: %w", namedErr)
	}
	v.LpaeActivationResult = named_lpaeactivationresult
	offset += n_lpaeactivationresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LpaeActivationResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EuiccConfiguredAddressesRequest to BER format.
func (v *EuiccConfiguredAddressesRequest) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 60, Constructed: true}, children), nil
}

// MarshalDER encodes EuiccConfiguredAddressesRequest to DER format.
func (v *EuiccConfiguredAddressesRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccConfiguredAddressesRequest from BER/DER format.
func (v *EuiccConfiguredAddressesRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccConfiguredAddressesRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 60 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccConfiguredAddressesRequest: %w: expected tag [CONTEXT 60], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccConfiguredAddressesRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EuiccConfiguredAddressesRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EuiccConfiguredAddressesResponse to BER format.
func (v *EuiccConfiguredAddressesResponse) MarshalBER() ([]byte, error) {
	var children []byte
	if v.DefaultDpAddress != nil {
		enc_defaultdpaddress := ber.EncodeStringTag(12, *v.DefaultDpAddress)
		enc_defaultdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_defaultdpaddress)
		children = append(children, enc_defaultdpaddress...)
	}
	enc_rootdsaddress := ber.EncodeStringTag(12, v.RootDsAddress)
	enc_rootdsaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_rootdsaddress)
	children = append(children, enc_rootdsaddress...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 60, Constructed: true}, children), nil
}

// MarshalDER encodes EuiccConfiguredAddressesResponse to DER format.
func (v *EuiccConfiguredAddressesResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccConfiguredAddressesResponse from BER/DER format.
func (v *EuiccConfiguredAddressesResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccConfiguredAddressesResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 60 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccConfiguredAddressesResponse: %w: expected tag [CONTEXT 60], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccConfiguredAddressesResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode defaultDpAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_defaultdpaddress, rawVal_defaultdpaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultDpAddress: %w", err)
				}
				decVal_defaultdpaddress := ber.DecodeStringValue(rawVal_defaultdpaddress)
				v.DefaultDpAddress = &decVal_defaultdpaddress
				offset += n_defaultdpaddress
			}
		}
	}
	// Decode rootDsAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field rootDsAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for rootDsAddress, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_rootdsaddress, rawVal_rootdsaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rootDsAddress: %w", err)
	}
	decVal_rootdsaddress := ber.DecodeStringValue(rawVal_rootdsaddress)
	v.RootDsAddress = decVal_rootdsaddress
	offset += n_rootdsaddress
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EuiccConfiguredAddressesResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SetDefaultDpAddressRequest to BER format.
func (v *SetDefaultDpAddressRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_defaultdpaddress := ber.EncodeStringTag(12, v.DefaultDpAddress)
	enc_defaultdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_defaultdpaddress)
	children = append(children, enc_defaultdpaddress...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 63, Constructed: true}, children), nil
}

// MarshalDER encodes SetDefaultDpAddressRequest to DER format.
func (v *SetDefaultDpAddressRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SetDefaultDpAddressRequest from BER/DER format.
func (v *SetDefaultDpAddressRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetDefaultDpAddressRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 63 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SetDefaultDpAddressRequest: %w: expected tag [CONTEXT 63], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetDefaultDpAddressRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode defaultDpAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultDpAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for defaultDpAddress, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_defaultdpaddress, rawVal_defaultdpaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding defaultDpAddress: %w", err)
	}
	decVal_defaultdpaddress := ber.DecodeStringValue(rawVal_defaultdpaddress)
	v.DefaultDpAddress = decVal_defaultdpaddress
	offset += n_defaultdpaddress
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SetDefaultDpAddressRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SetDefaultDpAddressResponse to BER format.
func (v *SetDefaultDpAddressResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_setdefaultdpaddressresult := ber.EncodeBigInt((v.SetDefaultDpAddressResult).BigInt())
	enc_setdefaultdpaddressresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_setdefaultdpaddressresult)
	children = append(children, enc_setdefaultdpaddressresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 63, Constructed: true}, children), nil
}

// MarshalDER encodes SetDefaultDpAddressResponse to DER format.
func (v *SetDefaultDpAddressResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SetDefaultDpAddressResponse from BER/DER format.
func (v *SetDefaultDpAddressResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetDefaultDpAddressResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 63 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SetDefaultDpAddressResponse: %w: expected tag [CONTEXT 63], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetDefaultDpAddressResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode setDefaultDpAddressResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field setDefaultDpAddressResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for setDefaultDpAddressResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_setdefaultdpaddressresult, rawVal_setdefaultdpaddressresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding setDefaultDpAddressResult: %w", err)
	}
	decVal_setdefaultdpaddressresult, intErr := ber.DecodeBigIntValue(rawVal_setdefaultdpaddressresult)
	if intErr != nil {
		return fmt.Errorf("decoding setDefaultDpAddressResult: %w", intErr)
	}
	var named_setdefaultdpaddressresult SetDefaultDpAddressResponseSetDefaultDpAddressResultValue
	if namedErr := named_setdefaultdpaddressresult.UnmarshalText([]byte(decVal_setdefaultdpaddressresult.String())); namedErr != nil {
		return fmt.Errorf("decoding setDefaultDpAddressResult: %w", namedErr)
	}
	v.SetDefaultDpAddressResult = named_setdefaultdpaddressresult
	offset += n_setdefaultdpaddressresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SetDefaultDpAddressResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareDownloadRequest to BER format.
func (v *PrepareDownloadRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_smdpsigned2, err := v.SmdpSigned2.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding smdpSigned2: %w", err)
	}
	children = append(children, enc_smdpsigned2...)
	enc_smdpsignature2 := ber.EncodeOctetString(v.SmdpSignature2)
	enc_smdpsignature2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_smdpsignature2)
	children = append(children, enc_smdpsignature2...)
	if v.HashCc != nil {
		enc_hashcc := ber.EncodeOctetString([]byte(*v.HashCc))
		children = append(children, enc_hashcc...)
	}
	enc_smdpcertificate, err := v.SmdpCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding smdpCertificate: %w", err)
	}
	children = append(children, enc_smdpcertificate...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 33, Constructed: true}, children), nil
}

// MarshalDER encodes PrepareDownloadRequest to DER format.
func (v *PrepareDownloadRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareDownloadRequest from BER/DER format.
func (v *PrepareDownloadRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrepareDownloadRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 33 || !decodedTag.Constructed {
		return fmt.Errorf("decoding PrepareDownloadRequest: %w: expected tag [CONTEXT 33], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareDownloadRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode smdpSigned2
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpSigned2")
	}
	// Decode nested SEQUENCE (SmdpSigned2)
	_, n_smdpsigned2, _, tlvErr_smdpsigned2 := ber.DecodeTLV(content[offset:])
	if tlvErr_smdpsigned2 != nil {
		return fmt.Errorf("decoding smdpSigned2: %w", tlvErr_smdpsigned2)
	}
	if unmErr := v.SmdpSigned2.UnmarshalBER(content[offset : offset+n_smdpsigned2]); unmErr != nil {
		return fmt.Errorf("decoding smdpSigned2: %w", unmErr)
	}
	offset += n_smdpsigned2
	// Decode smdpSignature2
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpSignature2")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for smdpSignature2, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_smdpsignature2, rawVal_smdpsignature2, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpSignature2: %w", err)
	}
	v.SmdpSignature2 = rawVal_smdpsignature2
	offset += n_smdpsignature2
	// Decode hashCc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_hashcc, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding hashCc: %w", err)
				}
				tmp_hashcc := Octet32(val_hashcc)
				v.HashCc = &tmp_hashcc
				offset += n
			}
		}
	}
	// Decode smdpCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_smdpcertificate, _, tlvErr_smdpcertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_smdpcertificate != nil {
		return fmt.Errorf("decoding smdpCertificate: %w", tlvErr_smdpcertificate)
	}
	if unmErr := v.SmdpCertificate.UnmarshalBER(content[offset : offset+n_smdpcertificate]); unmErr != nil {
		return fmt.Errorf("decoding smdpCertificate: %w", unmErr)
	}
	offset += n_smdpcertificate
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareDownloadRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SmdpSigned2 to BER format.
func (v *SmdpSigned2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	var enc_ccrequiredflag []byte
	if v.CcRequiredFlagRaw_ != 0 {
		enc_ccrequiredflag = ber.EncodeBooleanRaw(v.CcRequiredFlagRaw_)
	} else {
		enc_ccrequiredflag = ber.EncodeBoolean(v.CcRequiredFlag)
	}
	children = append(children, enc_ccrequiredflag...)
	if v.BppEuiccOtpk != nil {
		enc_bppeuiccotpk := ber.EncodeOctetString(v.BppEuiccOtpk)
		enc_bppeuiccotpk = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 73, false, enc_bppeuiccotpk)
		children = append(children, enc_bppeuiccotpk...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SmdpSigned2 to DER format.
func (v *SmdpSigned2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SmdpSigned2 from BER/DER format.
func (v *SmdpSigned2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SmdpSigned2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SmdpSigned2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode ccRequiredFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field ccRequiredFlag")
	}
	val_ccrequiredflag, raw_ccrequiredflag, n, err := ber.DecodeBoolean(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ccRequiredFlag: %w", err)
	}
	v.CcRequiredFlag = val_ccrequiredflag
	v.CcRequiredFlagRaw_ = raw_ccrequiredflag
	offset += n
	// Decode bppEuiccOtpk
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 73 {
				_, n_bppeuiccotpk, rawVal_bppeuiccotpk, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bppEuiccOtpk: %w", err)
				}
				tmp_bppeuiccotpk := rawVal_bppeuiccotpk
				v.BppEuiccOtpk = tmp_bppeuiccotpk
				offset += n_bppeuiccotpk
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SmdpSigned2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareDownloadResponse to BER format.
func (v *PrepareDownloadResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PrepareDownloadResponseChoiceDownloadResponseOk:
		if v.DownloadResponseOk == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseOk is nil")
		}
		enc_0, err := v.DownloadResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_0)
		return enc_0, nil
	case PrepareDownloadResponseChoiceDownloadResponseError:
		if v.DownloadResponseError == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseError is nil")
		}
		enc_1, err := v.DownloadResponseError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseError: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrepareDownloadResponse", v.Choice)
	}
}

// MarshalDER encodes PrepareDownloadResponse to DER format.
func (v *PrepareDownloadResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case PrepareDownloadResponseChoiceDownloadResponseOk:
		if v.DownloadResponseOk == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseOk is nil")
		}
		enc_der_0, err := v.DownloadResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_der_0)
		return enc_der_0, nil
	case PrepareDownloadResponseChoiceDownloadResponseError:
		if v.DownloadResponseError == nil {
			return nil, fmt.Errorf("choice PrepareDownloadResponse: downloadResponseError is nil")
		}
		enc_der_1, err := v.DownloadResponseError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding downloadResponseError: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 33, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareDownloadResponse from BER/DER format.
func (v *PrepareDownloadResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrepareDownloadResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrepareDownloadResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 33 || !decodedTag.Constructed {
		return fmt.Errorf("decoding PrepareDownloadResponse CHOICE: %w: expected tag [CONTEXT 33], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareDownloadResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for PrepareDownloadResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrepareDownloadResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrepareDownloadResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareDownloadResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = PrepareDownloadResponseChoiceDownloadResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding downloadResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PrepareDownloadResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding downloadResponseOk: %w", unmErr)
		}
		v.DownloadResponseOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = PrepareDownloadResponseChoiceDownloadResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding downloadResponseError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PrepareDownloadResponseError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding downloadResponseError: %w", unmErr)
		}
		v.DownloadResponseError = &dec
	} else {
		return fmt.Errorf("unknown tag %s for PrepareDownloadResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PrepareDownloadResponseOk to BER format.
func (v *PrepareDownloadResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccsigned2, err := v.EuiccSigned2.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccSigned2: %w", err)
	}
	children = append(children, enc_euiccsigned2...)
	enc_euiccsignature2 := ber.EncodeOctetString(v.EuiccSignature2)
	enc_euiccsignature2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignature2)
	children = append(children, enc_euiccsignature2...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrepareDownloadResponseOk to DER format.
func (v *PrepareDownloadResponseOk) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareDownloadResponseOk from BER/DER format.
func (v *PrepareDownloadResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrepareDownloadResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareDownloadResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccSigned2
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSigned2")
	}
	// Decode nested SEQUENCE (EUICCSigned2)
	_, n_euiccsigned2, _, tlvErr_euiccsigned2 := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccsigned2 != nil {
		return fmt.Errorf("decoding euiccSigned2: %w", tlvErr_euiccsigned2)
	}
	if unmErr := v.EuiccSigned2.UnmarshalBER(content[offset : offset+n_euiccsigned2]); unmErr != nil {
		return fmt.Errorf("decoding euiccSigned2: %w", unmErr)
	}
	offset += n_euiccsigned2
	// Decode euiccSignature2
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignature2")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignature2, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignature2, rawVal_euiccsignature2, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignature2: %w", err)
	}
	v.EuiccSignature2 = rawVal_euiccsignature2
	offset += n_euiccsignature2
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareDownloadResponseOk", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EUICCSigned2 to BER format.
func (v *EUICCSigned2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_euiccotpk := ber.EncodeOctetString(v.EuiccOtpk)
	enc_euiccotpk = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 73, false, enc_euiccotpk)
	children = append(children, enc_euiccotpk...)
	if v.HashCc != nil {
		enc_hashcc := ber.EncodeOctetString([]byte(*v.HashCc))
		children = append(children, enc_hashcc...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EUICCSigned2 to DER format.
func (v *EUICCSigned2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EUICCSigned2 from BER/DER format.
func (v *EUICCSigned2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EUICCSigned2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EUICCSigned2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode euiccOtpk
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccOtpk")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 73 {
			return fmt.Errorf("expected tag [%s %d] for euiccOtpk, got %s", "APPLICATION", 73, reqTag_)
		}
	}
	_, n_euiccotpk, rawVal_euiccotpk, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccOtpk: %w", err)
	}
	v.EuiccOtpk = rawVal_euiccotpk
	offset += n_euiccotpk
	// Decode hashCc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_hashcc, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding hashCc: %w", err)
				}
				tmp_hashcc := Octet32(val_hashcc)
				v.HashCc = &tmp_hashcc
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EUICCSigned2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareDownloadResponseError to BER format.
func (v *PrepareDownloadResponseError) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_downloaderrorcode := ber.EncodeBigInt((v.DownloadErrorCode).BigInt())
	children = append(children, enc_downloaderrorcode...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrepareDownloadResponseError to DER format.
func (v *PrepareDownloadResponseError) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareDownloadResponseError from BER/DER format.
func (v *PrepareDownloadResponseError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrepareDownloadResponseError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareDownloadResponseError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode downloadErrorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field downloadErrorCode")
	}
	val_downloaderrorcode, n, err := ber.DecodeBigInt(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding downloadErrorCode: %w", err)
	}
	var named_downloaderrorcode DownloadErrorCode
	if namedErr := named_downloaderrorcode.UnmarshalText([]byte(val_downloaderrorcode.String())); namedErr != nil {
		return fmt.Errorf("decoding downloadErrorCode: %w", namedErr)
	}
	v.DownloadErrorCode = named_downloaderrorcode
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareDownloadResponseError", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetEuiccChallengeRequest to BER format.
func (v *GetEuiccChallengeRequest) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 46, Constructed: true}, children), nil
}

// MarshalDER encodes GetEuiccChallengeRequest to DER format.
func (v *GetEuiccChallengeRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEuiccChallengeRequest from BER/DER format.
func (v *GetEuiccChallengeRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEuiccChallengeRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 46 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEuiccChallengeRequest: %w: expected tag [CONTEXT 46], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEuiccChallengeRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetEuiccChallengeRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetEuiccChallengeResponse to BER format.
func (v *GetEuiccChallengeResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccchallenge := ber.EncodeOctetString([]byte(v.EuiccChallenge))
	enc_euiccchallenge = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_euiccchallenge)
	children = append(children, enc_euiccchallenge...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 46, Constructed: true}, children), nil
}

// MarshalDER encodes GetEuiccChallengeResponse to DER format.
func (v *GetEuiccChallengeResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEuiccChallengeResponse from BER/DER format.
func (v *GetEuiccChallengeResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEuiccChallengeResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 46 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEuiccChallengeResponse: %w: expected tag [CONTEXT 46], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEuiccChallengeResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccChallenge
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccChallenge")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for euiccChallenge, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_euiccchallenge, rawVal_euiccchallenge, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccChallenge: %w", err)
	}
	v.EuiccChallenge = Octet16(rawVal_euiccchallenge)
	offset += n_euiccchallenge
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetEuiccChallengeResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetEuiccInfo1Request to BER format.
func (v *GetEuiccInfo1Request) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 32, Constructed: true}, children), nil
}

// MarshalDER encodes GetEuiccInfo1Request to DER format.
func (v *GetEuiccInfo1Request) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEuiccInfo1Request from BER/DER format.
func (v *GetEuiccInfo1Request) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEuiccInfo1Request: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 32 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEuiccInfo1Request: %w: expected tag [CONTEXT 32], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEuiccInfo1Request", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetEuiccInfo1Request", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetEuiccInfo2Request to BER format.
func (v *GetEuiccInfo2Request) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 34, Constructed: true}, children), nil
}

// MarshalDER encodes GetEuiccInfo2Request to DER format.
func (v *GetEuiccInfo2Request) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEuiccInfo2Request from BER/DER format.
func (v *GetEuiccInfo2Request) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEuiccInfo2Request: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 34 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEuiccInfo2Request: %w: expected tag [CONTEXT 34], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEuiccInfo2Request", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetEuiccInfo2Request", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EUICCInfo1 to BER format.
func (v *EUICCInfo1) MarshalBER() ([]byte, error) {
	var children []byte
	enc_svn := ber.EncodeOctetString([]byte(v.Svn))
	enc_svn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_svn)
	children = append(children, enc_svn...)
	enc_euicccipkidlistforverification, err := MarshalBEREUICCInfo1EuiccCiPKIdListForVerification(v.EuiccCiPKIdListForVerification)
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCiPKIdListForVerification: %w", err)
	}
	if v.EuiccCiPKIdListForVerificationIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforverification)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_euicccipkidlistforverification = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 9}, seqContent_)
	} else {
		enc_euicccipkidlistforverification = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_euicccipkidlistforverification)
	}
	children = append(children, enc_euicccipkidlistforverification...)
	enc_euicccipkidlistforsigning, err := MarshalBEREUICCInfo1EuiccCiPKIdListForSigning(v.EuiccCiPKIdListForSigning)
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCiPKIdListForSigning: %w", err)
	}
	if v.EuiccCiPKIdListForSigningIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforsigning)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_euicccipkidlistforsigning = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 10}, seqContent_)
	} else {
		enc_euicccipkidlistforsigning = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_euicccipkidlistforsigning)
	}
	children = append(children, enc_euicccipkidlistforsigning...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 32, Constructed: true}, children), nil
}

// MarshalDER encodes EUICCInfo1 to DER format.
func (v *EUICCInfo1) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.EuiccCiPKIdListForVerificationIndef_ = false
	derValue.EuiccCiPKIdListForSigningIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes EUICCInfo1 from BER/DER format.
func (v *EUICCInfo1) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EUICCInfo1: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 32 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EUICCInfo1: %w: expected tag [CONTEXT 32], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EUICCInfo1", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode svn
	if offset >= len(content) {
		return fmt.Errorf("missing required field svn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for svn, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_svn, rawVal_svn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding svn: %w", err)
	}
	v.Svn = VersionType(rawVal_svn)
	offset += n_svn
	// Decode euiccCiPKIdListForVerification
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdListForVerification")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for euiccCiPKIdListForVerification, got %s", "CONTEXT", 9, reqTag_)
		}
	}
	v.EuiccCiPKIdListForVerificationIndef_ = false
	_, n_euicccipkidlistforverification, rawVal_euicccipkidlistforverification, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForVerification: %w", err)
	}
	reconstructed_euicccipkidlistforverification := ber.EncodeSequence(rawVal_euicccipkidlistforverification)
	dec_euicccipkidlistforverification, unmErr := UnmarshalBEREUICCInfo1EuiccCiPKIdListForVerification(reconstructed_euicccipkidlistforverification)
	if unmErr != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForVerification: %w", unmErr)
	}
	v.EuiccCiPKIdListForVerification = dec_euicccipkidlistforverification
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EuiccCiPKIdListForVerificationIndef_ = true
		}
	}
	offset += n_euicccipkidlistforverification
	// Decode euiccCiPKIdListForSigning
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdListForSigning")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 10 {
			return fmt.Errorf("expected tag [%s %d] for euiccCiPKIdListForSigning, got %s", "CONTEXT", 10, reqTag_)
		}
	}
	v.EuiccCiPKIdListForSigningIndef_ = false
	_, n_euicccipkidlistforsigning, rawVal_euicccipkidlistforsigning, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForSigning: %w", err)
	}
	reconstructed_euicccipkidlistforsigning := ber.EncodeSequence(rawVal_euicccipkidlistforsigning)
	dec_euicccipkidlistforsigning, unmErr := UnmarshalBEREUICCInfo1EuiccCiPKIdListForSigning(reconstructed_euicccipkidlistforsigning)
	if unmErr != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForSigning: %w", unmErr)
	}
	v.EuiccCiPKIdListForSigning = dec_euicccipkidlistforsigning
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EuiccCiPKIdListForSigningIndef_ = true
		}
	}
	offset += n_euicccipkidlistforsigning
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EUICCInfo1", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EUICCInfo2 to BER format.
func (v *EUICCInfo2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profileversion := ber.EncodeOctetString([]byte(v.ProfileVersion))
	enc_profileversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_profileversion)
	children = append(children, enc_profileversion...)
	enc_svn := ber.EncodeOctetString([]byte(v.Svn))
	enc_svn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_svn)
	children = append(children, enc_svn...)
	enc_euiccfirmwarever := ber.EncodeOctetString([]byte(v.EuiccFirmwareVer))
	enc_euiccfirmwarever = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_euiccfirmwarever)
	children = append(children, enc_euiccfirmwarever...)
	enc_extcardresource := ber.EncodeOctetString(v.ExtCardResource)
	enc_extcardresource = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_extcardresource)
	children = append(children, enc_extcardresource...)
	enc_uicccapability := ber.EncodeBitString(v.UiccCapability.Bytes, (8-(v.UiccCapability.BitLength%8))%8)
	enc_uicccapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_uicccapability)
	children = append(children, enc_uicccapability...)
	if v.Ts102241Version != nil {
		enc_ts102241version := ber.EncodeOctetString([]byte(*v.Ts102241Version))
		enc_ts102241version = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_ts102241version)
		children = append(children, enc_ts102241version...)
	}
	if v.GlobalplatformVersion != nil {
		enc_globalplatformversion := ber.EncodeOctetString([]byte(*v.GlobalplatformVersion))
		enc_globalplatformversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_globalplatformversion)
		children = append(children, enc_globalplatformversion...)
	}
	enc_rspcapability := ber.EncodeBitString(v.RspCapability.Bytes, (8-(v.RspCapability.BitLength%8))%8)
	enc_rspcapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_rspcapability)
	children = append(children, enc_rspcapability...)
	enc_euicccipkidlistforverification, err := MarshalBEREUICCInfo2EuiccCiPKIdListForVerification(v.EuiccCiPKIdListForVerification)
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCiPKIdListForVerification: %w", err)
	}
	if v.EuiccCiPKIdListForVerificationIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforverification)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_euicccipkidlistforverification = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 9}, seqContent_)
	} else {
		enc_euicccipkidlistforverification = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_euicccipkidlistforverification)
	}
	children = append(children, enc_euicccipkidlistforverification...)
	enc_euicccipkidlistforsigning, err := MarshalBEREUICCInfo2EuiccCiPKIdListForSigning(v.EuiccCiPKIdListForSigning)
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCiPKIdListForSigning: %w", err)
	}
	if v.EuiccCiPKIdListForSigningIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforsigning)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_euicccipkidlistforsigning = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 10}, seqContent_)
	} else {
		enc_euicccipkidlistforsigning = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_euicccipkidlistforsigning)
	}
	children = append(children, enc_euicccipkidlistforsigning...)
	if v.EuiccCategory != nil {
		enc_euicccategory := ber.EncodeBigInt((*v.EuiccCategory).BigInt())
		enc_euicccategory = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_euicccategory)
		children = append(children, enc_euicccategory...)
	}
	if v.ForbiddenProfilePolicyRules != nil {
		enc_forbiddenprofilepolicyrules := ber.EncodeBitString(v.ForbiddenProfilePolicyRules.Bytes, (8-(v.ForbiddenProfilePolicyRules.BitLength%8))%8)
		enc_forbiddenprofilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_forbiddenprofilepolicyrules)
		children = append(children, enc_forbiddenprofilepolicyrules...)
	}
	enc_ppversion := ber.EncodeOctetString([]byte(v.PpVersion))
	children = append(children, enc_ppversion...)
	enc_sasacreditationnumber := ber.EncodeStringTag(12, v.SasAcreditationNumber)
	children = append(children, enc_sasacreditationnumber...)
	if v.CertificationDataObject != nil {
		enc_certificationdataobject, err := v.CertificationDataObject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding certificationDataObject: %w", err)
		}
		enc_certificationdataobject = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, true, enc_certificationdataobject)
		children = append(children, enc_certificationdataobject...)
	}
	if v.TreProperties != nil {
		enc_treproperties := ber.EncodeBitString(v.TreProperties.Bytes, (8-(v.TreProperties.BitLength%8))%8)
		enc_treproperties = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_treproperties)
		children = append(children, enc_treproperties...)
	}
	if v.TreProductReference != nil {
		enc_treproductreference := ber.EncodeStringTag(12, *v.TreProductReference)
		enc_treproductreference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_treproductreference)
		children = append(children, enc_treproductreference...)
	}
	if v.AdditionalEuiccProfilePackageVersions != nil {
		enc_additionaleuiccprofilepackageversions, err := MarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(v.AdditionalEuiccProfilePackageVersions)
		if err != nil {
			return nil, fmt.Errorf("encoding additionalEuiccProfilePackageVersions: %w", err)
		}
		if v.AdditionalEuiccProfilePackageVersionsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_additionaleuiccprofilepackageversions)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_additionaleuiccprofilepackageversions = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 15}, seqContent_)
		} else {
			enc_additionaleuiccprofilepackageversions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, true, enc_additionaleuiccprofilepackageversions)
		}
		children = append(children, enc_additionaleuiccprofilepackageversions...)
	}
	if v.LpaMode != nil {
		enc_lpamode := ber.EncodeBigInt(v.LpaMode)
		enc_lpamode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_lpamode)
		children = append(children, enc_lpamode...)
	}
	if v.EuiccCiPKIdListForSigningV3 != nil {
		enc_euicccipkidlistforsigningv3, err := MarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(v.EuiccCiPKIdListForSigningV3)
		if err != nil {
			return nil, fmt.Errorf("encoding euiccCiPKIdListForSigningV3: %w", err)
		}
		if v.EuiccCiPKIdListForSigningV3Indef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_euicccipkidlistforsigningv3)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_euicccipkidlistforsigningv3 = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 17}, seqContent_)
		} else {
			enc_euicccipkidlistforsigningv3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, true, enc_euicccipkidlistforsigningv3)
		}
		children = append(children, enc_euicccipkidlistforsigningv3...)
	}
	if v.AdditionalEuiccInfo != nil {
		enc_additionaleuiccinfo := ber.EncodeOctetString(v.AdditionalEuiccInfo)
		enc_additionaleuiccinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_additionaleuiccinfo)
		children = append(children, enc_additionaleuiccinfo...)
	}
	if v.HighestSvn != nil {
		enc_highestsvn := ber.EncodeOctetString([]byte(*v.HighestSvn))
		enc_highestsvn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_highestsvn)
		children = append(children, enc_highestsvn...)
	}
	if v.IotSpecificInfo != nil {
		enc_iotspecificinfo, err := v.IotSpecificInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding iotSpecificInfo: %w", err)
		}
		enc_iotspecificinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, true, enc_iotspecificinfo)
		children = append(children, enc_iotspecificinfo...)
	}
	if v.EuiccMinimumSecurityLevel != nil {
		enc_euiccminimumsecuritylevel := ber.EncodeOctetString(v.EuiccMinimumSecurityLevel)
		enc_euiccminimumsecuritylevel = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_euiccminimumsecuritylevel)
		children = append(children, enc_euiccminimumsecuritylevel...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 34, Constructed: true}, children), nil
}

// MarshalDER encodes EUICCInfo2 to DER format.
func (v *EUICCInfo2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.EuiccCiPKIdListForVerificationIndef_ = false
	derValue.EuiccCiPKIdListForSigningIndef_ = false
	derValue.AdditionalEuiccProfilePackageVersionsIndef_ = false
	derValue.EuiccCiPKIdListForSigningV3Indef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes EUICCInfo2 from BER/DER format.
func (v *EUICCInfo2) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EUICCInfo2: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 34 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EUICCInfo2: %w: expected tag [CONTEXT 34], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileVersion
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileVersion")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for profileVersion, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_profileversion, rawVal_profileversion, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileVersion: %w", err)
	}
	v.ProfileVersion = VersionType(rawVal_profileversion)
	offset += n_profileversion
	// Decode svn
	if offset >= len(content) {
		return fmt.Errorf("missing required field svn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for svn, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_svn, rawVal_svn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding svn: %w", err)
	}
	v.Svn = VersionType(rawVal_svn)
	offset += n_svn
	// Decode euiccFirmwareVer
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccFirmwareVer")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for euiccFirmwareVer, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_euiccfirmwarever, rawVal_euiccfirmwarever, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccFirmwareVer: %w", err)
	}
	v.EuiccFirmwareVer = VersionType(rawVal_euiccfirmwarever)
	offset += n_euiccfirmwarever
	// Decode extCardResource
	if offset >= len(content) {
		return fmt.Errorf("missing required field extCardResource")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for extCardResource, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_extcardresource, rawVal_extcardresource, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extCardResource: %w", err)
	}
	v.ExtCardResource = rawVal_extcardresource
	offset += n_extcardresource
	// Decode uiccCapability
	if offset >= len(content) {
		return fmt.Errorf("missing required field uiccCapability")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 5 {
			return fmt.Errorf("expected tag [%s %d] for uiccCapability, got %s", "CONTEXT", 5, reqTag_)
		}
	}
	_, n_uicccapability, rawVal_uicccapability, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uiccCapability: %w", err)
	}
	bsBytes_uicccapability, bsUnused_uicccapability, bsErr := ber.DecodeBitStringValue(rawVal_uicccapability)
	if bsErr != nil {
		return fmt.Errorf("decoding uiccCapability: %w", bsErr)
	}
	v.UiccCapability = runtime.BitString{Bytes: bsBytes_uicccapability, BitLength: len(bsBytes_uicccapability)*8 - bsUnused_uicccapability}
	offset += n_uicccapability
	// Decode ts102241Version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_ts102241version, rawVal_ts102241version, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ts102241Version: %w", err)
				}
				tmp_ts102241version := VersionType(rawVal_ts102241version)
				v.Ts102241Version = &tmp_ts102241version
				offset += n_ts102241version
			}
		}
	}
	// Decode globalplatformVersion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_globalplatformversion, rawVal_globalplatformversion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding globalplatformVersion: %w", err)
				}
				tmp_globalplatformversion := VersionType(rawVal_globalplatformversion)
				v.GlobalplatformVersion = &tmp_globalplatformversion
				offset += n_globalplatformversion
			}
		}
	}
	// Decode rspCapability
	if offset >= len(content) {
		return fmt.Errorf("missing required field rspCapability")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 8 {
			return fmt.Errorf("expected tag [%s %d] for rspCapability, got %s", "CONTEXT", 8, reqTag_)
		}
	}
	_, n_rspcapability, rawVal_rspcapability, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rspCapability: %w", err)
	}
	bsBytes_rspcapability, bsUnused_rspcapability, bsErr := ber.DecodeBitStringValue(rawVal_rspcapability)
	if bsErr != nil {
		return fmt.Errorf("decoding rspCapability: %w", bsErr)
	}
	v.RspCapability = runtime.BitString{Bytes: bsBytes_rspcapability, BitLength: len(bsBytes_rspcapability)*8 - bsUnused_rspcapability}
	offset += n_rspcapability
	// Decode euiccCiPKIdListForVerification
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdListForVerification")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for euiccCiPKIdListForVerification, got %s", "CONTEXT", 9, reqTag_)
		}
	}
	v.EuiccCiPKIdListForVerificationIndef_ = false
	_, n_euicccipkidlistforverification, rawVal_euicccipkidlistforverification, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForVerification: %w", err)
	}
	reconstructed_euicccipkidlistforverification := ber.EncodeSequence(rawVal_euicccipkidlistforverification)
	dec_euicccipkidlistforverification, unmErr := UnmarshalBEREUICCInfo2EuiccCiPKIdListForVerification(reconstructed_euicccipkidlistforverification)
	if unmErr != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForVerification: %w", unmErr)
	}
	v.EuiccCiPKIdListForVerification = dec_euicccipkidlistforverification
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EuiccCiPKIdListForVerificationIndef_ = true
		}
	}
	offset += n_euicccipkidlistforverification
	// Decode euiccCiPKIdListForSigning
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdListForSigning")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 10 {
			return fmt.Errorf("expected tag [%s %d] for euiccCiPKIdListForSigning, got %s", "CONTEXT", 10, reqTag_)
		}
	}
	v.EuiccCiPKIdListForSigningIndef_ = false
	_, n_euicccipkidlistforsigning, rawVal_euicccipkidlistforsigning, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForSigning: %w", err)
	}
	reconstructed_euicccipkidlistforsigning := ber.EncodeSequence(rawVal_euicccipkidlistforsigning)
	dec_euicccipkidlistforsigning, unmErr := UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigning(reconstructed_euicccipkidlistforsigning)
	if unmErr != nil {
		return fmt.Errorf("decoding euiccCiPKIdListForSigning: %w", unmErr)
	}
	v.EuiccCiPKIdListForSigning = dec_euicccipkidlistforsigning
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EuiccCiPKIdListForSigningIndef_ = true
		}
	}
	offset += n_euicccipkidlistforsigning
	// Decode euiccCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_euicccategory, rawVal_euicccategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCategory: %w", err)
				}
				decVal_euicccategory, intErr := ber.DecodeBigIntValue(rawVal_euicccategory)
				if intErr != nil {
					return fmt.Errorf("decoding euiccCategory: %w", intErr)
				}
				var named_euicccategory EUICCInfo2EuiccCategoryValue
				if namedErr := named_euicccategory.UnmarshalText([]byte(decVal_euicccategory.String())); namedErr != nil {
					return fmt.Errorf("decoding euiccCategory: %w", namedErr)
				}
				v.EuiccCategory = &named_euicccategory
				offset += n_euicccategory
			}
		}
	}
	// Decode forbiddenProfilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_forbiddenprofilepolicyrules, rawVal_forbiddenprofilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forbiddenProfilePolicyRules: %w", err)
				}
				bsBytes_forbiddenprofilepolicyrules, bsUnused_forbiddenprofilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_forbiddenprofilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding forbiddenProfilePolicyRules: %w", bsErr)
				}
				tmp_forbiddenprofilepolicyrules := runtime.BitString{Bytes: bsBytes_forbiddenprofilepolicyrules, BitLength: len(bsBytes_forbiddenprofilepolicyrules)*8 - bsUnused_forbiddenprofilepolicyrules}
				v.ForbiddenProfilePolicyRules = &tmp_forbiddenprofilepolicyrules
				offset += n_forbiddenprofilepolicyrules
			}
		}
	}
	// Decode ppVersion
	if offset >= len(content) {
		return fmt.Errorf("missing required field ppVersion")
	}
	val_ppversion, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ppVersion: %w", err)
	}
	v.PpVersion = VersionType(val_ppversion)
	offset += n
	// Decode sasAcreditationNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field sasAcreditationNumber")
	}
	val_sasacreditationnumber, n, err := ber.DecodeString(content[offset:], 12)
	if err != nil {
		return fmt.Errorf("decoding sasAcreditationNumber: %w", err)
	}
	v.SasAcreditationNumber = val_sasacreditationnumber
	offset += n
	// Decode certificationDataObject
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_certificationdataobject, rawVal_certificationdataobject, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding certificationDataObject: %w", err)
				}
				reconstructed_certificationdataobject := ber.EncodeSequence(rawVal_certificationdataobject)
				var dec_certificationdataobject CertificationDataObject
				if unmErr := dec_certificationdataobject.UnmarshalBER(reconstructed_certificationdataobject); unmErr != nil {
					return fmt.Errorf("decoding certificationDataObject: %w", unmErr)
				}
				v.CertificationDataObject = &dec_certificationdataobject
				offset += n_certificationdataobject
			}
		}
	}
	// Decode treProperties
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_treproperties, rawVal_treproperties, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding treProperties: %w", err)
				}
				bsBytes_treproperties, bsUnused_treproperties, bsErr := ber.DecodeBitStringValue(rawVal_treproperties)
				if bsErr != nil {
					return fmt.Errorf("decoding treProperties: %w", bsErr)
				}
				tmp_treproperties := runtime.BitString{Bytes: bsBytes_treproperties, BitLength: len(bsBytes_treproperties)*8 - bsUnused_treproperties}
				v.TreProperties = &tmp_treproperties
				offset += n_treproperties
			}
		}
	}
	// Decode treProductReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_treproductreference, rawVal_treproductreference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding treProductReference: %w", err)
				}
				decVal_treproductreference := ber.DecodeStringValue(rawVal_treproductreference)
				v.TreProductReference = &decVal_treproductreference
				offset += n_treproductreference
			}
		}
	}
	// Decode additionalEuiccProfilePackageVersions
	v.AdditionalEuiccProfilePackageVersionsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				_, n_additionaleuiccprofilepackageversions, rawVal_additionaleuiccprofilepackageversions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalEuiccProfilePackageVersions: %w", err)
				}
				reconstructed_additionaleuiccprofilepackageversions := ber.EncodeSequence(rawVal_additionaleuiccprofilepackageversions)
				dec_additionaleuiccprofilepackageversions, unmErr := UnmarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(reconstructed_additionaleuiccprofilepackageversions)
				if unmErr != nil {
					return fmt.Errorf("decoding additionalEuiccProfilePackageVersions: %w", unmErr)
				}
				v.AdditionalEuiccProfilePackageVersions = dec_additionaleuiccprofilepackageversions
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.AdditionalEuiccProfilePackageVersionsIndef_ = true
					}
				}
				offset += n_additionaleuiccprofilepackageversions
			}
		}
	}
	// Decode lpaMode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_lpamode, rawVal_lpamode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lpaMode: %w", err)
				}
				decVal_lpamode, intErr := ber.DecodeBigIntValue(rawVal_lpamode)
				if intErr != nil {
					return fmt.Errorf("decoding lpaMode: %w", intErr)
				}
				v.LpaMode = decVal_lpamode
				offset += n_lpamode
			}
		}
	}
	// Decode euiccCiPKIdListForSigningV3
	v.EuiccCiPKIdListForSigningV3Indef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_euicccipkidlistforsigningv3, rawVal_euicccipkidlistforsigningv3, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccCiPKIdListForSigningV3: %w", err)
				}
				reconstructed_euicccipkidlistforsigningv3 := ber.EncodeSequence(rawVal_euicccipkidlistforsigningv3)
				dec_euicccipkidlistforsigningv3, unmErr := UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(reconstructed_euicccipkidlistforsigningv3)
				if unmErr != nil {
					return fmt.Errorf("decoding euiccCiPKIdListForSigningV3: %w", unmErr)
				}
				v.EuiccCiPKIdListForSigningV3 = dec_euicccipkidlistforsigningv3
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.EuiccCiPKIdListForSigningV3Indef_ = true
					}
				}
				offset += n_euicccipkidlistforsigningv3
			}
		}
	}
	// Decode additionalEuiccInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_additionaleuiccinfo, rawVal_additionaleuiccinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalEuiccInfo: %w", err)
				}
				tmp_additionaleuiccinfo := rawVal_additionaleuiccinfo
				v.AdditionalEuiccInfo = tmp_additionaleuiccinfo
				offset += n_additionaleuiccinfo
			}
		}
	}
	// Decode highestSvn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_highestsvn, rawVal_highestsvn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding highestSvn: %w", err)
				}
				tmp_highestsvn := VersionType(rawVal_highestsvn)
				v.HighestSvn = &tmp_highestsvn
				offset += n_highestsvn
			}
		}
	}
	// Decode iotSpecificInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_iotspecificinfo, rawVal_iotspecificinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iotSpecificInfo: %w", err)
				}
				reconstructed_iotspecificinfo := ber.EncodeSequence(rawVal_iotspecificinfo)
				var dec_iotspecificinfo IoTSpecificInfo
				if unmErr := dec_iotspecificinfo.UnmarshalBER(reconstructed_iotspecificinfo); unmErr != nil {
					return fmt.Errorf("decoding iotSpecificInfo: %w", unmErr)
				}
				v.IotSpecificInfo = &dec_iotspecificinfo
				offset += n_iotspecificinfo
			}
		}
	}
	// Decode euiccMinimumSecurityLevel
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_euiccminimumsecuritylevel, rawVal_euiccminimumsecuritylevel, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding euiccMinimumSecurityLevel: %w", err)
				}
				tmp_euiccminimumsecuritylevel := rawVal_euiccminimumsecuritylevel
				v.EuiccMinimumSecurityLevel = tmp_euiccminimumsecuritylevel
				offset += n_euiccminimumsecuritylevel
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EUICCInfo2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CertificationDataObject to BER format.
func (v *CertificationDataObject) MarshalBER() ([]byte, error) {
	var children []byte
	enc_platformlabel := ber.EncodeStringTag(12, v.PlatformLabel)
	enc_platformlabel = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_platformlabel)
	children = append(children, enc_platformlabel...)
	enc_discoverybaseurl := ber.EncodeStringTag(12, v.DiscoveryBaseURL)
	enc_discoverybaseurl = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_discoverybaseurl)
	children = append(children, enc_discoverybaseurl...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CertificationDataObject to DER format.
func (v *CertificationDataObject) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CertificationDataObject from BER/DER format.
func (v *CertificationDataObject) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CertificationDataObject SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CertificationDataObject", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode platformLabel
	if offset >= len(content) {
		return fmt.Errorf("missing required field platformLabel")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for platformLabel, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_platformlabel, rawVal_platformlabel, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding platformLabel: %w", err)
	}
	decVal_platformlabel := ber.DecodeStringValue(rawVal_platformlabel)
	v.PlatformLabel = decVal_platformlabel
	offset += n_platformlabel
	// Decode discoveryBaseURL
	if offset >= len(content) {
		return fmt.Errorf("missing required field discoveryBaseURL")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for discoveryBaseURL, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_discoverybaseurl, rawVal_discoverybaseurl, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding discoveryBaseURL: %w", err)
	}
	decVal_discoverybaseurl := ber.DecodeStringValue(rawVal_discoverybaseurl)
	v.DiscoveryBaseURL = decVal_discoverybaseurl
	offset += n_discoverybaseurl
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CertificationDataObject", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IoTSpecificInfo to BER format.
func (v *IoTSpecificInfo) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes IoTSpecificInfo to DER format.
func (v *IoTSpecificInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IoTSpecificInfo from BER/DER format.
func (v *IoTSpecificInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IoTSpecificInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IoTSpecificInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IoTSpecificInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ListNotificationRequest to BER format.
func (v *ListNotificationRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ProfileManagementOperation != nil {
		enc_profilemanagementoperation := ber.EncodeBitString(v.ProfileManagementOperation.Bytes, (8-(v.ProfileManagementOperation.BitLength%8))%8)
		enc_profilemanagementoperation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_profilemanagementoperation)
		children = append(children, enc_profilemanagementoperation...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 40, Constructed: true}, children), nil
}

// MarshalDER encodes ListNotificationRequest to DER format.
func (v *ListNotificationRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ListNotificationRequest from BER/DER format.
func (v *ListNotificationRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ListNotificationRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 40 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ListNotificationRequest: %w: expected tag [CONTEXT 40], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ListNotificationRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileManagementOperation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_profilemanagementoperation, rawVal_profilemanagementoperation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileManagementOperation: %w", err)
				}
				bsBytes_profilemanagementoperation, bsUnused_profilemanagementoperation, bsErr := ber.DecodeBitStringValue(rawVal_profilemanagementoperation)
				if bsErr != nil {
					return fmt.Errorf("decoding profileManagementOperation: %w", bsErr)
				}
				tmp_profilemanagementoperation := runtime.BitString{Bytes: bsBytes_profilemanagementoperation, BitLength: len(bsBytes_profilemanagementoperation)*8 - bsUnused_profilemanagementoperation}
				v.ProfileManagementOperation = &tmp_profilemanagementoperation
				offset += n_profilemanagementoperation
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ListNotificationRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ListNotificationResponse to BER format.
func (v *ListNotificationResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ListNotificationResponseChoiceNotificationMetadataList:
		if v.NotificationMetadataList == nil {
			return nil, fmt.Errorf("choice ListNotificationResponse: notificationMetadataList is nil")
		}
		enc_0, err := MarshalBERListNotificationResponseNotificationMetadataList(v.NotificationMetadataList)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationMetadataList: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 40, enc_0)
		return enc_0, nil
	case ListNotificationResponseChoiceListNotificationsResultError:
		if v.ListNotificationsResultError == nil {
			return nil, fmt.Errorf("choice ListNotificationResponse: listNotificationsResultError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.ListNotificationsResultError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 40, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ListNotificationResponse", v.Choice)
	}
}

// MarshalDER encodes ListNotificationResponse to DER format.
func (v *ListNotificationResponse) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ListNotificationResponse from BER/DER format.
func (v *ListNotificationResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ListNotificationResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ListNotificationResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 40 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ListNotificationResponse CHOICE: %w: expected tag [CONTEXT 40], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ListNotificationResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for ListNotificationResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ListNotificationResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ListNotificationResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ListNotificationResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ListNotificationResponseChoiceNotificationMetadataList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding notificationMetadataList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERListNotificationResponseNotificationMetadataList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding notificationMetadataList: %w", unmErr)
		}
		v.NotificationMetadataList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ListNotificationResponseChoiceListNotificationsResultError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding listNotificationsResultError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding listNotificationsResultError: %w", intErr)
		}
		var named_listnotificationsresulterror ListNotificationResponseListNotificationsResultErrorValue
		if namedErr := named_listnotificationsresulterror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding listNotificationsResultError: %w", namedErr)
		}
		v.ListNotificationsResultError = &named_listnotificationsresulterror
	} else {
		return fmt.Errorf("unknown tag %s for ListNotificationResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes NotificationMetadata to BER format.
func (v *NotificationMetadata) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SeqNumber == nil {
		return nil, fmt.Errorf("encoding seqNumber: required INTEGER is nil")
	}
	enc_seqnumber := ber.EncodeBigInt(v.SeqNumber)
	enc_seqnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_seqnumber)
	children = append(children, enc_seqnumber...)
	enc_profilemanagementoperation := ber.EncodeBitString(v.ProfileManagementOperation.Bytes, (8-(v.ProfileManagementOperation.BitLength%8))%8)
	enc_profilemanagementoperation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_profilemanagementoperation)
	children = append(children, enc_profilemanagementoperation...)
	enc_notificationaddress := ber.EncodeStringTag(12, v.NotificationAddress)
	children = append(children, enc_notificationaddress...)
	if v.Iccid != nil {
		enc_iccid := ber.EncodeOctetString([]byte(*v.Iccid))
		enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
		children = append(children, enc_iccid...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 47, Constructed: true}, children), nil
}

// MarshalDER encodes NotificationMetadata to DER format.
func (v *NotificationMetadata) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NotificationMetadata from BER/DER format.
func (v *NotificationMetadata) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding NotificationMetadata: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 47 || !decodedTag.Constructed {
		return fmt.Errorf("decoding NotificationMetadata: %w: expected tag [CONTEXT 47], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NotificationMetadata", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode seqNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field seqNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for seqNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_seqnumber, rawVal_seqnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding seqNumber: %w", err)
	}
	decVal_seqnumber, intErr := ber.DecodeBigIntValue(rawVal_seqnumber)
	if intErr != nil {
		return fmt.Errorf("decoding seqNumber: %w", intErr)
	}
	v.SeqNumber = decVal_seqnumber
	offset += n_seqnumber
	// Decode profileManagementOperation
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileManagementOperation")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for profileManagementOperation, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_profilemanagementoperation, rawVal_profilemanagementoperation, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileManagementOperation: %w", err)
	}
	bsBytes_profilemanagementoperation, bsUnused_profilemanagementoperation, bsErr := ber.DecodeBitStringValue(rawVal_profilemanagementoperation)
	if bsErr != nil {
		return fmt.Errorf("decoding profileManagementOperation: %w", bsErr)
	}
	v.ProfileManagementOperation = runtime.BitString{Bytes: bsBytes_profilemanagementoperation, BitLength: len(bsBytes_profilemanagementoperation)*8 - bsUnused_profilemanagementoperation}
	offset += n_profilemanagementoperation
	// Decode notificationAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field notificationAddress")
	}
	val_notificationaddress, n, err := ber.DecodeString(content[offset:], 12)
	if err != nil {
		return fmt.Errorf("decoding notificationAddress: %w", err)
	}
	v.NotificationAddress = val_notificationaddress
	offset += n
	// Decode iccid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
				_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iccid: %w", err)
				}
				tmp_iccid := Iccid(rawVal_iccid)
				v.Iccid = &tmp_iccid
				offset += n_iccid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NotificationMetadata", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RetrieveNotificationsListRequest to BER format.
func (v *RetrieveNotificationsListRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SearchCriteria != nil {
		enc_searchcriteria, err := v.SearchCriteria.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding searchCriteria: %w", err)
		}
		enc_searchcriteria = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_searchcriteria)
		children = append(children, enc_searchcriteria...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 43, Constructed: true}, children), nil
}

// MarshalDER encodes RetrieveNotificationsListRequest to DER format.
func (v *RetrieveNotificationsListRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RetrieveNotificationsListRequest from BER/DER format.
func (v *RetrieveNotificationsListRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 43 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RetrieveNotificationsListRequest: %w: expected tag [CONTEXT 43], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode searchCriteria
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_searchcriteria, innerData_searchcriteria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding searchCriteria: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_searchcriteria RetrieveNotificationsListRequestSearchCriteria
				if unmErr := dec_searchcriteria.UnmarshalBER(innerData_searchcriteria); unmErr != nil {
					return fmt.Errorf("decoding searchCriteria: %w", unmErr)
				}
				v.SearchCriteria = &dec_searchcriteria
				offset += n_searchcriteria
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RetrieveNotificationsListRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RetrieveNotificationsListResponse to BER format.
func (v *RetrieveNotificationsListResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RetrieveNotificationsListResponseChoiceNotificationList:
		if v.NotificationList == nil {
			return nil, fmt.Errorf("choice RetrieveNotificationsListResponse: notificationList is nil")
		}
		enc_0, err := MarshalBERRetrieveNotificationsListResponseNotificationList(v.NotificationList)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationList: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 43, enc_0)
		return enc_0, nil
	case RetrieveNotificationsListResponseChoiceNotificationsListResultError:
		if v.NotificationsListResultError == nil {
			return nil, fmt.Errorf("choice RetrieveNotificationsListResponse: notificationsListResultError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.NotificationsListResultError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 43, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RetrieveNotificationsListResponse", v.Choice)
	}
}

// MarshalDER encodes RetrieveNotificationsListResponse to DER format.
func (v *RetrieveNotificationsListResponse) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes RetrieveNotificationsListResponse from BER/DER format.
func (v *RetrieveNotificationsListResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RetrieveNotificationsListResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 43 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RetrieveNotificationsListResponse CHOICE: %w: expected tag [CONTEXT 43], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for RetrieveNotificationsListResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RetrieveNotificationsListResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = RetrieveNotificationsListResponseChoiceNotificationList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding notificationList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERRetrieveNotificationsListResponseNotificationList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding notificationList: %w", unmErr)
		}
		v.NotificationList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = RetrieveNotificationsListResponseChoiceNotificationsListResultError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding notificationsListResultError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding notificationsListResultError: %w", intErr)
		}
		var named_notificationslistresulterror RetrieveNotificationsListResponseNotificationsListResultErrorValue
		if namedErr := named_notificationslistresulterror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding notificationsListResultError: %w", namedErr)
		}
		v.NotificationsListResultError = &named_notificationslistresulterror
	} else {
		return fmt.Errorf("unknown tag %s for RetrieveNotificationsListResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PendingNotification to BER format.
func (v *PendingNotification) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PendingNotificationChoiceProfileInstallationResult:
		if v.ProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice PendingNotification: profileInstallationResult is nil")
		}
		enc_0, err := v.ProfileInstallationResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileInstallationResult: %w", err)
		}
		return enc_0, nil
	case PendingNotificationChoiceOtherSignedNotification:
		if v.OtherSignedNotification == nil {
			return nil, fmt.Errorf("choice PendingNotification: otherSignedNotification is nil")
		}
		enc_1, err := v.OtherSignedNotification.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding otherSignedNotification: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PendingNotification", v.Choice)
	}
}

// MarshalDER encodes PendingNotification to DER format.
func (v *PendingNotification) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case PendingNotificationChoiceProfileInstallationResult:
		if v.ProfileInstallationResult == nil {
			return nil, fmt.Errorf("choice PendingNotification: profileInstallationResult is nil")
		}
		enc_der_0, err := v.ProfileInstallationResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileInstallationResult: %w", err)
		}
		return enc_der_0, nil
	case PendingNotificationChoiceOtherSignedNotification:
		if v.OtherSignedNotification == nil {
			return nil, fmt.Errorf("choice PendingNotification: otherSignedNotification is nil")
		}
		enc_der_1, err := v.OtherSignedNotification.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding otherSignedNotification: %w", err)
		}
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes PendingNotification from BER/DER format.
func (v *PendingNotification) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PendingNotification CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PendingNotification: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PendingNotification CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PendingNotification", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 55 {
		v.Choice = PendingNotificationChoiceProfileInstallationResult
		var dec ProfileInstallationResult
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding profileInstallationResult: %w", unmErr)
		}
		v.ProfileInstallationResult = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = PendingNotificationChoiceOtherSignedNotification
		var dec OtherSignedNotification
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding otherSignedNotification: %w", unmErr)
		}
		v.OtherSignedNotification = &dec
	} else {
		return fmt.Errorf("unknown tag %s for PendingNotification CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes OtherSignedNotification to BER format.
func (v *OtherSignedNotification) MarshalBER() ([]byte, error) {
	var children []byte
	enc_tbsothernotification, err := v.TbsOtherNotification.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding tbsOtherNotification: %w", err)
	}
	children = append(children, enc_tbsothernotification...)
	enc_euiccnotificationsignature := ber.EncodeOctetString(v.EuiccNotificationSignature)
	enc_euiccnotificationsignature = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccnotificationsignature)
	children = append(children, enc_euiccnotificationsignature...)
	enc_euicccertificate, err := v.EuiccCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCertificate: %w", err)
	}
	children = append(children, enc_euicccertificate...)
	enc_eumcertificate, err := v.EumCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding eumCertificate: %w", err)
	}
	children = append(children, enc_eumcertificate...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes OtherSignedNotification to DER format.
func (v *OtherSignedNotification) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes OtherSignedNotification from BER/DER format.
func (v *OtherSignedNotification) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OtherSignedNotification SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OtherSignedNotification", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode tbsOtherNotification
	if offset >= len(content) {
		return fmt.Errorf("missing required field tbsOtherNotification")
	}
	// Decode nested SEQUENCE (NotificationMetadata)
	_, n_tbsothernotification, _, tlvErr_tbsothernotification := ber.DecodeTLV(content[offset:])
	if tlvErr_tbsothernotification != nil {
		return fmt.Errorf("decoding tbsOtherNotification: %w", tlvErr_tbsothernotification)
	}
	if unmErr := v.TbsOtherNotification.UnmarshalBER(content[offset : offset+n_tbsothernotification]); unmErr != nil {
		return fmt.Errorf("decoding tbsOtherNotification: %w", unmErr)
	}
	offset += n_tbsothernotification
	// Decode euiccNotificationSignature
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccNotificationSignature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccNotificationSignature, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccnotificationsignature, rawVal_euiccnotificationsignature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccNotificationSignature: %w", err)
	}
	v.EuiccNotificationSignature = rawVal_euiccnotificationsignature
	offset += n_euiccnotificationsignature
	// Decode euiccCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_euicccertificate, _, tlvErr_euicccertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_euicccertificate != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", tlvErr_euicccertificate)
	}
	if unmErr := v.EuiccCertificate.UnmarshalBER(content[offset : offset+n_euicccertificate]); unmErr != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", unmErr)
	}
	offset += n_euicccertificate
	// Decode eumCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field eumCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_eumcertificate, _, tlvErr_eumcertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_eumcertificate != nil {
		return fmt.Errorf("decoding eumCertificate: %w", tlvErr_eumcertificate)
	}
	if unmErr := v.EumCertificate.UnmarshalBER(content[offset : offset+n_eumcertificate]); unmErr != nil {
		return fmt.Errorf("decoding eumCertificate: %w", unmErr)
	}
	offset += n_eumcertificate
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OtherSignedNotification", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NotificationSentRequest to BER format.
func (v *NotificationSentRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SeqNumber == nil {
		return nil, fmt.Errorf("encoding seqNumber: required INTEGER is nil")
	}
	enc_seqnumber := ber.EncodeBigInt(v.SeqNumber)
	enc_seqnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_seqnumber)
	children = append(children, enc_seqnumber...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 48, Constructed: true}, children), nil
}

// MarshalDER encodes NotificationSentRequest to DER format.
func (v *NotificationSentRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NotificationSentRequest from BER/DER format.
func (v *NotificationSentRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding NotificationSentRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 48 || !decodedTag.Constructed {
		return fmt.Errorf("decoding NotificationSentRequest: %w: expected tag [CONTEXT 48], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NotificationSentRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode seqNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field seqNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for seqNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_seqnumber, rawVal_seqnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding seqNumber: %w", err)
	}
	decVal_seqnumber, intErr := ber.DecodeBigIntValue(rawVal_seqnumber)
	if intErr != nil {
		return fmt.Errorf("decoding seqNumber: %w", intErr)
	}
	v.SeqNumber = decVal_seqnumber
	offset += n_seqnumber
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NotificationSentRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NotificationSentResponse to BER format.
func (v *NotificationSentResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_deletenotificationstatus := ber.EncodeBigInt((v.DeleteNotificationStatus).BigInt())
	enc_deletenotificationstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_deletenotificationstatus)
	children = append(children, enc_deletenotificationstatus...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 48, Constructed: true}, children), nil
}

// MarshalDER encodes NotificationSentResponse to DER format.
func (v *NotificationSentResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NotificationSentResponse from BER/DER format.
func (v *NotificationSentResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding NotificationSentResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 48 || !decodedTag.Constructed {
		return fmt.Errorf("decoding NotificationSentResponse: %w: expected tag [CONTEXT 48], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NotificationSentResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deleteNotificationStatus
	if offset >= len(content) {
		return fmt.Errorf("missing required field deleteNotificationStatus")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for deleteNotificationStatus, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_deletenotificationstatus, rawVal_deletenotificationstatus, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deleteNotificationStatus: %w", err)
	}
	decVal_deletenotificationstatus, intErr := ber.DecodeBigIntValue(rawVal_deletenotificationstatus)
	if intErr != nil {
		return fmt.Errorf("decoding deleteNotificationStatus: %w", intErr)
	}
	var named_deletenotificationstatus NotificationSentResponseDeleteNotificationStatusValue
	if namedErr := named_deletenotificationstatus.UnmarshalText([]byte(decVal_deletenotificationstatus.String())); namedErr != nil {
		return fmt.Errorf("decoding deleteNotificationStatus: %w", namedErr)
	}
	v.DeleteNotificationStatus = named_deletenotificationstatus
	offset += n_deletenotificationstatus
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NotificationSentResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LoadCRLRequest to BER format.
func (v *LoadCRLRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_crl, err := v.Crl.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding crl: %w", err)
	}
	enc_crl = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_crl)
	children = append(children, enc_crl...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 53, Constructed: true}, children), nil
}

// MarshalDER encodes LoadCRLRequest to DER format.
func (v *LoadCRLRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LoadCRLRequest from BER/DER format.
func (v *LoadCRLRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding LoadCRLRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 53 || !decodedTag.Constructed {
		return fmt.Errorf("decoding LoadCRLRequest: %w: expected tag [CONTEXT 53], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LoadCRLRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode crl
	if offset >= len(content) {
		return fmt.Errorf("missing required field crl")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for crl, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_crl, rawVal_crl, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding crl: %w", err)
	}
	reconstructed_crl := ber.EncodeSequence(rawVal_crl)
	if unmErr := v.Crl.UnmarshalBER(reconstructed_crl); unmErr != nil {
		return fmt.Errorf("decoding crl: %w", unmErr)
	}
	offset += n_crl
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LoadCRLRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LoadCRLResponse to BER format.
func (v *LoadCRLResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case LoadCRLResponseChoiceLoadCRLResponseOk:
		if v.LoadCRLResponseOk == nil {
			return nil, fmt.Errorf("choice LoadCRLResponse: loadCRLResponseOk is nil")
		}
		enc_0, err := v.LoadCRLResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding loadCRLResponseOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 53, enc_0)
		return enc_0, nil
	case LoadCRLResponseChoiceLoadCRLResponseError:
		if v.LoadCRLResponseError == nil {
			return nil, fmt.Errorf("choice LoadCRLResponse: loadCRLResponseError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.LoadCRLResponseError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 53, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for LoadCRLResponse", v.Choice)
	}
}

// MarshalDER encodes LoadCRLResponse to DER format.
func (v *LoadCRLResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case LoadCRLResponseChoiceLoadCRLResponseOk:
		if v.LoadCRLResponseOk == nil {
			return nil, fmt.Errorf("choice LoadCRLResponse: loadCRLResponseOk is nil")
		}
		enc_der_0, err := v.LoadCRLResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding loadCRLResponseOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 53, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes LoadCRLResponse from BER/DER format.
func (v *LoadCRLResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for LoadCRLResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding LoadCRLResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 53 || !decodedTag.Constructed {
		return fmt.Errorf("decoding LoadCRLResponse CHOICE: %w: expected tag [CONTEXT 53], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LoadCRLResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for LoadCRLResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for LoadCRLResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding LoadCRLResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "LoadCRLResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = LoadCRLResponseChoiceLoadCRLResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding loadCRLResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec LoadCRLResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding loadCRLResponseOk: %w", unmErr)
		}
		v.LoadCRLResponseOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LoadCRLResponseChoiceLoadCRLResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding loadCRLResponseError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding loadCRLResponseError: %w", intErr)
		}
		var named_loadcrlresponseerror LoadCRLResponseError
		if namedErr := named_loadcrlresponseerror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding loadCRLResponseError: %w", namedErr)
		}
		v.LoadCRLResponseError = &named_loadcrlresponseerror
	} else {
		return fmt.Errorf("unknown tag %s for LoadCRLResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LoadCRLResponseOk to BER format.
func (v *LoadCRLResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MissingParts != nil {
		enc_missingparts, err := MarshalBERLoadCRLResponseOkMissingParts(v.MissingParts)
		if err != nil {
			return nil, fmt.Errorf("encoding missingParts: %w", err)
		}
		if v.MissingPartsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_missingparts)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_missingparts = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_missingparts = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_missingparts)
		}
		children = append(children, enc_missingparts...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes LoadCRLResponseOk to DER format.
func (v *LoadCRLResponseOk) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.MissingPartsIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LoadCRLResponseOk from BER/DER format.
func (v *LoadCRLResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LoadCRLResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LoadCRLResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode missingParts
	v.MissingPartsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_missingparts, rawVal_missingparts, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding missingParts: %w", err)
				}
				reconstructed_missingparts := ber.EncodeSequence(rawVal_missingparts)
				dec_missingparts, unmErr := UnmarshalBERLoadCRLResponseOkMissingParts(reconstructed_missingparts)
				if unmErr != nil {
					return fmt.Errorf("decoding missingParts: %w", unmErr)
				}
				v.MissingParts = dec_missingparts
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.MissingPartsIndef_ = true
					}
				}
				offset += n_missingparts
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LoadCRLResponseOk", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AuthenticateServerRequest to BER format.
func (v *AuthenticateServerRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_serversigned1, err := v.ServerSigned1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding serverSigned1: %w", err)
	}
	children = append(children, enc_serversigned1...)
	enc_serversignature1 := ber.EncodeOctetString(v.ServerSignature1)
	enc_serversignature1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_serversignature1)
	children = append(children, enc_serversignature1...)
	enc_euicccipkidtobeused := ber.EncodeOctetString([]byte(v.EuiccCiPKIdToBeUsed))
	children = append(children, enc_euicccipkidtobeused...)
	enc_servercertificate, err := v.ServerCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding serverCertificate: %w", err)
	}
	children = append(children, enc_servercertificate...)
	enc_ctxparams1, err := v.CtxParams1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding ctxParams1: %w", err)
	}
	children = append(children, enc_ctxparams1...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 56, Constructed: true}, children), nil
}

// MarshalDER encodes AuthenticateServerRequest to DER format.
func (v *AuthenticateServerRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateServerRequest from BER/DER format.
func (v *AuthenticateServerRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateServerRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 56 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateServerRequest: %w: expected tag [CONTEXT 56], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateServerRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode serverSigned1
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverSigned1")
	}
	// Decode nested SEQUENCE (ServerSigned1)
	_, n_serversigned1, _, tlvErr_serversigned1 := ber.DecodeTLV(content[offset:])
	if tlvErr_serversigned1 != nil {
		return fmt.Errorf("decoding serverSigned1: %w", tlvErr_serversigned1)
	}
	if unmErr := v.ServerSigned1.UnmarshalBER(content[offset : offset+n_serversigned1]); unmErr != nil {
		return fmt.Errorf("decoding serverSigned1: %w", unmErr)
	}
	offset += n_serversigned1
	// Decode serverSignature1
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverSignature1")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for serverSignature1, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_serversignature1, rawVal_serversignature1, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverSignature1: %w", err)
	}
	v.ServerSignature1 = rawVal_serversignature1
	offset += n_serversignature1
	// Decode euiccCiPKIdToBeUsed
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdToBeUsed")
	}
	val_euicccipkidtobeused, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdToBeUsed: %w", err)
	}
	v.EuiccCiPKIdToBeUsed = SubjectKeyIdentifier(val_euicccipkidtobeused)
	offset += n
	// Decode serverCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_servercertificate, _, tlvErr_servercertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_servercertificate != nil {
		return fmt.Errorf("decoding serverCertificate: %w", tlvErr_servercertificate)
	}
	if unmErr := v.ServerCertificate.UnmarshalBER(content[offset : offset+n_servercertificate]); unmErr != nil {
		return fmt.Errorf("decoding serverCertificate: %w", unmErr)
	}
	offset += n_servercertificate
	// Decode ctxParams1
	if offset >= len(content) {
		return fmt.Errorf("missing required field ctxParams1")
	}
	// Decode nested CHOICE (CtxParams1)
	_, n_ctxparams1, _, tlvErr_ctxparams1 := ber.DecodeTLV(content[offset:])
	if tlvErr_ctxparams1 != nil {
		return fmt.Errorf("decoding ctxParams1: %w", tlvErr_ctxparams1)
	}
	if unmErr := v.CtxParams1.UnmarshalBER(content[offset : offset+n_ctxparams1]); unmErr != nil {
		return fmt.Errorf("decoding ctxParams1: %w", unmErr)
	}
	offset += n_ctxparams1
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateServerRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ServerSigned1 to BER format.
func (v *ServerSigned1) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_euiccchallenge := ber.EncodeOctetString([]byte(v.EuiccChallenge))
	enc_euiccchallenge = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_euiccchallenge)
	children = append(children, enc_euiccchallenge...)
	enc_serveraddress := ber.EncodeStringTag(12, v.ServerAddress)
	enc_serveraddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_serveraddress)
	children = append(children, enc_serveraddress...)
	enc_serverchallenge := ber.EncodeOctetString([]byte(v.ServerChallenge))
	enc_serverchallenge = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_serverchallenge)
	children = append(children, enc_serverchallenge...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ServerSigned1 to DER format.
func (v *ServerSigned1) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ServerSigned1 from BER/DER format.
func (v *ServerSigned1) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ServerSigned1 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ServerSigned1", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode euiccChallenge
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccChallenge")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for euiccChallenge, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_euiccchallenge, rawVal_euiccchallenge, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccChallenge: %w", err)
	}
	v.EuiccChallenge = Octet16(rawVal_euiccchallenge)
	offset += n_euiccchallenge
	// Decode serverAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for serverAddress, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_serveraddress, rawVal_serveraddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverAddress: %w", err)
	}
	decVal_serveraddress := ber.DecodeStringValue(rawVal_serveraddress)
	v.ServerAddress = decVal_serveraddress
	offset += n_serveraddress
	// Decode serverChallenge
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverChallenge")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for serverChallenge, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_serverchallenge, rawVal_serverchallenge, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverChallenge: %w", err)
	}
	v.ServerChallenge = Octet16(rawVal_serverchallenge)
	offset += n_serverchallenge
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ServerSigned1", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CtxParams1 to BER format.
func (v *CtxParams1) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CtxParams1ChoiceCtxParamsForCommonAuthentication:
		if v.CtxParamsForCommonAuthentication == nil {
			return nil, fmt.Errorf("choice CtxParams1: ctxParamsForCommonAuthentication is nil")
		}
		enc_0, err := v.CtxParamsForCommonAuthentication.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ctxParamsForCommonAuthentication: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CtxParams1", v.Choice)
	}
}

// MarshalDER encodes CtxParams1 to DER format.
func (v *CtxParams1) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CtxParams1ChoiceCtxParamsForCommonAuthentication:
		if v.CtxParamsForCommonAuthentication == nil {
			return nil, fmt.Errorf("choice CtxParams1: ctxParamsForCommonAuthentication is nil")
		}
		enc_der_0, err := v.CtxParamsForCommonAuthentication.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ctxParamsForCommonAuthentication: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CtxParams1 from BER/DER format.
func (v *CtxParams1) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CtxParams1 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CtxParams1: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CtxParams1 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CtxParams1", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CtxParams1ChoiceCtxParamsForCommonAuthentication
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ctxParamsForCommonAuthentication: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CtxParamsForCommonAuthentication
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ctxParamsForCommonAuthentication: %w", unmErr)
		}
		v.CtxParamsForCommonAuthentication = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CtxParams1 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CtxParamsForCommonAuthentication to BER format.
func (v *CtxParamsForCommonAuthentication) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MatchingId != nil {
		enc_matchingid := ber.EncodeStringTag(12, *v.MatchingId)
		enc_matchingid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_matchingid)
		children = append(children, enc_matchingid...)
	}
	enc_deviceinfo, err := v.DeviceInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding deviceInfo: %w", err)
	}
	enc_deviceinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_deviceinfo)
	children = append(children, enc_deviceinfo...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CtxParamsForCommonAuthentication to DER format.
func (v *CtxParamsForCommonAuthentication) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CtxParamsForCommonAuthentication from BER/DER format.
func (v *CtxParamsForCommonAuthentication) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CtxParamsForCommonAuthentication SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CtxParamsForCommonAuthentication", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode matchingId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_matchingid, rawVal_matchingid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding matchingId: %w", err)
				}
				decVal_matchingid := ber.DecodeStringValue(rawVal_matchingid)
				v.MatchingId = &decVal_matchingid
				offset += n_matchingid
			}
		}
	}
	// Decode deviceInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field deviceInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for deviceInfo, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_deviceinfo, rawVal_deviceinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deviceInfo: %w", err)
	}
	reconstructed_deviceinfo := ber.EncodeSequence(rawVal_deviceinfo)
	if unmErr := v.DeviceInfo.UnmarshalBER(reconstructed_deviceinfo); unmErr != nil {
		return fmt.Errorf("decoding deviceInfo: %w", unmErr)
	}
	offset += n_deviceinfo
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CtxParamsForCommonAuthentication", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AuthenticateServerResponse to BER format.
func (v *AuthenticateServerResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateServerResponseChoiceAuthenticateResponseOk:
		if v.AuthenticateResponseOk == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseOk is nil")
		}
		enc_0, err := v.AuthenticateResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_0)
		return enc_0, nil
	case AuthenticateServerResponseChoiceAuthenticateResponseError:
		if v.AuthenticateResponseError == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseError is nil")
		}
		enc_1, err := v.AuthenticateResponseError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseError: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AuthenticateServerResponse", v.Choice)
	}
}

// MarshalDER encodes AuthenticateServerResponse to DER format.
func (v *AuthenticateServerResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateServerResponseChoiceAuthenticateResponseOk:
		if v.AuthenticateResponseOk == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseOk is nil")
		}
		enc_der_0, err := v.AuthenticateResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_der_0)
		return enc_der_0, nil
	case AuthenticateServerResponseChoiceAuthenticateResponseError:
		if v.AuthenticateResponseError == nil {
			return nil, fmt.Errorf("choice AuthenticateServerResponse: authenticateResponseError is nil")
		}
		enc_der_1, err := v.AuthenticateResponseError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateResponseError: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 56, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateServerResponse from BER/DER format.
func (v *AuthenticateServerResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AuthenticateServerResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateServerResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 56 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateServerResponse CHOICE: %w: expected tag [CONTEXT 56], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateServerResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for AuthenticateServerResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AuthenticateServerResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AuthenticateServerResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateServerResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AuthenticateServerResponseChoiceAuthenticateResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateResponseOk: %w", unmErr)
		}
		v.AuthenticateResponseOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AuthenticateServerResponseChoiceAuthenticateResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateResponseError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateResponseError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateResponseError: %w", unmErr)
		}
		v.AuthenticateResponseError = &dec
	} else {
		return fmt.Errorf("unknown tag %s for AuthenticateServerResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AuthenticateResponseOk to BER format.
func (v *AuthenticateResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccsigned1, err := v.EuiccSigned1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccSigned1: %w", err)
	}
	children = append(children, enc_euiccsigned1...)
	enc_euiccsignature1 := ber.EncodeOctetString(v.EuiccSignature1)
	enc_euiccsignature1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euiccsignature1)
	children = append(children, enc_euiccsignature1...)
	enc_euicccertificate, err := v.EuiccCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCertificate: %w", err)
	}
	children = append(children, enc_euicccertificate...)
	enc_eumcertificate, err := v.EumCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding eumCertificate: %w", err)
	}
	children = append(children, enc_eumcertificate...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateResponseOk to DER format.
func (v *AuthenticateResponseOk) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateResponseOk from BER/DER format.
func (v *AuthenticateResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccSigned1
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSigned1")
	}
	// Decode nested SEQUENCE (EuiccSigned1)
	_, n_euiccsigned1, _, tlvErr_euiccsigned1 := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccsigned1 != nil {
		return fmt.Errorf("decoding euiccSigned1: %w", tlvErr_euiccsigned1)
	}
	if unmErr := v.EuiccSigned1.UnmarshalBER(content[offset : offset+n_euiccsigned1]); unmErr != nil {
		return fmt.Errorf("decoding euiccSigned1: %w", unmErr)
	}
	offset += n_euiccsigned1
	// Decode euiccSignature1
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccSignature1")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccSignature1, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euiccsignature1, rawVal_euiccsignature1, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccSignature1: %w", err)
	}
	v.EuiccSignature1 = rawVal_euiccsignature1
	offset += n_euiccsignature1
	// Decode euiccCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_euicccertificate, _, tlvErr_euicccertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_euicccertificate != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", tlvErr_euicccertificate)
	}
	if unmErr := v.EuiccCertificate.UnmarshalBER(content[offset : offset+n_euicccertificate]); unmErr != nil {
		return fmt.Errorf("decoding euiccCertificate: %w", unmErr)
	}
	offset += n_euicccertificate
	// Decode eumCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field eumCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_eumcertificate, _, tlvErr_eumcertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_eumcertificate != nil {
		return fmt.Errorf("decoding eumCertificate: %w", tlvErr_eumcertificate)
	}
	if unmErr := v.EumCertificate.UnmarshalBER(content[offset : offset+n_eumcertificate]); unmErr != nil {
		return fmt.Errorf("decoding eumCertificate: %w", unmErr)
	}
	offset += n_eumcertificate
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateResponseOk", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EuiccSigned1 to BER format.
func (v *EuiccSigned1) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_serveraddress := ber.EncodeStringTag(12, v.ServerAddress)
	enc_serveraddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_serveraddress)
	children = append(children, enc_serveraddress...)
	enc_serverchallenge := ber.EncodeOctetString([]byte(v.ServerChallenge))
	enc_serverchallenge = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_serverchallenge)
	children = append(children, enc_serverchallenge...)
	enc_euiccinfo2, err := v.EuiccInfo2.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccInfo2: %w", err)
	}
	children = append(children, enc_euiccinfo2...)
	enc_ctxparams1, err := v.CtxParams1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding ctxParams1: %w", err)
	}
	children = append(children, enc_ctxparams1...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccSigned1 to DER format.
func (v *EuiccSigned1) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccSigned1 from BER/DER format.
func (v *EuiccSigned1) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccSigned1 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccSigned1", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode serverAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for serverAddress, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_serveraddress, rawVal_serveraddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverAddress: %w", err)
	}
	decVal_serveraddress := ber.DecodeStringValue(rawVal_serveraddress)
	v.ServerAddress = decVal_serveraddress
	offset += n_serveraddress
	// Decode serverChallenge
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverChallenge")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for serverChallenge, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_serverchallenge, rawVal_serverchallenge, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverChallenge: %w", err)
	}
	v.ServerChallenge = Octet16(rawVal_serverchallenge)
	offset += n_serverchallenge
	// Decode euiccInfo2
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccInfo2")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 34 {
			return fmt.Errorf("expected tag [%s %d] for euiccInfo2, got %s", "CONTEXT", 34, reqTag_)
		}
	}
	// Decode nested SEQUENCE (EUICCInfo2)
	_, n_euiccinfo2, _, tlvErr_euiccinfo2 := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccinfo2 != nil {
		return fmt.Errorf("decoding euiccInfo2: %w", tlvErr_euiccinfo2)
	}
	if unmErr := v.EuiccInfo2.UnmarshalBER(content[offset : offset+n_euiccinfo2]); unmErr != nil {
		return fmt.Errorf("decoding euiccInfo2: %w", unmErr)
	}
	offset += n_euiccinfo2
	// Decode ctxParams1
	if offset >= len(content) {
		return fmt.Errorf("missing required field ctxParams1")
	}
	// Decode nested CHOICE (CtxParams1)
	_, n_ctxparams1, _, tlvErr_ctxparams1 := ber.DecodeTLV(content[offset:])
	if tlvErr_ctxparams1 != nil {
		return fmt.Errorf("decoding ctxParams1: %w", tlvErr_ctxparams1)
	}
	if unmErr := v.CtxParams1.UnmarshalBER(content[offset : offset+n_ctxparams1]); unmErr != nil {
		return fmt.Errorf("decoding ctxParams1: %w", unmErr)
	}
	offset += n_ctxparams1
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EuiccSigned1", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AuthenticateResponseError to BER format.
func (v *AuthenticateResponseError) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_authenticateerrorcode := ber.EncodeBigInt((v.AuthenticateErrorCode).BigInt())
	children = append(children, enc_authenticateerrorcode...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateResponseError to DER format.
func (v *AuthenticateResponseError) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateResponseError from BER/DER format.
func (v *AuthenticateResponseError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateResponseError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateResponseError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode authenticateErrorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field authenticateErrorCode")
	}
	val_authenticateerrorcode, n, err := ber.DecodeBigInt(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding authenticateErrorCode: %w", err)
	}
	var named_authenticateerrorcode AuthenticateErrorCode
	if namedErr := named_authenticateerrorcode.UnmarshalText([]byte(val_authenticateerrorcode.String())); namedErr != nil {
		return fmt.Errorf("decoding authenticateErrorCode: %w", namedErr)
	}
	v.AuthenticateErrorCode = named_authenticateerrorcode
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateResponseError", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CancelSessionRequest to BER format.
func (v *CancelSessionRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_reason := ber.EncodeBigInt((v.Reason).BigInt())
	enc_reason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_reason)
	children = append(children, enc_reason...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 65, Constructed: true}, children), nil
}

// MarshalDER encodes CancelSessionRequest to DER format.
func (v *CancelSessionRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionRequest from BER/DER format.
func (v *CancelSessionRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 65 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CancelSessionRequest: %w: expected tag [CONTEXT 65], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode reason
	if offset >= len(content) {
		return fmt.Errorf("missing required field reason")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for reason, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding reason: %w", err)
	}
	decVal_reason, intErr := ber.DecodeBigIntValue(rawVal_reason)
	if intErr != nil {
		return fmt.Errorf("decoding reason: %w", intErr)
	}
	var named_reason CancelSessionReason
	if namedErr := named_reason.UnmarshalText([]byte(decVal_reason.String())); namedErr != nil {
		return fmt.Errorf("decoding reason: %w", namedErr)
	}
	v.Reason = named_reason
	offset += n_reason
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CancelSessionRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CancelSessionResponse to BER format.
func (v *CancelSessionResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseChoiceCancelSessionResponseOk:
		if v.CancelSessionResponseOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: cancelSessionResponseOk is nil")
		}
		enc_0, err := v.CancelSessionResponseOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_0)
		return enc_0, nil
	case CancelSessionResponseChoiceCancelSessionResponseError:
		if v.CancelSessionResponseError == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: cancelSessionResponseError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.CancelSessionResponseError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CancelSessionResponse", v.Choice)
	}
}

// MarshalDER encodes CancelSessionResponse to DER format.
func (v *CancelSessionResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseChoiceCancelSessionResponseOk:
		if v.CancelSessionResponseOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponse: cancelSessionResponseOk is nil")
		}
		enc_der_0, err := v.CancelSessionResponseOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionResponse from BER/DER format.
func (v *CancelSessionResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CancelSessionResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 65 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CancelSessionResponse CHOICE: %w: expected tag [CONTEXT 65], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for CancelSessionResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CancelSessionResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CancelSessionResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CancelSessionResponseChoiceCancelSessionResponseOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CancelSessionResponseOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseOk: %w", unmErr)
		}
		v.CancelSessionResponseOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CancelSessionResponseChoiceCancelSessionResponseError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseError: %w", intErr)
		}
		var named_cancelsessionresponseerror CancelSessionResponseCancelSessionResponseErrorValue
		if namedErr := named_cancelsessionresponseerror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseError: %w", namedErr)
		}
		v.CancelSessionResponseError = &named_cancelsessionresponseerror
	} else {
		return fmt.Errorf("unknown tag %s for CancelSessionResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CancelSessionResponseOk to BER format.
func (v *CancelSessionResponseOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euicccancelsessionsigned, err := v.EuiccCancelSessionSigned.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccCancelSessionSigned: %w", err)
	}
	children = append(children, enc_euicccancelsessionsigned...)
	enc_euicccancelsessionsignature := ber.EncodeOctetString(v.EuiccCancelSessionSignature)
	enc_euicccancelsessionsignature = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_euicccancelsessionsignature)
	children = append(children, enc_euicccancelsessionsignature...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CancelSessionResponseOk to DER format.
func (v *CancelSessionResponseOk) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionResponseOk from BER/DER format.
func (v *CancelSessionResponseOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionResponseOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponseOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccCancelSessionSigned
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCancelSessionSigned")
	}
	// Decode nested SEQUENCE (EuiccCancelSessionSigned)
	_, n_euicccancelsessionsigned, _, tlvErr_euicccancelsessionsigned := ber.DecodeTLV(content[offset:])
	if tlvErr_euicccancelsessionsigned != nil {
		return fmt.Errorf("decoding euiccCancelSessionSigned: %w", tlvErr_euicccancelsessionsigned)
	}
	if unmErr := v.EuiccCancelSessionSigned.UnmarshalBER(content[offset : offset+n_euicccancelsessionsigned]); unmErr != nil {
		return fmt.Errorf("decoding euiccCancelSessionSigned: %w", unmErr)
	}
	offset += n_euicccancelsessionsigned
	// Decode euiccCancelSessionSignature
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCancelSessionSignature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for euiccCancelSessionSignature, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_euicccancelsessionsignature, rawVal_euicccancelsessionsignature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCancelSessionSignature: %w", err)
	}
	v.EuiccCancelSessionSignature = rawVal_euicccancelsessionsignature
	offset += n_euicccancelsessionsignature
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CancelSessionResponseOk", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EuiccCancelSessionSigned to BER format.
func (v *EuiccCancelSessionSigned) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_smdpoid := ber.EncodeObjectIdentifier([]uint64(v.SmdpOid))
	enc_smdpoid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_smdpoid)
	children = append(children, enc_smdpoid...)
	enc_reason := ber.EncodeBigInt((v.Reason).BigInt())
	enc_reason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_reason)
	children = append(children, enc_reason...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EuiccCancelSessionSigned to DER format.
func (v *EuiccCancelSessionSigned) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccCancelSessionSigned from BER/DER format.
func (v *EuiccCancelSessionSigned) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccCancelSessionSigned SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccCancelSessionSigned", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode smdpOid
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpOid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for smdpOid, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_smdpoid, rawVal_smdpoid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpOid: %w", err)
	}
	decVal_smdpoid, oidErr := ber.DecodeOIDValue(rawVal_smdpoid)
	if oidErr != nil {
		return fmt.Errorf("decoding smdpOid: %w", oidErr)
	}
	v.SmdpOid = runtime.ObjectIdentifier(decVal_smdpoid)
	offset += n_smdpoid
	// Decode reason
	if offset >= len(content) {
		return fmt.Errorf("missing required field reason")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for reason, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding reason: %w", err)
	}
	decVal_reason, intErr := ber.DecodeBigIntValue(rawVal_reason)
	if intErr != nil {
		return fmt.Errorf("decoding reason: %w", intErr)
	}
	var named_reason CancelSessionReason
	if namedErr := named_reason.UnmarshalText([]byte(decVal_reason.String())); namedErr != nil {
		return fmt.Errorf("decoding reason: %w", namedErr)
	}
	v.Reason = named_reason
	offset += n_reason
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EuiccCancelSessionSigned", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProfileInfoListRequest to BER format.
func (v *ProfileInfoListRequest) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SearchCriteria != nil {
		enc_searchcriteria, err := v.SearchCriteria.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding searchCriteria: %w", err)
		}
		enc_searchcriteria = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_searchcriteria)
		children = append(children, enc_searchcriteria...)
	}
	if v.TagList != nil {
		enc_taglist := ber.EncodeOctetString(v.TagList)
		enc_taglist = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 28, false, enc_taglist)
		children = append(children, enc_taglist...)
	}
	if v.IotSpecificTagList != nil {
		enc_iotspecifictaglist := ber.EncodeOctetString(v.IotSpecificTagList)
		enc_iotspecifictaglist = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 29, false, enc_iotspecifictaglist)
		children = append(children, enc_iotspecifictaglist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 45, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileInfoListRequest to DER format.
func (v *ProfileInfoListRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfoListRequest from BER/DER format.
func (v *ProfileInfoListRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInfoListRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 45 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInfoListRequest: %w: expected tag [CONTEXT 45], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode searchCriteria
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_searchcriteria, innerData_searchcriteria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding searchCriteria: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_searchcriteria ProfileInfoListRequestSearchCriteria
				if unmErr := dec_searchcriteria.UnmarshalBER(innerData_searchcriteria); unmErr != nil {
					return fmt.Errorf("decoding searchCriteria: %w", unmErr)
				}
				v.SearchCriteria = &dec_searchcriteria
				offset += n_searchcriteria
			}
		}
	}
	// Decode tagList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 28 {
				_, n_taglist, rawVal_taglist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding tagList: %w", err)
				}
				tmp_taglist := rawVal_taglist
				v.TagList = tmp_taglist
				offset += n_taglist
			}
		}
	}
	// Decode iotSpecificTagList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 29 {
				_, n_iotspecifictaglist, rawVal_iotspecifictaglist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iotSpecificTagList: %w", err)
				}
				tmp_iotspecifictaglist := rawVal_iotspecifictaglist
				v.IotSpecificTagList = tmp_iotspecifictaglist
				offset += n_iotspecifictaglist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProfileInfoListRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProfileInfoListResponse to BER format.
func (v *ProfileInfoListResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ProfileInfoListResponseChoiceProfileInfoListOk:
		if v.ProfileInfoListOk == nil {
			return nil, fmt.Errorf("choice ProfileInfoListResponse: profileInfoListOk is nil")
		}
		enc_0, err := MarshalBERProfileInfoListResponseProfileInfoListOk(v.ProfileInfoListOk)
		if err != nil {
			return nil, fmt.Errorf("encoding profileInfoListOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 45, enc_0)
		return enc_0, nil
	case ProfileInfoListResponseChoiceProfileInfoListError:
		if v.ProfileInfoListError == nil {
			return nil, fmt.Errorf("choice ProfileInfoListResponse: profileInfoListError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.ProfileInfoListError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 45, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ProfileInfoListResponse", v.Choice)
	}
}

// MarshalDER encodes ProfileInfoListResponse to DER format.
func (v *ProfileInfoListResponse) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfoListResponse from BER/DER format.
func (v *ProfileInfoListResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ProfileInfoListResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInfoListResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 45 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInfoListResponse CHOICE: %w: expected tag [CONTEXT 45], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for ProfileInfoListResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ProfileInfoListResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ProfileInfoListResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ProfileInfoListResponseChoiceProfileInfoListOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileInfoListOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERProfileInfoListResponseProfileInfoListOk(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding profileInfoListOk: %w", unmErr)
		}
		v.ProfileInfoListOk = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ProfileInfoListResponseChoiceProfileInfoListError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileInfoListError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding profileInfoListError: %w", intErr)
		}
		var named_profileinfolisterror ProfileInfoListError
		if namedErr := named_profileinfolisterror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding profileInfoListError: %w", namedErr)
		}
		v.ProfileInfoListError = &named_profileinfolisterror
	} else {
		return fmt.Errorf("unknown tag %s for ProfileInfoListResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ProfileInfo to BER format.
func (v *ProfileInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Iccid != nil {
		enc_iccid := ber.EncodeOctetString([]byte(*v.Iccid))
		enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
		children = append(children, enc_iccid...)
	}
	if v.IsdpAid != nil {
		enc_isdpaid := ber.EncodeOctetString([]byte(*v.IsdpAid))
		enc_isdpaid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_isdpaid)
		children = append(children, enc_isdpaid...)
	}
	if v.ProfileState != nil {
		enc_profilestate := ber.EncodeBigInt((*v.ProfileState).BigInt())
		enc_profilestate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 112, false, enc_profilestate)
		children = append(children, enc_profilestate...)
	}
	if v.ProfileNickname != nil {
		enc_profilenickname := ber.EncodeStringTag(12, *v.ProfileNickname)
		enc_profilenickname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_profilenickname)
		children = append(children, enc_profilenickname...)
	}
	if v.ServiceProviderName != nil {
		enc_serviceprovidername := ber.EncodeStringTag(12, *v.ServiceProviderName)
		enc_serviceprovidername = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_serviceprovidername)
		children = append(children, enc_serviceprovidername...)
	}
	if v.ProfileName != nil {
		enc_profilename := ber.EncodeStringTag(12, *v.ProfileName)
		enc_profilename = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_profilename)
		children = append(children, enc_profilename...)
	}
	if v.IconType != nil {
		enc_icontype := ber.EncodeBigInt((*v.IconType).BigInt())
		enc_icontype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_icontype)
		children = append(children, enc_icontype...)
	}
	if v.Icon != nil {
		enc_icon := ber.EncodeOctetString(v.Icon)
		enc_icon = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_icon)
		children = append(children, enc_icon...)
	}
	if v.ProfileClass != nil {
		enc_profileclass := ber.EncodeBigInt((*v.ProfileClass).BigInt())
		enc_profileclass = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_profileclass)
		children = append(children, enc_profileclass...)
	}
	if v.NotificationConfigurationInfo != nil {
		enc_notificationconfigurationinfo, err := MarshalBERProfileInfoNotificationConfigurationInfo(v.NotificationConfigurationInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding notificationConfigurationInfo: %w", err)
		}
		if v.NotificationConfigurationInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_notificationconfigurationinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_notificationconfigurationinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 22}, seqContent_)
		} else {
			enc_notificationconfigurationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, true, enc_notificationconfigurationinfo)
		}
		children = append(children, enc_notificationconfigurationinfo...)
	}
	if v.ProfileOwner != nil {
		enc_profileowner, err := v.ProfileOwner.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding profileOwner: %w", err)
		}
		enc_profileowner = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, true, enc_profileowner)
		children = append(children, enc_profileowner...)
	}
	if v.DpProprietaryData != nil {
		enc_dpproprietarydata, err := v.DpProprietaryData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dpProprietaryData: %w", err)
		}
		enc_dpproprietarydata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, true, enc_dpproprietarydata)
		children = append(children, enc_dpproprietarydata...)
	}
	if v.ProfilePolicyRules != nil {
		enc_profilepolicyrules := ber.EncodeBitString(v.ProfilePolicyRules.Bytes, (8-(v.ProfilePolicyRules.BitLength%8))%8)
		enc_profilepolicyrules = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, false, enc_profilepolicyrules)
		children = append(children, enc_profilepolicyrules...)
	}
	if v.ServiceSpecificDataStoredInEuicc != nil {
		enc_servicespecificdatastoredineuicc, err := MarshalBERVendorSpecificExtension(v.ServiceSpecificDataStoredInEuicc)
		if err != nil {
			return nil, fmt.Errorf("encoding serviceSpecificDataStoredInEuicc: %w", err)
		}
		if v.ServiceSpecificDataStoredInEuiccIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servicespecificdatastoredineuicc)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servicespecificdatastoredineuicc = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 34}, seqContent_)
		} else {
			enc_servicespecificdatastoredineuicc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 34, true, enc_servicespecificdatastoredineuicc)
		}
		children = append(children, enc_servicespecificdatastoredineuicc...)
	}
	if v.EcallIndication != nil {
		var enc_ecallindication []byte
		if v.EcallIndicationRaw_ != 0 {
			enc_ecallindication = ber.EncodeBooleanRaw(v.EcallIndicationRaw_)
		} else {
			enc_ecallindication = ber.EncodeBoolean(*v.EcallIndication)
		}
		enc_ecallindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 123, false, enc_ecallindication)
		children = append(children, enc_ecallindication...)
	}
	if v.FallbackAttribute != nil {
		var enc_fallbackattribute []byte
		if v.FallbackAttributeRaw_ != 0 {
			enc_fallbackattribute = ber.EncodeBooleanRaw(v.FallbackAttributeRaw_)
		} else {
			enc_fallbackattribute = ber.EncodeBoolean(*v.FallbackAttribute)
		}
		enc_fallbackattribute = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 38, false, enc_fallbackattribute)
		children = append(children, enc_fallbackattribute...)
	}
	if v.FallbackAllowed != nil {
		var enc_fallbackallowed []byte
		if v.FallbackAllowedRaw_ != 0 {
			enc_fallbackallowed = ber.EncodeBooleanRaw(v.FallbackAllowedRaw_)
		} else {
			enc_fallbackallowed = ber.EncodeBoolean(*v.FallbackAllowed)
		}
		enc_fallbackallowed = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 103, false, enc_fallbackallowed)
		children = append(children, enc_fallbackallowed...)
	}
	if v.IotSpecificProfileInfo != nil {
		enc_iotspecificprofileinfo, err := v.IotSpecificProfileInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding iotSpecificProfileInfo: %w", err)
		}
		enc_iotspecificprofileinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 100, true, enc_iotspecificprofileinfo)
		children = append(children, enc_iotspecificprofileinfo...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 3, Constructed: true}, children), nil
}

// MarshalDER encodes ProfileInfo to DER format.
func (v *ProfileInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.NotificationConfigurationInfoIndef_ = false
	derValue.ServiceSpecificDataStoredInEuiccIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfo from BER/DER format.
func (v *ProfileInfo) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInfo: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ProfileInfo: %w: expected tag [PRIVATE 3], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
				_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iccid: %w", err)
				}
				tmp_iccid := Iccid(rawVal_iccid)
				v.Iccid = &tmp_iccid
				offset += n_iccid
			}
		}
	}
	// Decode isdpAid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 15 {
				_, n_isdpaid, rawVal_isdpaid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding isdpAid: %w", err)
				}
				tmp_isdpaid := OctetTo16(rawVal_isdpaid)
				v.IsdpAid = &tmp_isdpaid
				offset += n_isdpaid
			}
		}
	}
	// Decode profileState
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 112 {
				_, n_profilestate, rawVal_profilestate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileState: %w", err)
				}
				decVal_profilestate, intErr := ber.DecodeBigIntValue(rawVal_profilestate)
				if intErr != nil {
					return fmt.Errorf("decoding profileState: %w", intErr)
				}
				var named_profilestate ProfileState
				if namedErr := named_profilestate.UnmarshalText([]byte(decVal_profilestate.String())); namedErr != nil {
					return fmt.Errorf("decoding profileState: %w", namedErr)
				}
				v.ProfileState = &named_profilestate
				offset += n_profilestate
			}
		}
	}
	// Decode profileNickname
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_profilenickname, rawVal_profilenickname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileNickname: %w", err)
				}
				decVal_profilenickname := ber.DecodeStringValue(rawVal_profilenickname)
				v.ProfileNickname = &decVal_profilenickname
				offset += n_profilenickname
			}
		}
	}
	// Decode serviceProviderName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_serviceprovidername, rawVal_serviceprovidername, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceProviderName: %w", err)
				}
				decVal_serviceprovidername := ber.DecodeStringValue(rawVal_serviceprovidername)
				v.ServiceProviderName = &decVal_serviceprovidername
				offset += n_serviceprovidername
			}
		}
	}
	// Decode profileName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_profilename, rawVal_profilename, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileName: %w", err)
				}
				decVal_profilename := ber.DecodeStringValue(rawVal_profilename)
				v.ProfileName = &decVal_profilename
				offset += n_profilename
			}
		}
	}
	// Decode iconType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_icontype, rawVal_icontype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iconType: %w", err)
				}
				decVal_icontype, intErr := ber.DecodeBigIntValue(rawVal_icontype)
				if intErr != nil {
					return fmt.Errorf("decoding iconType: %w", intErr)
				}
				var named_icontype IconType
				if namedErr := named_icontype.UnmarshalText([]byte(decVal_icontype.String())); namedErr != nil {
					return fmt.Errorf("decoding iconType: %w", namedErr)
				}
				v.IconType = &named_icontype
				offset += n_icontype
			}
		}
	}
	// Decode icon
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_icon, rawVal_icon, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding icon: %w", err)
				}
				tmp_icon := rawVal_icon
				v.Icon = tmp_icon
				offset += n_icon
			}
		}
	}
	// Decode profileClass
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_profileclass, rawVal_profileclass, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileClass: %w", err)
				}
				decVal_profileclass, intErr := ber.DecodeBigIntValue(rawVal_profileclass)
				if intErr != nil {
					return fmt.Errorf("decoding profileClass: %w", intErr)
				}
				var named_profileclass ProfileClass
				if namedErr := named_profileclass.UnmarshalText([]byte(decVal_profileclass.String())); namedErr != nil {
					return fmt.Errorf("decoding profileClass: %w", namedErr)
				}
				v.ProfileClass = &named_profileclass
				offset += n_profileclass
			}
		}
	}
	// Decode notificationConfigurationInfo
	v.NotificationConfigurationInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				_, n_notificationconfigurationinfo, rawVal_notificationconfigurationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", err)
				}
				reconstructed_notificationconfigurationinfo := ber.EncodeSequence(rawVal_notificationconfigurationinfo)
				dec_notificationconfigurationinfo, unmErr := UnmarshalBERProfileInfoNotificationConfigurationInfo(reconstructed_notificationconfigurationinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding notificationConfigurationInfo: %w", unmErr)
				}
				v.NotificationConfigurationInfo = dec_notificationconfigurationinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.NotificationConfigurationInfoIndef_ = true
					}
				}
				offset += n_notificationconfigurationinfo
			}
		}
	}
	// Decode profileOwner
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				_, n_profileowner, rawVal_profileowner, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profileOwner: %w", err)
				}
				reconstructed_profileowner := ber.EncodeSequence(rawVal_profileowner)
				var dec_profileowner OperatorId
				if unmErr := dec_profileowner.UnmarshalBER(reconstructed_profileowner); unmErr != nil {
					return fmt.Errorf("decoding profileOwner: %w", unmErr)
				}
				v.ProfileOwner = &dec_profileowner
				offset += n_profileowner
			}
		}
	}
	// Decode dpProprietaryData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				_, n_dpproprietarydata, rawVal_dpproprietarydata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dpProprietaryData: %w", err)
				}
				reconstructed_dpproprietarydata := ber.EncodeSequence(rawVal_dpproprietarydata)
				var dec_dpproprietarydata DpProprietaryData
				if unmErr := dec_dpproprietarydata.UnmarshalBER(reconstructed_dpproprietarydata); unmErr != nil {
					return fmt.Errorf("decoding dpProprietaryData: %w", unmErr)
				}
				v.DpProprietaryData = &dec_dpproprietarydata
				offset += n_dpproprietarydata
			}
		}
	}
	// Decode profilePolicyRules
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				_, n_profilepolicyrules, rawVal_profilepolicyrules, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", err)
				}
				bsBytes_profilepolicyrules, bsUnused_profilepolicyrules, bsErr := ber.DecodeBitStringValue(rawVal_profilepolicyrules)
				if bsErr != nil {
					return fmt.Errorf("decoding profilePolicyRules: %w", bsErr)
				}
				tmp_profilepolicyrules := runtime.BitString{Bytes: bsBytes_profilepolicyrules, BitLength: len(bsBytes_profilepolicyrules)*8 - bsUnused_profilepolicyrules}
				v.ProfilePolicyRules = &tmp_profilepolicyrules
				offset += n_profilepolicyrules
			}
		}
	}
	// Decode serviceSpecificDataStoredInEuicc
	v.ServiceSpecificDataStoredInEuiccIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 34 {
				_, n_servicespecificdatastoredineuicc, rawVal_servicespecificdatastoredineuicc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", err)
				}
				reconstructed_servicespecificdatastoredineuicc := ber.EncodeSequence(rawVal_servicespecificdatastoredineuicc)
				dec_servicespecificdatastoredineuicc, unmErr := UnmarshalBERVendorSpecificExtension(reconstructed_servicespecificdatastoredineuicc)
				if unmErr != nil {
					return fmt.Errorf("decoding serviceSpecificDataStoredInEuicc: %w", unmErr)
				}
				v.ServiceSpecificDataStoredInEuicc = dec_servicespecificdatastoredineuicc
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServiceSpecificDataStoredInEuiccIndef_ = true
					}
				}
				offset += n_servicespecificdatastoredineuicc
			}
		}
	}
	// Decode ecallIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 123 {
				_, n_ecallindication, rawVal_ecallindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ecallIndication: %w", err)
				}
				decVal_ecallindication, boolErr := ber.DecodeBooleanValue(rawVal_ecallindication)
				if boolErr != nil {
					return fmt.Errorf("decoding ecallIndication: %w", boolErr)
				}
				if len(rawVal_ecallindication) == 1 {
					v.EcallIndicationRaw_ = rawVal_ecallindication[0]
				}
				v.EcallIndication = &decVal_ecallindication
				offset += n_ecallindication
			}
		}
	}
	// Decode fallbackAttribute
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 38 {
				_, n_fallbackattribute, rawVal_fallbackattribute, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAttribute: %w", err)
				}
				decVal_fallbackattribute, boolErr := ber.DecodeBooleanValue(rawVal_fallbackattribute)
				if boolErr != nil {
					return fmt.Errorf("decoding fallbackAttribute: %w", boolErr)
				}
				if len(rawVal_fallbackattribute) == 1 {
					v.FallbackAttributeRaw_ = rawVal_fallbackattribute[0]
				}
				v.FallbackAttribute = &decVal_fallbackattribute
				offset += n_fallbackattribute
			}
		}
	}
	// Decode fallbackAllowed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 103 {
				_, n_fallbackallowed, rawVal_fallbackallowed, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", err)
				}
				decVal_fallbackallowed, boolErr := ber.DecodeBooleanValue(rawVal_fallbackallowed)
				if boolErr != nil {
					return fmt.Errorf("decoding fallbackAllowed: %w", boolErr)
				}
				if len(rawVal_fallbackallowed) == 1 {
					v.FallbackAllowedRaw_ = rawVal_fallbackallowed[0]
				}
				v.FallbackAllowed = &decVal_fallbackallowed
				offset += n_fallbackallowed
			}
		}
	}
	// Decode iotSpecificProfileInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 100 {
				_, n_iotspecificprofileinfo, rawVal_iotspecificprofileinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding iotSpecificProfileInfo: %w", err)
				}
				reconstructed_iotspecificprofileinfo := ber.EncodeSequence(rawVal_iotspecificprofileinfo)
				var dec_iotspecificprofileinfo ProfileInfoIotSpecificProfileInfo
				if unmErr := dec_iotspecificprofileinfo.UnmarshalBER(reconstructed_iotspecificprofileinfo); unmErr != nil {
					return fmt.Errorf("decoding iotSpecificProfileInfo: %w", unmErr)
				}
				v.IotSpecificProfileInfo = &dec_iotspecificprofileinfo
				offset += n_iotspecificprofileinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProfileInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EnableProfileRequest to BER format.
func (v *EnableProfileRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profileidentifier, err := v.ProfileIdentifier.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding profileIdentifier: %w", err)
	}
	enc_profileidentifier = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_profileidentifier)
	children = append(children, enc_profileidentifier...)
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 49, Constructed: true}, children), nil
}

// MarshalDER encodes EnableProfileRequest to DER format.
func (v *EnableProfileRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EnableProfileRequest from BER/DER format.
func (v *EnableProfileRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EnableProfileRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 49 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EnableProfileRequest: %w: expected tag [CONTEXT 49], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EnableProfileRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileIdentifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileIdentifier")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for profileIdentifier, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_profileidentifier, innerData_profileidentifier, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileIdentifier: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.ProfileIdentifier.UnmarshalBER(innerData_profileidentifier); unmErr != nil {
		return fmt.Errorf("decoding profileIdentifier: %w", unmErr)
	}
	offset += n_profileidentifier
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EnableProfileRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EnableProfileResponse to BER format.
func (v *EnableProfileResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_enableresult := ber.EncodeBigInt((v.EnableResult).BigInt())
	enc_enableresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_enableresult)
	children = append(children, enc_enableresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 49, Constructed: true}, children), nil
}

// MarshalDER encodes EnableProfileResponse to DER format.
func (v *EnableProfileResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EnableProfileResponse from BER/DER format.
func (v *EnableProfileResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EnableProfileResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 49 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EnableProfileResponse: %w: expected tag [CONTEXT 49], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EnableProfileResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode enableResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field enableResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for enableResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_enableresult, rawVal_enableresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding enableResult: %w", err)
	}
	decVal_enableresult, intErr := ber.DecodeBigIntValue(rawVal_enableresult)
	if intErr != nil {
		return fmt.Errorf("decoding enableResult: %w", intErr)
	}
	var named_enableresult EnableProfileResponseEnableResultValue
	if namedErr := named_enableresult.UnmarshalText([]byte(decVal_enableresult.String())); namedErr != nil {
		return fmt.Errorf("decoding enableResult: %w", namedErr)
	}
	v.EnableResult = named_enableresult
	offset += n_enableresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EnableProfileResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DisableProfileRequest to BER format.
func (v *DisableProfileRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_profileidentifier, err := v.ProfileIdentifier.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding profileIdentifier: %w", err)
	}
	enc_profileidentifier = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_profileidentifier)
	children = append(children, enc_profileidentifier...)
	var enc_refreshflag []byte
	if v.RefreshFlagRaw_ != 0 {
		enc_refreshflag = ber.EncodeBooleanRaw(v.RefreshFlagRaw_)
	} else {
		enc_refreshflag = ber.EncodeBoolean(v.RefreshFlag)
	}
	enc_refreshflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_refreshflag)
	children = append(children, enc_refreshflag...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 50, Constructed: true}, children), nil
}

// MarshalDER encodes DisableProfileRequest to DER format.
func (v *DisableProfileRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DisableProfileRequest from BER/DER format.
func (v *DisableProfileRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding DisableProfileRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 50 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DisableProfileRequest: %w: expected tag [CONTEXT 50], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DisableProfileRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode profileIdentifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileIdentifier")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for profileIdentifier, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_profileidentifier, innerData_profileidentifier, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileIdentifier: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.ProfileIdentifier.UnmarshalBER(innerData_profileidentifier); unmErr != nil {
		return fmt.Errorf("decoding profileIdentifier: %w", unmErr)
	}
	offset += n_profileidentifier
	// Decode refreshFlag
	if offset >= len(content) {
		return fmt.Errorf("missing required field refreshFlag")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for refreshFlag, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_refreshflag, rawVal_refreshflag, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding refreshFlag: %w", err)
	}
	decVal_refreshflag, boolErr := ber.DecodeBooleanValue(rawVal_refreshflag)
	if boolErr != nil {
		return fmt.Errorf("decoding refreshFlag: %w", boolErr)
	}
	if len(rawVal_refreshflag) == 1 {
		v.RefreshFlagRaw_ = rawVal_refreshflag[0]
	}
	v.RefreshFlag = decVal_refreshflag
	offset += n_refreshflag
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DisableProfileRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DisableProfileResponse to BER format.
func (v *DisableProfileResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_disableresult := ber.EncodeBigInt((v.DisableResult).BigInt())
	enc_disableresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_disableresult)
	children = append(children, enc_disableresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 50, Constructed: true}, children), nil
}

// MarshalDER encodes DisableProfileResponse to DER format.
func (v *DisableProfileResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DisableProfileResponse from BER/DER format.
func (v *DisableProfileResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding DisableProfileResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 50 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DisableProfileResponse: %w: expected tag [CONTEXT 50], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DisableProfileResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode disableResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field disableResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for disableResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_disableresult, rawVal_disableresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding disableResult: %w", err)
	}
	decVal_disableresult, intErr := ber.DecodeBigIntValue(rawVal_disableresult)
	if intErr != nil {
		return fmt.Errorf("decoding disableResult: %w", intErr)
	}
	var named_disableresult DisableProfileResponseDisableResultValue
	if namedErr := named_disableresult.UnmarshalText([]byte(decVal_disableresult.String())); namedErr != nil {
		return fmt.Errorf("decoding disableResult: %w", namedErr)
	}
	v.DisableResult = named_disableresult
	offset += n_disableresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DisableProfileResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeleteProfileRequest to BER format.
func (v *DeleteProfileRequest) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DeleteProfileRequestChoiceIsdpAid:
		enc_0 := ber.EncodeOctetString([]byte(*v.IsdpAid))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 51, enc_0)
		return enc_0, nil
	case DeleteProfileRequestChoiceIccid:
		enc_1 := ber.EncodeOctetString([]byte(*v.Iccid))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 51, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DeleteProfileRequest", v.Choice)
	}
}

// MarshalDER encodes DeleteProfileRequest to DER format.
func (v *DeleteProfileRequest) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes DeleteProfileRequest from BER/DER format.
func (v *DeleteProfileRequest) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for DeleteProfileRequest CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeleteProfileRequest CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 51 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DeleteProfileRequest CHOICE: %w: expected tag [CONTEXT 51], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeleteProfileRequest", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for DeleteProfileRequest CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DeleteProfileRequest: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DeleteProfileRequest CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DeleteProfileRequest", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 15 {
		v.Choice = DeleteProfileRequestChoiceIsdpAid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdpAid: %w", tlvErr)
		}
		tmp := OctetTo16(rawVal)
		v.IsdpAid = &tmp
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
		v.Choice = DeleteProfileRequestChoiceIccid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding iccid: %w", tlvErr)
		}
		tmp := Iccid(rawVal)
		v.Iccid = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for DeleteProfileRequest CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes DeleteProfileResponse to BER format.
func (v *DeleteProfileResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_deleteresult := ber.EncodeBigInt((v.DeleteResult).BigInt())
	enc_deleteresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_deleteresult)
	children = append(children, enc_deleteresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 51, Constructed: true}, children), nil
}

// MarshalDER encodes DeleteProfileResponse to DER format.
func (v *DeleteProfileResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeleteProfileResponse from BER/DER format.
func (v *DeleteProfileResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeleteProfileResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 51 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DeleteProfileResponse: %w: expected tag [CONTEXT 51], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeleteProfileResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deleteResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field deleteResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for deleteResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_deleteresult, rawVal_deleteresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deleteResult: %w", err)
	}
	decVal_deleteresult, intErr := ber.DecodeBigIntValue(rawVal_deleteresult)
	if intErr != nil {
		return fmt.Errorf("decoding deleteResult: %w", intErr)
	}
	var named_deleteresult DeleteProfileResponseDeleteResultValue
	if namedErr := named_deleteresult.UnmarshalText([]byte(decVal_deleteresult.String())); namedErr != nil {
		return fmt.Errorf("decoding deleteResult: %w", namedErr)
	}
	v.DeleteResult = named_deleteresult
	offset += n_deleteresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeleteProfileResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EuiccMemoryResetRequest to BER format.
func (v *EuiccMemoryResetRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_resetoptions := ber.EncodeBitString(v.ResetOptions.Bytes, (8-(v.ResetOptions.BitLength%8))%8)
	enc_resetoptions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_resetoptions)
	children = append(children, enc_resetoptions...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 52, Constructed: true}, children), nil
}

// MarshalDER encodes EuiccMemoryResetRequest to DER format.
func (v *EuiccMemoryResetRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccMemoryResetRequest from BER/DER format.
func (v *EuiccMemoryResetRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccMemoryResetRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 52 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccMemoryResetRequest: %w: expected tag [CONTEXT 52], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccMemoryResetRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode resetOptions
	if offset >= len(content) {
		return fmt.Errorf("missing required field resetOptions")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for resetOptions, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_resetoptions, rawVal_resetoptions, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding resetOptions: %w", err)
	}
	bsBytes_resetoptions, bsUnused_resetoptions, bsErr := ber.DecodeBitStringValue(rawVal_resetoptions)
	if bsErr != nil {
		return fmt.Errorf("decoding resetOptions: %w", bsErr)
	}
	v.ResetOptions = runtime.BitString{Bytes: bsBytes_resetoptions, BitLength: len(bsBytes_resetoptions)*8 - bsUnused_resetoptions}
	offset += n_resetoptions
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EuiccMemoryResetRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EuiccMemoryResetResponse to BER format.
func (v *EuiccMemoryResetResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_resetresult := ber.EncodeBigInt((v.ResetResult).BigInt())
	enc_resetresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_resetresult)
	children = append(children, enc_resetresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 52, Constructed: true}, children), nil
}

// MarshalDER encodes EuiccMemoryResetResponse to DER format.
func (v *EuiccMemoryResetResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EuiccMemoryResetResponse from BER/DER format.
func (v *EuiccMemoryResetResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding EuiccMemoryResetResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 52 || !decodedTag.Constructed {
		return fmt.Errorf("decoding EuiccMemoryResetResponse: %w: expected tag [CONTEXT 52], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EuiccMemoryResetResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode resetResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field resetResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for resetResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_resetresult, rawVal_resetresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding resetResult: %w", err)
	}
	decVal_resetresult, intErr := ber.DecodeBigIntValue(rawVal_resetresult)
	if intErr != nil {
		return fmt.Errorf("decoding resetResult: %w", intErr)
	}
	var named_resetresult EuiccMemoryResetResponseResetResultValue
	if namedErr := named_resetresult.UnmarshalText([]byte(decVal_resetresult.String())); namedErr != nil {
		return fmt.Errorf("decoding resetResult: %w", namedErr)
	}
	v.ResetResult = named_resetresult
	offset += n_resetresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EuiccMemoryResetResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetEuiccDataRequest to BER format.
func (v *GetEuiccDataRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_taglist := ber.EncodeOctetString([]byte(v.TagList))
	enc_taglist = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 28, false, enc_taglist)
	children = append(children, enc_taglist...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 62, Constructed: true}, children), nil
}

// MarshalDER encodes GetEuiccDataRequest to DER format.
func (v *GetEuiccDataRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEuiccDataRequest from BER/DER format.
func (v *GetEuiccDataRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEuiccDataRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 62 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEuiccDataRequest: %w: expected tag [CONTEXT 62], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEuiccDataRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode tagList
	if offset >= len(content) {
		return fmt.Errorf("missing required field tagList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 28 {
			return fmt.Errorf("expected tag [%s %d] for tagList, got %s", "APPLICATION", 28, reqTag_)
		}
	}
	_, n_taglist, rawVal_taglist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding tagList: %w", err)
	}
	v.TagList = Octet1(rawVal_taglist)
	offset += n_taglist
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetEuiccDataRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetEuiccDataResponse to BER format.
func (v *GetEuiccDataResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eidvalue := ber.EncodeOctetString([]byte(v.EidValue))
	enc_eidvalue = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_eidvalue)
	children = append(children, enc_eidvalue...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 62, Constructed: true}, children), nil
}

// MarshalDER encodes GetEuiccDataResponse to DER format.
func (v *GetEuiccDataResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetEuiccDataResponse from BER/DER format.
func (v *GetEuiccDataResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetEuiccDataResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 62 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetEuiccDataResponse: %w: expected tag [CONTEXT 62], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetEuiccDataResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eidValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field eidValue")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for eidValue, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_eidvalue, rawVal_eidvalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eidValue: %w", err)
	}
	v.EidValue = Octet16(rawVal_eidvalue)
	offset += n_eidvalue
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetEuiccDataResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SetNicknameRequest to BER format.
func (v *SetNicknameRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_iccid := ber.EncodeOctetString([]byte(v.Iccid))
	enc_iccid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_iccid)
	children = append(children, enc_iccid...)
	enc_profilenickname := ber.EncodeStringTag(12, v.ProfileNickname)
	enc_profilenickname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_profilenickname)
	children = append(children, enc_profilenickname...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 41, Constructed: true}, children), nil
}

// MarshalDER encodes SetNicknameRequest to DER format.
func (v *SetNicknameRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SetNicknameRequest from BER/DER format.
func (v *SetNicknameRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetNicknameRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 41 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SetNicknameRequest: %w: expected tag [CONTEXT 41], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetNicknameRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode iccid
	if offset >= len(content) {
		return fmt.Errorf("missing required field iccid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 26 {
			return fmt.Errorf("expected tag [%s %d] for iccid, got %s", "APPLICATION", 26, reqTag_)
		}
	}
	_, n_iccid, rawVal_iccid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding iccid: %w", err)
	}
	v.Iccid = Iccid(rawVal_iccid)
	offset += n_iccid
	// Decode profileNickname
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileNickname")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 16 {
			return fmt.Errorf("expected tag [%s %d] for profileNickname, got %s", "CONTEXT", 16, reqTag_)
		}
	}
	_, n_profilenickname, rawVal_profilenickname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding profileNickname: %w", err)
	}
	decVal_profilenickname := ber.DecodeStringValue(rawVal_profilenickname)
	v.ProfileNickname = decVal_profilenickname
	offset += n_profilenickname
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SetNicknameRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SetNicknameResponse to BER format.
func (v *SetNicknameResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_setnicknameresult := ber.EncodeBigInt((v.SetNicknameResult).BigInt())
	enc_setnicknameresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_setnicknameresult)
	children = append(children, enc_setnicknameresult...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 41, Constructed: true}, children), nil
}

// MarshalDER encodes SetNicknameResponse to DER format.
func (v *SetNicknameResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SetNicknameResponse from BER/DER format.
func (v *SetNicknameResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetNicknameResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 41 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SetNicknameResponse: %w: expected tag [CONTEXT 41], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetNicknameResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode setNicknameResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field setNicknameResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for setNicknameResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_setnicknameresult, rawVal_setnicknameresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding setNicknameResult: %w", err)
	}
	decVal_setnicknameresult, intErr := ber.DecodeBigIntValue(rawVal_setnicknameresult)
	if intErr != nil {
		return fmt.Errorf("decoding setNicknameResult: %w", intErr)
	}
	var named_setnicknameresult SetNicknameResponseSetNicknameResultValue
	if namedErr := named_setnicknameresult.UnmarshalText([]byte(decVal_setnicknameresult.String())); namedErr != nil {
		return fmt.Errorf("decoding setNicknameResult: %w", namedErr)
	}
	v.SetNicknameResult = named_setnicknameresult
	offset += n_setnicknameresult
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SetNicknameResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetRatRequest to BER format.
func (v *GetRatRequest) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 67, Constructed: true}, children), nil
}

// MarshalDER encodes GetRatRequest to DER format.
func (v *GetRatRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetRatRequest from BER/DER format.
func (v *GetRatRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetRatRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 67 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetRatRequest: %w: expected tag [CONTEXT 67], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetRatRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetRatRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetRatResponse to BER format.
func (v *GetRatResponse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_rat, err := MarshalBERRulesAuthorisationTable(v.Rat)
	if err != nil {
		return nil, fmt.Errorf("encoding rat: %w", err)
	}
	if v.RatIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_rat)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_rat = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_rat = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_rat)
	}
	children = append(children, enc_rat...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 67, Constructed: true}, children), nil
}

// MarshalDER encodes GetRatResponse to DER format.
func (v *GetRatResponse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RatIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes GetRatResponse from BER/DER format.
func (v *GetRatResponse) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetRatResponse: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 67 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetRatResponse: %w: expected tag [CONTEXT 67], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetRatResponse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rat
	if offset >= len(content) {
		return fmt.Errorf("missing required field rat")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for rat, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.RatIndef_ = false
	_, n_rat, rawVal_rat, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rat: %w", err)
	}
	reconstructed_rat := ber.EncodeSequence(rawVal_rat)
	dec_rat, unmErr := UnmarshalBERRulesAuthorisationTable(reconstructed_rat)
	if unmErr != nil {
		return fmt.Errorf("decoding rat: %w", unmErr)
	}
	v.Rat = dec_rat
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.RatIndef_ = true
		}
	}
	offset += n_rat
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetRatResponse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERRulesAuthorisationTable encodes a RulesAuthorisationTable list to BER.
func MarshalBERRulesAuthorisationTable(list RulesAuthorisationTable) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERRulesAuthorisationTable decodes a RulesAuthorisationTable list from BER.
func UnmarshalBERRulesAuthorisationTable(data []byte) (RulesAuthorisationTable, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RulesAuthorisationTable: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RulesAuthorisationTable", Cause: ber.ErrExtraData}
	}
	var result RulesAuthorisationTable
	offset := 0
	for offset < len(content) {
		var elem ProfilePolicyAuthorisationRule
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ProfilePolicyAuthorisationRule to BER format.
func (v *ProfilePolicyAuthorisationRule) MarshalBER() ([]byte, error) {
	var children []byte
	enc_pprids := ber.EncodeBitString(v.PprIds.Bytes, (8-(v.PprIds.BitLength%8))%8)
	enc_pprids = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_pprids)
	children = append(children, enc_pprids...)
	enc_allowedoperators, err := MarshalBERProfilePolicyAuthorisationRuleAllowedOperators(v.AllowedOperators)
	if err != nil {
		return nil, fmt.Errorf("encoding allowedOperators: %w", err)
	}
	if v.AllowedOperatorsIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_allowedoperators)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_allowedoperators = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
	} else {
		enc_allowedoperators = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_allowedoperators)
	}
	children = append(children, enc_allowedoperators...)
	enc_pprflags := ber.EncodeBitString(v.PprFlags.Bytes, (8-(v.PprFlags.BitLength%8))%8)
	enc_pprflags = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_pprflags)
	children = append(children, enc_pprflags...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ProfilePolicyAuthorisationRule to DER format.
func (v *ProfilePolicyAuthorisationRule) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.AllowedOperatorsIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfilePolicyAuthorisationRule from BER/DER format.
func (v *ProfilePolicyAuthorisationRule) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfilePolicyAuthorisationRule SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfilePolicyAuthorisationRule", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode pprIds
	if offset >= len(content) {
		return fmt.Errorf("missing required field pprIds")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for pprIds, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_pprids, rawVal_pprids, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding pprIds: %w", err)
	}
	bsBytes_pprids, bsUnused_pprids, bsErr := ber.DecodeBitStringValue(rawVal_pprids)
	if bsErr != nil {
		return fmt.Errorf("decoding pprIds: %w", bsErr)
	}
	v.PprIds = runtime.BitString{Bytes: bsBytes_pprids, BitLength: len(bsBytes_pprids)*8 - bsUnused_pprids}
	offset += n_pprids
	// Decode allowedOperators
	if offset >= len(content) {
		return fmt.Errorf("missing required field allowedOperators")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for allowedOperators, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	v.AllowedOperatorsIndef_ = false
	_, n_allowedoperators, rawVal_allowedoperators, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding allowedOperators: %w", err)
	}
	reconstructed_allowedoperators := ber.EncodeSequence(rawVal_allowedoperators)
	dec_allowedoperators, unmErr := UnmarshalBERProfilePolicyAuthorisationRuleAllowedOperators(reconstructed_allowedoperators)
	if unmErr != nil {
		return fmt.Errorf("decoding allowedOperators: %w", unmErr)
	}
	v.AllowedOperators = dec_allowedoperators
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.AllowedOperatorsIndef_ = true
		}
	}
	offset += n_allowedoperators
	// Decode pprFlags
	if offset >= len(content) {
		return fmt.Errorf("missing required field pprFlags")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for pprFlags, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_pprflags, rawVal_pprflags, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding pprFlags: %w", err)
	}
	bsBytes_pprflags, bsUnused_pprflags, bsErr := ber.DecodeBitStringValue(rawVal_pprflags)
	if bsErr != nil {
		return fmt.Errorf("decoding pprFlags: %w", bsErr)
	}
	v.PprFlags = runtime.BitString{Bytes: bsBytes_pprflags, BitLength: len(bsBytes_pprflags)*8 - bsUnused_pprflags}
	offset += n_pprflags
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProfilePolicyAuthorisationRule", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RemoteProfileProvisioningRequest to BER format.
func (v *RemoteProfileProvisioningRequest) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RemoteProfileProvisioningRequestChoiceInitiateAuthenticationRequest:
		if v.InitiateAuthenticationRequest == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: initiateAuthenticationRequest is nil")
		}
		enc_0, err := v.InitiateAuthenticationRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationRequest: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		return enc_0, nil
	case RemoteProfileProvisioningRequestChoiceAuthenticateClientRequest:
		if v.AuthenticateClientRequest == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: authenticateClientRequest is nil")
		}
		enc_1, err := v.AuthenticateClientRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientRequest: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		return enc_1, nil
	case RemoteProfileProvisioningRequestChoiceGetBoundProfilePackageRequest:
		if v.GetBoundProfilePackageRequest == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: getBoundProfilePackageRequest is nil")
		}
		enc_2, err := v.GetBoundProfilePackageRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageRequest: %w", err)
		}
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		return enc_2, nil
	case RemoteProfileProvisioningRequestChoiceCancelSessionRequestEs9:
		if v.CancelSessionRequestEs9 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: cancelSessionRequestEs9 is nil")
		}
		enc_3, err := v.CancelSessionRequestEs9.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionRequestEs9: %w", err)
		}
		enc_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_3)
		return enc_3, nil
	case RemoteProfileProvisioningRequestChoiceHandleNotification:
		if v.HandleNotification == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: handleNotification is nil")
		}
		enc_4, err := v.HandleNotification.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding handleNotification: %w", err)
		}
		enc_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_4)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RemoteProfileProvisioningRequest", v.Choice)
	}
}

// MarshalDER encodes RemoteProfileProvisioningRequest to DER format.
func (v *RemoteProfileProvisioningRequest) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case RemoteProfileProvisioningRequestChoiceInitiateAuthenticationRequest:
		if v.InitiateAuthenticationRequest == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: initiateAuthenticationRequest is nil")
		}
		enc_der_0, err := v.InitiateAuthenticationRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationRequest: %w", err)
		}
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_0)
		return enc_der_0, nil
	case RemoteProfileProvisioningRequestChoiceAuthenticateClientRequest:
		if v.AuthenticateClientRequest == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: authenticateClientRequest is nil")
		}
		enc_der_1, err := v.AuthenticateClientRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientRequest: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		return enc_der_1, nil
	case RemoteProfileProvisioningRequestChoiceGetBoundProfilePackageRequest:
		if v.GetBoundProfilePackageRequest == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: getBoundProfilePackageRequest is nil")
		}
		enc_der_2, err := v.GetBoundProfilePackageRequest.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageRequest: %w", err)
		}
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		return enc_der_2, nil
	case RemoteProfileProvisioningRequestChoiceCancelSessionRequestEs9:
		if v.CancelSessionRequestEs9 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: cancelSessionRequestEs9 is nil")
		}
		enc_der_3, err := v.CancelSessionRequestEs9.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionRequestEs9: %w", err)
		}
		enc_der_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_3)
		return enc_der_3, nil
	case RemoteProfileProvisioningRequestChoiceHandleNotification:
		if v.HandleNotification == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningRequest: handleNotification is nil")
		}
		enc_der_4, err := v.HandleNotification.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding handleNotification: %w", err)
		}
		enc_der_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_4)
		return enc_der_4, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes RemoteProfileProvisioningRequest from BER/DER format.
func (v *RemoteProfileProvisioningRequest) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RemoteProfileProvisioningRequest CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RemoteProfileProvisioningRequest CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 2 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RemoteProfileProvisioningRequest CHOICE: %w: expected tag [CONTEXT 2], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RemoteProfileProvisioningRequest", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for RemoteProfileProvisioningRequest CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RemoteProfileProvisioningRequest: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RemoteProfileProvisioningRequest CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RemoteProfileProvisioningRequest", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 57 {
		v.Choice = RemoteProfileProvisioningRequestChoiceInitiateAuthenticationRequest
		var dec InitiateAuthenticationRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationRequest: %w", unmErr)
		}
		v.InitiateAuthenticationRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 59 {
		v.Choice = RemoteProfileProvisioningRequestChoiceAuthenticateClientRequest
		var dec AuthenticateClientRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientRequest: %w", unmErr)
		}
		v.AuthenticateClientRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 58 {
		v.Choice = RemoteProfileProvisioningRequestChoiceGetBoundProfilePackageRequest
		var dec GetBoundProfilePackageRequest
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageRequest: %w", unmErr)
		}
		v.GetBoundProfilePackageRequest = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 65 {
		v.Choice = RemoteProfileProvisioningRequestChoiceCancelSessionRequestEs9
		var dec CancelSessionRequestEs9
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionRequestEs9: %w", unmErr)
		}
		v.CancelSessionRequestEs9 = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 61 {
		v.Choice = RemoteProfileProvisioningRequestChoiceHandleNotification
		var dec HandleNotification
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding handleNotification: %w", unmErr)
		}
		v.HandleNotification = &dec
	} else {
		return fmt.Errorf("unknown tag %s for RemoteProfileProvisioningRequest CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes RemoteProfileProvisioningResponse to BER format.
func (v *RemoteProfileProvisioningResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RemoteProfileProvisioningResponseChoiceInitiateAuthenticationResponse:
		if v.InitiateAuthenticationResponse == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: initiateAuthenticationResponse is nil")
		}
		enc_0, err := v.InitiateAuthenticationResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationResponse: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		return enc_0, nil
	case RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs9:
		if v.AuthenticateClientResponseEs9 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: authenticateClientResponseEs9 is nil")
		}
		enc_1, err := v.AuthenticateClientResponseEs9.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientResponseEs9: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		return enc_1, nil
	case RemoteProfileProvisioningResponseChoiceGetBoundProfilePackageResponse:
		if v.GetBoundProfilePackageResponse == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: getBoundProfilePackageResponse is nil")
		}
		enc_2, err := v.GetBoundProfilePackageResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageResponse: %w", err)
		}
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		return enc_2, nil
	case RemoteProfileProvisioningResponseChoiceCancelSessionResponseEs9:
		if v.CancelSessionResponseEs9 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: cancelSessionResponseEs9 is nil")
		}
		enc_3, err := v.CancelSessionResponseEs9.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseEs9: %w", err)
		}
		enc_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_3)
		return enc_3, nil
	case RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs11:
		if v.AuthenticateClientResponseEs11 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: authenticateClientResponseEs11 is nil")
		}
		enc_4, err := v.AuthenticateClientResponseEs11.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientResponseEs11: %w", err)
		}
		enc_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_4)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RemoteProfileProvisioningResponse", v.Choice)
	}
}

// MarshalDER encodes RemoteProfileProvisioningResponse to DER format.
func (v *RemoteProfileProvisioningResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case RemoteProfileProvisioningResponseChoiceInitiateAuthenticationResponse:
		if v.InitiateAuthenticationResponse == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: initiateAuthenticationResponse is nil")
		}
		enc_der_0, err := v.InitiateAuthenticationResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationResponse: %w", err)
		}
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_0)
		return enc_der_0, nil
	case RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs9:
		if v.AuthenticateClientResponseEs9 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: authenticateClientResponseEs9 is nil")
		}
		enc_der_1, err := v.AuthenticateClientResponseEs9.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientResponseEs9: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		return enc_der_1, nil
	case RemoteProfileProvisioningResponseChoiceGetBoundProfilePackageResponse:
		if v.GetBoundProfilePackageResponse == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: getBoundProfilePackageResponse is nil")
		}
		enc_der_2, err := v.GetBoundProfilePackageResponse.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageResponse: %w", err)
		}
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		return enc_der_2, nil
	case RemoteProfileProvisioningResponseChoiceCancelSessionResponseEs9:
		if v.CancelSessionResponseEs9 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: cancelSessionResponseEs9 is nil")
		}
		enc_der_3, err := v.CancelSessionResponseEs9.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionResponseEs9: %w", err)
		}
		enc_der_3 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_3)
		return enc_der_3, nil
	case RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs11:
		if v.AuthenticateClientResponseEs11 == nil {
			return nil, fmt.Errorf("choice RemoteProfileProvisioningResponse: authenticateClientResponseEs11 is nil")
		}
		enc_der_4, err := v.AuthenticateClientResponseEs11.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientResponseEs11: %w", err)
		}
		enc_der_4 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_4)
		return enc_der_4, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes RemoteProfileProvisioningResponse from BER/DER format.
func (v *RemoteProfileProvisioningResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RemoteProfileProvisioningResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RemoteProfileProvisioningResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 2 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RemoteProfileProvisioningResponse CHOICE: %w: expected tag [CONTEXT 2], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RemoteProfileProvisioningResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for RemoteProfileProvisioningResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RemoteProfileProvisioningResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RemoteProfileProvisioningResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RemoteProfileProvisioningResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 57 {
		v.Choice = RemoteProfileProvisioningResponseChoiceInitiateAuthenticationResponse
		var dec InitiateAuthenticationResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationResponse: %w", unmErr)
		}
		v.InitiateAuthenticationResponse = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 59 {
		v.Choice = RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs9
		var dec AuthenticateClientResponseEs9
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientResponseEs9: %w", unmErr)
		}
		v.AuthenticateClientResponseEs9 = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 58 {
		v.Choice = RemoteProfileProvisioningResponseChoiceGetBoundProfilePackageResponse
		var dec GetBoundProfilePackageResponse
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageResponse: %w", unmErr)
		}
		v.GetBoundProfilePackageResponse = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 65 {
		v.Choice = RemoteProfileProvisioningResponseChoiceCancelSessionResponseEs9
		var dec CancelSessionResponseEs9
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionResponseEs9: %w", unmErr)
		}
		v.CancelSessionResponseEs9 = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 64 {
		v.Choice = RemoteProfileProvisioningResponseChoiceAuthenticateClientResponseEs11
		var dec AuthenticateClientResponseEs11
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientResponseEs11: %w", unmErr)
		}
		v.AuthenticateClientResponseEs11 = &dec
	} else {
		return fmt.Errorf("unknown tag %s for RemoteProfileProvisioningResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes InitiateAuthenticationRequest to BER format.
func (v *InitiateAuthenticationRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_euiccchallenge := ber.EncodeOctetString([]byte(v.EuiccChallenge))
	enc_euiccchallenge = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_euiccchallenge)
	children = append(children, enc_euiccchallenge...)
	enc_smdpaddress := ber.EncodeStringTag(12, v.SmdpAddress)
	enc_smdpaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_smdpaddress)
	children = append(children, enc_smdpaddress...)
	enc_euiccinfo1, err := v.EuiccInfo1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding euiccInfo1: %w", err)
	}
	children = append(children, enc_euiccinfo1...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 57, Constructed: true}, children), nil
}

// MarshalDER encodes InitiateAuthenticationRequest to DER format.
func (v *InitiateAuthenticationRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes InitiateAuthenticationRequest from BER/DER format.
func (v *InitiateAuthenticationRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding InitiateAuthenticationRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 57 || !decodedTag.Constructed {
		return fmt.Errorf("decoding InitiateAuthenticationRequest: %w: expected tag [CONTEXT 57], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode euiccChallenge
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccChallenge")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for euiccChallenge, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_euiccchallenge, rawVal_euiccchallenge, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccChallenge: %w", err)
	}
	v.EuiccChallenge = Octet16(rawVal_euiccchallenge)
	offset += n_euiccchallenge
	// Decode smdpAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for smdpAddress, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_smdpaddress, rawVal_smdpaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpAddress: %w", err)
	}
	decVal_smdpaddress := ber.DecodeStringValue(rawVal_smdpaddress)
	v.SmdpAddress = decVal_smdpaddress
	offset += n_smdpaddress
	// Decode euiccInfo1
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccInfo1")
	}
	// Decode nested SEQUENCE (EUICCInfo1)
	_, n_euiccinfo1, _, tlvErr_euiccinfo1 := ber.DecodeTLV(content[offset:])
	if tlvErr_euiccinfo1 != nil {
		return fmt.Errorf("decoding euiccInfo1: %w", tlvErr_euiccinfo1)
	}
	if unmErr := v.EuiccInfo1.UnmarshalBER(content[offset : offset+n_euiccinfo1]); unmErr != nil {
		return fmt.Errorf("decoding euiccInfo1: %w", unmErr)
	}
	offset += n_euiccinfo1
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InitiateAuthenticationRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InitiateAuthenticationResponse to BER format.
func (v *InitiateAuthenticationResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case InitiateAuthenticationResponseChoiceInitiateAuthenticationOk:
		if v.InitiateAuthenticationOk == nil {
			return nil, fmt.Errorf("choice InitiateAuthenticationResponse: initiateAuthenticationOk is nil")
		}
		enc_0, err := v.InitiateAuthenticationOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 57, enc_0)
		return enc_0, nil
	case InitiateAuthenticationResponseChoiceInitiateAuthenticationError:
		if v.InitiateAuthenticationError == nil {
			return nil, fmt.Errorf("choice InitiateAuthenticationResponse: initiateAuthenticationError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.InitiateAuthenticationError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 57, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InitiateAuthenticationResponse", v.Choice)
	}
}

// MarshalDER encodes InitiateAuthenticationResponse to DER format.
func (v *InitiateAuthenticationResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case InitiateAuthenticationResponseChoiceInitiateAuthenticationOk:
		if v.InitiateAuthenticationOk == nil {
			return nil, fmt.Errorf("choice InitiateAuthenticationResponse: initiateAuthenticationOk is nil")
		}
		enc_der_0, err := v.InitiateAuthenticationOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding initiateAuthenticationOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 57, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes InitiateAuthenticationResponse from BER/DER format.
func (v *InitiateAuthenticationResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for InitiateAuthenticationResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding InitiateAuthenticationResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 57 || !decodedTag.Constructed {
		return fmt.Errorf("decoding InitiateAuthenticationResponse CHOICE: %w: expected tag [CONTEXT 57], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for InitiateAuthenticationResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InitiateAuthenticationResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding InitiateAuthenticationResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InitiateAuthenticationResponseChoiceInitiateAuthenticationOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec InitiateAuthenticationOkEs9
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationOk: %w", unmErr)
		}
		v.InitiateAuthenticationOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = InitiateAuthenticationResponseChoiceInitiateAuthenticationError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationError: %w", intErr)
		}
		var named_initiateauthenticationerror InitiateAuthenticationResponseInitiateAuthenticationErrorValue
		if namedErr := named_initiateauthenticationerror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding initiateAuthenticationError: %w", namedErr)
		}
		v.InitiateAuthenticationError = &named_initiateauthenticationerror
	} else {
		return fmt.Errorf("unknown tag %s for InitiateAuthenticationResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes InitiateAuthenticationOkEs9 to BER format.
func (v *InitiateAuthenticationOkEs9) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_serversigned1, err := v.ServerSigned1.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding serverSigned1: %w", err)
	}
	children = append(children, enc_serversigned1...)
	enc_serversignature1 := ber.EncodeOctetString(v.ServerSignature1)
	enc_serversignature1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_serversignature1)
	children = append(children, enc_serversignature1...)
	enc_euicccipkidtobeused := ber.EncodeOctetString([]byte(v.EuiccCiPKIdToBeUsed))
	children = append(children, enc_euicccipkidtobeused...)
	enc_servercertificate, err := v.ServerCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding serverCertificate: %w", err)
	}
	children = append(children, enc_servercertificate...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes InitiateAuthenticationOkEs9 to DER format.
func (v *InitiateAuthenticationOkEs9) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes InitiateAuthenticationOkEs9 from BER/DER format.
func (v *InitiateAuthenticationOkEs9) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding InitiateAuthenticationOkEs9 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InitiateAuthenticationOkEs9", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode serverSigned1
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverSigned1")
	}
	// Decode nested SEQUENCE (ServerSigned1)
	_, n_serversigned1, _, tlvErr_serversigned1 := ber.DecodeTLV(content[offset:])
	if tlvErr_serversigned1 != nil {
		return fmt.Errorf("decoding serverSigned1: %w", tlvErr_serversigned1)
	}
	if unmErr := v.ServerSigned1.UnmarshalBER(content[offset : offset+n_serversigned1]); unmErr != nil {
		return fmt.Errorf("decoding serverSigned1: %w", unmErr)
	}
	offset += n_serversigned1
	// Decode serverSignature1
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverSignature1")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for serverSignature1, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_serversignature1, rawVal_serversignature1, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serverSignature1: %w", err)
	}
	v.ServerSignature1 = rawVal_serversignature1
	offset += n_serversignature1
	// Decode euiccCiPKIdToBeUsed
	if offset >= len(content) {
		return fmt.Errorf("missing required field euiccCiPKIdToBeUsed")
	}
	val_euicccipkidtobeused, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding euiccCiPKIdToBeUsed: %w", err)
	}
	v.EuiccCiPKIdToBeUsed = SubjectKeyIdentifier(val_euicccipkidtobeused)
	offset += n
	// Decode serverCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field serverCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_servercertificate, _, tlvErr_servercertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_servercertificate != nil {
		return fmt.Errorf("decoding serverCertificate: %w", tlvErr_servercertificate)
	}
	if unmErr := v.ServerCertificate.UnmarshalBER(content[offset : offset+n_servercertificate]); unmErr != nil {
		return fmt.Errorf("decoding serverCertificate: %w", unmErr)
	}
	offset += n_servercertificate
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InitiateAuthenticationOkEs9", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AuthenticateClientRequest to BER format.
func (v *AuthenticateClientRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_authenticateserverresponse, err := v.AuthenticateServerResponse.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding authenticateServerResponse: %w", err)
	}
	children = append(children, enc_authenticateserverresponse...)
	if v.UseMatchingIdForAcr != nil {
		enc_usematchingidforacr := ber.EncodeNull()
		children = append(children, enc_usematchingidforacr...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 59, Constructed: true}, children), nil
}

// MarshalDER encodes AuthenticateClientRequest to DER format.
func (v *AuthenticateClientRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientRequest from BER/DER format.
func (v *AuthenticateClientRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 59 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateClientRequest: %w: expected tag [CONTEXT 59], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode authenticateServerResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field authenticateServerResponse")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 56 {
			return fmt.Errorf("expected tag [%s %d] for authenticateServerResponse, got %s", "CONTEXT", 56, reqTag_)
		}
	}
	// Decode nested CHOICE (AuthenticateServerResponse)
	_, n_authenticateserverresponse, _, tlvErr_authenticateserverresponse := ber.DecodeTLV(content[offset:])
	if tlvErr_authenticateserverresponse != nil {
		return fmt.Errorf("decoding authenticateServerResponse: %w", tlvErr_authenticateserverresponse)
	}
	if unmErr := v.AuthenticateServerResponse.UnmarshalBER(content[offset : offset+n_authenticateserverresponse]); unmErr != nil {
		return fmt.Errorf("decoding authenticateServerResponse: %w", unmErr)
	}
	offset += n_authenticateserverresponse
	// Decode useMatchingIdForAcr
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding useMatchingIdForAcr: %w", err)
				}
				v.UseMatchingIdForAcr = &struct{}{}
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AuthenticateClientResponseEs9 to BER format.
func (v *AuthenticateClientResponseEs9) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateClientResponseEs9ChoiceAuthenticateClientOk:
		if v.AuthenticateClientOk == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs9: authenticateClientOk is nil")
		}
		enc_0, err := v.AuthenticateClientOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_0)
		return enc_0, nil
	case AuthenticateClientResponseEs9ChoiceAuthenticateClientError:
		if v.AuthenticateClientError == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs9: authenticateClientError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.AuthenticateClientError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_1)
		return enc_1, nil
	case AuthenticateClientResponseEs9ChoiceAuthenticateClientOkAcr:
		if v.AuthenticateClientOkAcr == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs9: authenticateClientOkAcr is nil")
		}
		enc_2, err := v.AuthenticateClientOkAcr.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOkAcr: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_2)
		enc_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AuthenticateClientResponseEs9", v.Choice)
	}
}

// MarshalDER encodes AuthenticateClientResponseEs9 to DER format.
func (v *AuthenticateClientResponseEs9) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateClientResponseEs9ChoiceAuthenticateClientOk:
		if v.AuthenticateClientOk == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs9: authenticateClientOk is nil")
		}
		enc_der_0, err := v.AuthenticateClientOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_der_0)
		return enc_der_0, nil
	case AuthenticateClientResponseEs9ChoiceAuthenticateClientOkAcr:
		if v.AuthenticateClientOkAcr == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs9: authenticateClientOkAcr is nil")
		}
		enc_der_2, err := v.AuthenticateClientOkAcr.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOkAcr: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_der_2)
		enc_der_2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 59, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientResponseEs9 from BER/DER format.
func (v *AuthenticateClientResponseEs9) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AuthenticateClientResponseEs9 CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientResponseEs9 CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 59 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateClientResponseEs9 CHOICE: %w: expected tag [CONTEXT 59], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientResponseEs9", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for AuthenticateClientResponseEs9 CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AuthenticateClientResponseEs9: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AuthenticateClientResponseEs9 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientResponseEs9", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AuthenticateClientResponseEs9ChoiceAuthenticateClientOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateClientOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientOk: %w", unmErr)
		}
		v.AuthenticateClientOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AuthenticateClientResponseEs9ChoiceAuthenticateClientError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding authenticateClientError: %w", intErr)
		}
		var named_authenticateclienterror AuthenticateClientResponseEs9AuthenticateClientErrorValue
		if namedErr := named_authenticateclienterror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding authenticateClientError: %w", namedErr)
		}
		v.AuthenticateClientError = &named_authenticateclienterror
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = AuthenticateClientResponseEs9ChoiceAuthenticateClientOkAcr
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientOkAcr: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateClientOkAcr
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientOkAcr: %w", unmErr)
		}
		v.AuthenticateClientOkAcr = &dec
	} else {
		return fmt.Errorf("unknown tag %s for AuthenticateClientResponseEs9 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AuthenticateClientOk to BER format.
func (v *AuthenticateClientOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_profilemetadata, err := v.ProfileMetaData.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding profileMetaData: %w", err)
	}
	children = append(children, enc_profilemetadata...)
	enc_smdpsigned2, err := v.SmdpSigned2.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding smdpSigned2: %w", err)
	}
	children = append(children, enc_smdpsigned2...)
	enc_smdpsignature2 := ber.EncodeOctetString(v.SmdpSignature2)
	enc_smdpsignature2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 55, false, enc_smdpsignature2)
	children = append(children, enc_smdpsignature2...)
	enc_smdpcertificate, err := v.SmdpCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding smdpCertificate: %w", err)
	}
	children = append(children, enc_smdpcertificate...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateClientOk to DER format.
func (v *AuthenticateClientOk) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientOk from BER/DER format.
func (v *AuthenticateClientOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode profileMetaData
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileMetaData")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 37 {
			return fmt.Errorf("expected tag [%s %d] for profileMetaData, got %s", "CONTEXT", 37, reqTag_)
		}
	}
	// Decode nested SEQUENCE (StoreMetadataRequest)
	_, n_profilemetadata, _, tlvErr_profilemetadata := ber.DecodeTLV(content[offset:])
	if tlvErr_profilemetadata != nil {
		return fmt.Errorf("decoding profileMetaData: %w", tlvErr_profilemetadata)
	}
	if unmErr := v.ProfileMetaData.UnmarshalBER(content[offset : offset+n_profilemetadata]); unmErr != nil {
		return fmt.Errorf("decoding profileMetaData: %w", unmErr)
	}
	offset += n_profilemetadata
	// Decode smdpSigned2
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpSigned2")
	}
	// Decode nested SEQUENCE (SmdpSigned2)
	_, n_smdpsigned2, _, tlvErr_smdpsigned2 := ber.DecodeTLV(content[offset:])
	if tlvErr_smdpsigned2 != nil {
		return fmt.Errorf("decoding smdpSigned2: %w", tlvErr_smdpsigned2)
	}
	if unmErr := v.SmdpSigned2.UnmarshalBER(content[offset : offset+n_smdpsigned2]); unmErr != nil {
		return fmt.Errorf("decoding smdpSigned2: %w", unmErr)
	}
	offset += n_smdpsigned2
	// Decode smdpSignature2
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpSignature2")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 55 {
			return fmt.Errorf("expected tag [%s %d] for smdpSignature2, got %s", "APPLICATION", 55, reqTag_)
		}
	}
	_, n_smdpsignature2, rawVal_smdpsignature2, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding smdpSignature2: %w", err)
	}
	v.SmdpSignature2 = rawVal_smdpsignature2
	offset += n_smdpsignature2
	// Decode smdpCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field smdpCertificate")
	}
	// Decode nested SEQUENCE (Certificate)
	_, n_smdpcertificate, _, tlvErr_smdpcertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_smdpcertificate != nil {
		return fmt.Errorf("decoding smdpCertificate: %w", tlvErr_smdpcertificate)
	}
	if unmErr := v.SmdpCertificate.UnmarshalBER(content[offset : offset+n_smdpcertificate]); unmErr != nil {
		return fmt.Errorf("decoding smdpCertificate: %w", unmErr)
	}
	offset += n_smdpcertificate
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientOk", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AuthenticateClientOkAcr to BER format.
func (v *AuthenticateClientOkAcr) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_profilemetadata, err := v.ProfileMetaData.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding profileMetaData: %w", err)
	}
	children = append(children, enc_profilemetadata...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateClientOkAcr to DER format.
func (v *AuthenticateClientOkAcr) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientOkAcr from BER/DER format.
func (v *AuthenticateClientOkAcr) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientOkAcr SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientOkAcr", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode profileMetaData
	if offset >= len(content) {
		return fmt.Errorf("missing required field profileMetaData")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 37 {
			return fmt.Errorf("expected tag [%s %d] for profileMetaData, got %s", "CONTEXT", 37, reqTag_)
		}
	}
	// Decode nested SEQUENCE (StoreMetadataRequest)
	_, n_profilemetadata, _, tlvErr_profilemetadata := ber.DecodeTLV(content[offset:])
	if tlvErr_profilemetadata != nil {
		return fmt.Errorf("decoding profileMetaData: %w", tlvErr_profilemetadata)
	}
	if unmErr := v.ProfileMetaData.UnmarshalBER(content[offset : offset+n_profilemetadata]); unmErr != nil {
		return fmt.Errorf("decoding profileMetaData: %w", unmErr)
	}
	offset += n_profilemetadata
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientOkAcr", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetBoundProfilePackageRequest to BER format.
func (v *GetBoundProfilePackageRequest) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_preparedownloadresponse, err := v.PrepareDownloadResponse.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding prepareDownloadResponse: %w", err)
	}
	children = append(children, enc_preparedownloadresponse...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 58, Constructed: true}, children), nil
}

// MarshalDER encodes GetBoundProfilePackageRequest to DER format.
func (v *GetBoundProfilePackageRequest) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetBoundProfilePackageRequest from BER/DER format.
func (v *GetBoundProfilePackageRequest) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageRequest: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 58 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetBoundProfilePackageRequest: %w: expected tag [CONTEXT 58], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageRequest", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode prepareDownloadResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field prepareDownloadResponse")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 33 {
			return fmt.Errorf("expected tag [%s %d] for prepareDownloadResponse, got %s", "CONTEXT", 33, reqTag_)
		}
	}
	// Decode nested CHOICE (PrepareDownloadResponse)
	_, n_preparedownloadresponse, _, tlvErr_preparedownloadresponse := ber.DecodeTLV(content[offset:])
	if tlvErr_preparedownloadresponse != nil {
		return fmt.Errorf("decoding prepareDownloadResponse: %w", tlvErr_preparedownloadresponse)
	}
	if unmErr := v.PrepareDownloadResponse.UnmarshalBER(content[offset : offset+n_preparedownloadresponse]); unmErr != nil {
		return fmt.Errorf("decoding prepareDownloadResponse: %w", unmErr)
	}
	offset += n_preparedownloadresponse
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetBoundProfilePackageRequest", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GetBoundProfilePackageResponse to BER format.
func (v *GetBoundProfilePackageResponse) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case GetBoundProfilePackageResponseChoiceGetBoundProfilePackageOk:
		if v.GetBoundProfilePackageOk == nil {
			return nil, fmt.Errorf("choice GetBoundProfilePackageResponse: getBoundProfilePackageOk is nil")
		}
		enc_0, err := v.GetBoundProfilePackageOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 58, enc_0)
		return enc_0, nil
	case GetBoundProfilePackageResponseChoiceGetBoundProfilePackageError:
		if v.GetBoundProfilePackageError == nil {
			return nil, fmt.Errorf("choice GetBoundProfilePackageResponse: getBoundProfilePackageError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.GetBoundProfilePackageError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 58, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for GetBoundProfilePackageResponse", v.Choice)
	}
}

// MarshalDER encodes GetBoundProfilePackageResponse to DER format.
func (v *GetBoundProfilePackageResponse) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case GetBoundProfilePackageResponseChoiceGetBoundProfilePackageOk:
		if v.GetBoundProfilePackageOk == nil {
			return nil, fmt.Errorf("choice GetBoundProfilePackageResponse: getBoundProfilePackageOk is nil")
		}
		enc_der_0, err := v.GetBoundProfilePackageOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding getBoundProfilePackageOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 58, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes GetBoundProfilePackageResponse from BER/DER format.
func (v *GetBoundProfilePackageResponse) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for GetBoundProfilePackageResponse CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageResponse CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 58 || !decodedTag.Constructed {
		return fmt.Errorf("decoding GetBoundProfilePackageResponse CHOICE: %w: expected tag [CONTEXT 58], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageResponse", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for GetBoundProfilePackageResponse CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for GetBoundProfilePackageResponse: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageResponse CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageResponse", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = GetBoundProfilePackageResponseChoiceGetBoundProfilePackageOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec GetBoundProfilePackageOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageOk: %w", unmErr)
		}
		v.GetBoundProfilePackageOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = GetBoundProfilePackageResponseChoiceGetBoundProfilePackageError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageError: %w", intErr)
		}
		var named_getboundprofilepackageerror GetBoundProfilePackageResponseGetBoundProfilePackageErrorValue
		if namedErr := named_getboundprofilepackageerror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding getBoundProfilePackageError: %w", namedErr)
		}
		v.GetBoundProfilePackageError = &named_getboundprofilepackageerror
	} else {
		return fmt.Errorf("unknown tag %s for GetBoundProfilePackageResponse CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes GetBoundProfilePackageOk to BER format.
func (v *GetBoundProfilePackageOk) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_boundprofilepackage, err := v.BoundProfilePackage.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding boundProfilePackage: %w", err)
	}
	children = append(children, enc_boundprofilepackage...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes GetBoundProfilePackageOk to DER format.
func (v *GetBoundProfilePackageOk) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes GetBoundProfilePackageOk from BER/DER format.
func (v *GetBoundProfilePackageOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GetBoundProfilePackageOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GetBoundProfilePackageOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode boundProfilePackage
	if offset >= len(content) {
		return fmt.Errorf("missing required field boundProfilePackage")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 54 {
			return fmt.Errorf("expected tag [%s %d] for boundProfilePackage, got %s", "CONTEXT", 54, reqTag_)
		}
	}
	// Decode nested SEQUENCE (BoundProfilePackage)
	_, n_boundprofilepackage, _, tlvErr_boundprofilepackage := ber.DecodeTLV(content[offset:])
	if tlvErr_boundprofilepackage != nil {
		return fmt.Errorf("decoding boundProfilePackage: %w", tlvErr_boundprofilepackage)
	}
	if unmErr := v.BoundProfilePackage.UnmarshalBER(content[offset : offset+n_boundprofilepackage]); unmErr != nil {
		return fmt.Errorf("decoding boundProfilePackage: %w", unmErr)
	}
	offset += n_boundprofilepackage
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GetBoundProfilePackageOk", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes HandleNotification to BER format.
func (v *HandleNotification) MarshalBER() ([]byte, error) {
	var children []byte
	enc_pendingnotification, err := v.PendingNotification.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding pendingNotification: %w", err)
	}
	enc_pendingnotification = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_pendingnotification)
	children = append(children, enc_pendingnotification...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 61, Constructed: true}, children), nil
}

// MarshalDER encodes HandleNotification to DER format.
func (v *HandleNotification) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes HandleNotification from BER/DER format.
func (v *HandleNotification) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding HandleNotification: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 61 || !decodedTag.Constructed {
		return fmt.Errorf("decoding HandleNotification: %w: expected tag [CONTEXT 61], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "HandleNotification", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode pendingNotification
	if offset >= len(content) {
		return fmt.Errorf("missing required field pendingNotification")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for pendingNotification, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_pendingnotification, innerData_pendingnotification, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding pendingNotification: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.PendingNotification.UnmarshalBER(innerData_pendingnotification); unmErr != nil {
		return fmt.Errorf("decoding pendingNotification: %w", unmErr)
	}
	offset += n_pendingnotification
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "HandleNotification", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CancelSessionRequestEs9 to BER format.
func (v *CancelSessionRequestEs9) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_cancelsessionresponse, err := v.CancelSessionResponse.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding cancelSessionResponse: %w", err)
	}
	enc_cancelsessionresponse = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cancelsessionresponse)
	children = append(children, enc_cancelsessionresponse...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 65, Constructed: true}, children), nil
}

// MarshalDER encodes CancelSessionRequestEs9 to DER format.
func (v *CancelSessionRequestEs9) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionRequestEs9 from BER/DER format.
func (v *CancelSessionRequestEs9) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionRequestEs9: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 65 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CancelSessionRequestEs9: %w: expected tag [CONTEXT 65], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionRequestEs9", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode cancelSessionResponse
	if offset >= len(content) {
		return fmt.Errorf("missing required field cancelSessionResponse")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for cancelSessionResponse, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_cancelsessionresponse, innerData_cancelsessionresponse, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding cancelSessionResponse: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.CancelSessionResponse.UnmarshalBER(innerData_cancelsessionresponse); unmErr != nil {
		return fmt.Errorf("decoding cancelSessionResponse: %w", unmErr)
	}
	offset += n_cancelsessionresponse
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CancelSessionRequestEs9", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CancelSessionResponseEs9 to BER format.
func (v *CancelSessionResponseEs9) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseEs9ChoiceCancelSessionOk:
		if v.CancelSessionOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponseEs9: cancelSessionOk is nil")
		}
		enc_0, err := v.CancelSessionOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_0)
		return enc_0, nil
	case CancelSessionResponseEs9ChoiceCancelSessionError:
		if v.CancelSessionError == nil {
			return nil, fmt.Errorf("choice CancelSessionResponseEs9: cancelSessionError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.CancelSessionError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CancelSessionResponseEs9", v.Choice)
	}
}

// MarshalDER encodes CancelSessionResponseEs9 to DER format.
func (v *CancelSessionResponseEs9) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CancelSessionResponseEs9ChoiceCancelSessionOk:
		if v.CancelSessionOk == nil {
			return nil, fmt.Errorf("choice CancelSessionResponseEs9: cancelSessionOk is nil")
		}
		enc_der_0, err := v.CancelSessionOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cancelSessionOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 65, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionResponseEs9 from BER/DER format.
func (v *CancelSessionResponseEs9) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CancelSessionResponseEs9 CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionResponseEs9 CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 65 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CancelSessionResponseEs9 CHOICE: %w: expected tag [CONTEXT 65], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponseEs9", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for CancelSessionResponseEs9 CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CancelSessionResponseEs9: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CancelSessionResponseEs9 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionResponseEs9", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CancelSessionResponseEs9ChoiceCancelSessionOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CancelSessionOk
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding cancelSessionOk: %w", unmErr)
		}
		v.CancelSessionOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CancelSessionResponseEs9ChoiceCancelSessionError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cancelSessionError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cancelSessionError: %w", intErr)
		}
		var named_cancelsessionerror CancelSessionResponseEs9CancelSessionErrorValue
		if namedErr := named_cancelsessionerror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding cancelSessionError: %w", namedErr)
		}
		v.CancelSessionError = &named_cancelsessionerror
	} else {
		return fmt.Errorf("unknown tag %s for CancelSessionResponseEs9 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CancelSessionOk to BER format.
func (v *CancelSessionOk) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CancelSessionOk to DER format.
func (v *CancelSessionOk) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CancelSessionOk from BER/DER format.
func (v *CancelSessionOk) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CancelSessionOk SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelSessionOk", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CancelSessionOk", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AuthenticateClientResponseEs11 to BER format.
func (v *AuthenticateClientResponseEs11) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateClientResponseEs11ChoiceAuthenticateClientOk:
		if v.AuthenticateClientOk == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs11: authenticateClientOk is nil")
		}
		enc_0, err := v.AuthenticateClientOk.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOk: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 64, enc_0)
		return enc_0, nil
	case AuthenticateClientResponseEs11ChoiceAuthenticateClientError:
		if v.AuthenticateClientError == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs11: authenticateClientError is nil")
		}
		enc_1 := ber.EncodeBigInt(v.AuthenticateClientError.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 64, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AuthenticateClientResponseEs11", v.Choice)
	}
}

// MarshalDER encodes AuthenticateClientResponseEs11 to DER format.
func (v *AuthenticateClientResponseEs11) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case AuthenticateClientResponseEs11ChoiceAuthenticateClientOk:
		if v.AuthenticateClientOk == nil {
			return nil, fmt.Errorf("choice AuthenticateClientResponseEs11: authenticateClientOk is nil")
		}
		enc_der_0, err := v.AuthenticateClientOk.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticateClientOk: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 64, enc_der_0)
		return enc_der_0, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientResponseEs11 from BER/DER format.
func (v *AuthenticateClientResponseEs11) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AuthenticateClientResponseEs11 CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientResponseEs11 CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 64 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AuthenticateClientResponseEs11 CHOICE: %w: expected tag [CONTEXT 64], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientResponseEs11", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for AuthenticateClientResponseEs11 CHOICE")
	}
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AuthenticateClientResponseEs11: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AuthenticateClientResponseEs11 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientResponseEs11", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AuthenticateClientResponseEs11ChoiceAuthenticateClientOk
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientOk: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AuthenticateClientOkEs11
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding authenticateClientOk: %w", unmErr)
		}
		v.AuthenticateClientOk = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AuthenticateClientResponseEs11ChoiceAuthenticateClientError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticateClientError: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding authenticateClientError: %w", intErr)
		}
		var named_authenticateclienterror AuthenticateClientResponseEs11AuthenticateClientErrorValue
		if namedErr := named_authenticateclienterror.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding authenticateClientError: %w", namedErr)
		}
		v.AuthenticateClientError = &named_authenticateclienterror
	} else {
		return fmt.Errorf("unknown tag %s for AuthenticateClientResponseEs11 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AuthenticateClientOkEs11 to BER format.
func (v *AuthenticateClientOkEs11) MarshalBER() ([]byte, error) {
	var children []byte
	enc_transactionid := ber.EncodeOctetString([]byte(v.TransactionId))
	enc_transactionid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_transactionid)
	children = append(children, enc_transactionid...)
	enc_evententries, err := MarshalBERAuthenticateClientOkEs11EventEntries(v.EventEntries)
	if err != nil {
		return nil, fmt.Errorf("encoding eventEntries: %w", err)
	}
	if v.EventEntriesIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_evententries)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_evententries = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
	} else {
		enc_evententries = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_evententries)
	}
	children = append(children, enc_evententries...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticateClientOkEs11 to DER format.
func (v *AuthenticateClientOkEs11) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.EventEntriesIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticateClientOkEs11 from BER/DER format.
func (v *AuthenticateClientOkEs11) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticateClientOkEs11 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientOkEs11", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode transactionId
	if offset >= len(content) {
		return fmt.Errorf("missing required field transactionId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for transactionId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_transactionid, rawVal_transactionid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding transactionId: %w", err)
	}
	v.TransactionId = TransactionId(rawVal_transactionid)
	offset += n_transactionid
	// Decode eventEntries
	if offset >= len(content) {
		return fmt.Errorf("missing required field eventEntries")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for eventEntries, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	v.EventEntriesIndef_ = false
	_, n_evententries, rawVal_evententries, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eventEntries: %w", err)
	}
	reconstructed_evententries := ber.EncodeSequence(rawVal_evententries)
	dec_evententries, unmErr := UnmarshalBERAuthenticateClientOkEs11EventEntries(reconstructed_evententries)
	if unmErr != nil {
		return fmt.Errorf("decoding eventEntries: %w", unmErr)
	}
	v.EventEntries = dec_evententries
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.EventEntriesIndef_ = true
		}
	}
	offset += n_evententries
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateClientOkEs11", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EventEntries to BER format.
func (v *EventEntries) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eventid := ber.EncodeStringTag(12, v.EventId)
	enc_eventid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eventid)
	children = append(children, enc_eventid...)
	enc_rspserveraddress := ber.EncodeStringTag(12, v.RspServerAddress)
	enc_rspserveraddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_rspserveraddress)
	children = append(children, enc_rspserveraddress...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EventEntries to DER format.
func (v *EventEntries) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EventEntries from BER/DER format.
func (v *EventEntries) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EventEntries SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EventEntries", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eventId
	if offset >= len(content) {
		return fmt.Errorf("missing required field eventId")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eventId, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eventid, rawVal_eventid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eventId: %w", err)
	}
	decVal_eventid := ber.DecodeStringValue(rawVal_eventid)
	v.EventId = decVal_eventid
	offset += n_eventid
	// Decode rspServerAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field rspServerAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for rspServerAddress, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_rspserveraddress, rawVal_rspserveraddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rspServerAddress: %w", err)
	}
	decVal_rspserveraddress := ber.DecodeStringValue(rawVal_rspserveraddress)
	v.RspServerAddress = decVal_rspserveraddress
	offset += n_rspserveraddress
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EventEntries", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERBoundProfilePackageFirstSequenceOf87 encodes a BoundProfilePackageFirstSequenceOf87 list to BER.
func MarshalBERBoundProfilePackageFirstSequenceOf87(list BoundProfilePackageFirstSequenceOf87) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString(elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERBoundProfilePackageFirstSequenceOf87 decodes a BoundProfilePackageFirstSequenceOf87 list from BER.
func UnmarshalBERBoundProfilePackageFirstSequenceOf87(data []byte) (BoundProfilePackageFirstSequenceOf87, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BoundProfilePackageFirstSequenceOf87: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BoundProfilePackageFirstSequenceOf87", Cause: ber.ErrExtraData}
	}
	var result BoundProfilePackageFirstSequenceOf87
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}

// MarshalBERBoundProfilePackageSequenceOf88 encodes a BoundProfilePackageSequenceOf88 list to BER.
func MarshalBERBoundProfilePackageSequenceOf88(list BoundProfilePackageSequenceOf88) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString(elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERBoundProfilePackageSequenceOf88 decodes a BoundProfilePackageSequenceOf88 list from BER.
func UnmarshalBERBoundProfilePackageSequenceOf88(data []byte) (BoundProfilePackageSequenceOf88, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BoundProfilePackageSequenceOf88: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BoundProfilePackageSequenceOf88", Cause: ber.ErrExtraData}
	}
	var result BoundProfilePackageSequenceOf88
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}

// MarshalBERBoundProfilePackageSecondSequenceOf87 encodes a BoundProfilePackageSecondSequenceOf87 list to BER.
func MarshalBERBoundProfilePackageSecondSequenceOf87(list BoundProfilePackageSecondSequenceOf87) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString(elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERBoundProfilePackageSecondSequenceOf87 decodes a BoundProfilePackageSecondSequenceOf87 list from BER.
func UnmarshalBERBoundProfilePackageSecondSequenceOf87(data []byte) (BoundProfilePackageSecondSequenceOf87, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BoundProfilePackageSecondSequenceOf87: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BoundProfilePackageSecondSequenceOf87", Cause: ber.ErrExtraData}
	}
	var result BoundProfilePackageSecondSequenceOf87
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}

// MarshalBERBoundProfilePackageSequenceOf86 encodes a BoundProfilePackageSequenceOf86 list to BER.
func MarshalBERBoundProfilePackageSequenceOf86(list BoundProfilePackageSequenceOf86) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString(elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERBoundProfilePackageSequenceOf86 decodes a BoundProfilePackageSequenceOf86 list from BER.
func UnmarshalBERBoundProfilePackageSequenceOf86(data []byte) (BoundProfilePackageSequenceOf86, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BoundProfilePackageSequenceOf86: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BoundProfilePackageSequenceOf86", Cause: ber.ErrExtraData}
	}
	var result BoundProfilePackageSequenceOf86
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ProfileInstallationResultDataFinalResult to BER format.
func (v *ProfileInstallationResultDataFinalResult) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ProfileInstallationResultDataFinalResultChoiceSuccessResult:
		if v.SuccessResult == nil {
			return nil, fmt.Errorf("choice ProfileInstallationResultDataFinalResult: successResult is nil")
		}
		enc_0, err := v.SuccessResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding successResult: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case ProfileInstallationResultDataFinalResultChoiceErrorResult:
		if v.ErrorResult == nil {
			return nil, fmt.Errorf("choice ProfileInstallationResultDataFinalResult: errorResult is nil")
		}
		enc_1, err := v.ErrorResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding errorResult: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ProfileInstallationResultDataFinalResult", v.Choice)
	}
}

// MarshalDER encodes ProfileInstallationResultDataFinalResult to DER format.
func (v *ProfileInstallationResultDataFinalResult) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ProfileInstallationResultDataFinalResultChoiceSuccessResult:
		if v.SuccessResult == nil {
			return nil, fmt.Errorf("choice ProfileInstallationResultDataFinalResult: successResult is nil")
		}
		enc_der_0, err := v.SuccessResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding successResult: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case ProfileInstallationResultDataFinalResultChoiceErrorResult:
		if v.ErrorResult == nil {
			return nil, fmt.Errorf("choice ProfileInstallationResultDataFinalResult: errorResult is nil")
		}
		enc_der_1, err := v.ErrorResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding errorResult: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInstallationResultDataFinalResult from BER/DER format.
func (v *ProfileInstallationResultDataFinalResult) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ProfileInstallationResultDataFinalResult CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ProfileInstallationResultDataFinalResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ProfileInstallationResultDataFinalResult CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInstallationResultDataFinalResult", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ProfileInstallationResultDataFinalResultChoiceSuccessResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding successResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SuccessResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding successResult: %w", unmErr)
		}
		v.SuccessResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ProfileInstallationResultDataFinalResultChoiceErrorResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding errorResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ErrorResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding errorResult: %w", unmErr)
		}
		v.ErrorResult = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ProfileInstallationResultDataFinalResult CHOICE", peekTag)
	}
	return nil
}

// MarshalBERStoreMetadataRequestNotificationConfigurationInfo encodes a StoreMetadataRequestNotificationConfigurationInfo list to BER.
func MarshalBERStoreMetadataRequestNotificationConfigurationInfo(list StoreMetadataRequestNotificationConfigurationInfo) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERStoreMetadataRequestNotificationConfigurationInfo decodes a StoreMetadataRequestNotificationConfigurationInfo list from BER.
func UnmarshalBERStoreMetadataRequestNotificationConfigurationInfo(data []byte) (StoreMetadataRequestNotificationConfigurationInfo, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding StoreMetadataRequestNotificationConfigurationInfo: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "StoreMetadataRequestNotificationConfigurationInfo", Cause: ber.ErrExtraData}
	}
	var result StoreMetadataRequestNotificationConfigurationInfo
	offset := 0
	for offset < len(content) {
		var elem NotificationConfigurationInformation
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes StoreMetadataRequestIotSpecificMetadata to BER format.
func (v *StoreMetadataRequestIotSpecificMetadata) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes StoreMetadataRequestIotSpecificMetadata to DER format.
func (v *StoreMetadataRequestIotSpecificMetadata) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes StoreMetadataRequestIotSpecificMetadata from BER/DER format.
func (v *StoreMetadataRequestIotSpecificMetadata) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding StoreMetadataRequestIotSpecificMetadata SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "StoreMetadataRequestIotSpecificMetadata", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "StoreMetadataRequestIotSpecificMetadata", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes VendorSpecificExtensionElem to BER format.
func (v *VendorSpecificExtensionElem) MarshalBER() ([]byte, error) {
	var children []byte
	enc_vendoroid := ber.EncodeObjectIdentifier([]uint64(v.VendorOid))
	enc_vendoroid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_vendoroid)
	children = append(children, enc_vendoroid...)
	enc_vendorspecificdata := v.VendorSpecificData.Bytes
	enc_vendorspecificdata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_vendorspecificdata)
	children = append(children, enc_vendorspecificdata...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes VendorSpecificExtensionElem to DER format.
func (v *VendorSpecificExtensionElem) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes VendorSpecificExtensionElem from BER/DER format.
func (v *VendorSpecificExtensionElem) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding VendorSpecificExtensionElem SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "VendorSpecificExtensionElem", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode vendorOid
	if offset >= len(content) {
		return fmt.Errorf("missing required field vendorOid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for vendorOid, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_vendoroid, rawVal_vendoroid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding vendorOid: %w", err)
	}
	decVal_vendoroid, oidErr := ber.DecodeOIDValue(rawVal_vendoroid)
	if oidErr != nil {
		return fmt.Errorf("decoding vendorOid: %w", oidErr)
	}
	v.VendorOid = runtime.ObjectIdentifier(decVal_vendoroid)
	offset += n_vendoroid
	// Decode vendorSpecificData
	if offset >= len(content) {
		return fmt.Errorf("missing required field vendorSpecificData")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for vendorSpecificData, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_vendorspecificdata, rawVal_vendorspecificdata, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding vendorSpecificData: %w", err)
	}
	_ = rawVal_vendorspecificdata
	v.VendorSpecificData = runtime.RawValue{Bytes: content[offset : offset+n_vendorspecificdata]}
	offset += n_vendorspecificdata
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "VendorSpecificExtensionElem", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBEREUICCInfo1EuiccCiPKIdListForVerification encodes a EUICCInfo1EuiccCiPKIdListForVerification list to BER.
func MarshalBEREUICCInfo1EuiccCiPKIdListForVerification(list EUICCInfo1EuiccCiPKIdListForVerification) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo1EuiccCiPKIdListForVerification decodes a EUICCInfo1EuiccCiPKIdListForVerification list from BER.
func UnmarshalBEREUICCInfo1EuiccCiPKIdListForVerification(data []byte) (EUICCInfo1EuiccCiPKIdListForVerification, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo1EuiccCiPKIdListForVerification: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo1EuiccCiPKIdListForVerification", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo1EuiccCiPKIdListForVerification
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo1EuiccCiPKIdListForSigning encodes a EUICCInfo1EuiccCiPKIdListForSigning list to BER.
func MarshalBEREUICCInfo1EuiccCiPKIdListForSigning(list EUICCInfo1EuiccCiPKIdListForSigning) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo1EuiccCiPKIdListForSigning decodes a EUICCInfo1EuiccCiPKIdListForSigning list from BER.
func UnmarshalBEREUICCInfo1EuiccCiPKIdListForSigning(data []byte) (EUICCInfo1EuiccCiPKIdListForSigning, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo1EuiccCiPKIdListForSigning: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo1EuiccCiPKIdListForSigning", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo1EuiccCiPKIdListForSigning
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo2EuiccCiPKIdListForVerification encodes a EUICCInfo2EuiccCiPKIdListForVerification list to BER.
func MarshalBEREUICCInfo2EuiccCiPKIdListForVerification(list EUICCInfo2EuiccCiPKIdListForVerification) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2EuiccCiPKIdListForVerification decodes a EUICCInfo2EuiccCiPKIdListForVerification list from BER.
func UnmarshalBEREUICCInfo2EuiccCiPKIdListForVerification(data []byte) (EUICCInfo2EuiccCiPKIdListForVerification, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2EuiccCiPKIdListForVerification: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2EuiccCiPKIdListForVerification", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2EuiccCiPKIdListForVerification
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo2EuiccCiPKIdListForSigning encodes a EUICCInfo2EuiccCiPKIdListForSigning list to BER.
func MarshalBEREUICCInfo2EuiccCiPKIdListForSigning(list EUICCInfo2EuiccCiPKIdListForSigning) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigning decodes a EUICCInfo2EuiccCiPKIdListForSigning list from BER.
func UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigning(data []byte) (EUICCInfo2EuiccCiPKIdListForSigning, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2EuiccCiPKIdListForSigning: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2EuiccCiPKIdListForSigning", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2EuiccCiPKIdListForSigning
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions encodes a EUICCInfo2AdditionalEuiccProfilePackageVersions list to BER.
func MarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(list EUICCInfo2AdditionalEuiccProfilePackageVersions) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions decodes a EUICCInfo2AdditionalEuiccProfilePackageVersions list from BER.
func UnmarshalBEREUICCInfo2AdditionalEuiccProfilePackageVersions(data []byte) (EUICCInfo2AdditionalEuiccProfilePackageVersions, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2AdditionalEuiccProfilePackageVersions: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2AdditionalEuiccProfilePackageVersions", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2AdditionalEuiccProfilePackageVersions
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, VersionType(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3 encodes a EUICCInfo2EuiccCiPKIdListForSigningV3 list to BER.
func MarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(list EUICCInfo2EuiccCiPKIdListForSigningV3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3 decodes a EUICCInfo2EuiccCiPKIdListForSigningV3 list from BER.
func UnmarshalBEREUICCInfo2EuiccCiPKIdListForSigningV3(data []byte) (EUICCInfo2EuiccCiPKIdListForSigningV3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUICCInfo2EuiccCiPKIdListForSigningV3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUICCInfo2EuiccCiPKIdListForSigningV3", Cause: ber.ErrExtraData}
	}
	var result EUICCInfo2EuiccCiPKIdListForSigningV3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SubjectKeyIdentifier(val))
		offset += n
	}
	return result, nil
}

// MarshalBERListNotificationResponseNotificationMetadataList encodes a ListNotificationResponseNotificationMetadataList list to BER.
func MarshalBERListNotificationResponseNotificationMetadataList(list ListNotificationResponseNotificationMetadataList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERListNotificationResponseNotificationMetadataList decodes a ListNotificationResponseNotificationMetadataList list from BER.
func UnmarshalBERListNotificationResponseNotificationMetadataList(data []byte) (ListNotificationResponseNotificationMetadataList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ListNotificationResponseNotificationMetadataList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ListNotificationResponseNotificationMetadataList", Cause: ber.ErrExtraData}
	}
	var result ListNotificationResponseNotificationMetadataList
	offset := 0
	for offset < len(content) {
		var elem NotificationMetadata
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes RetrieveNotificationsListRequestSearchCriteria to BER format.
func (v *RetrieveNotificationsListRequestSearchCriteria) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber:
		if v.SeqNumber == nil {
			return nil, fmt.Errorf("choice RetrieveNotificationsListRequestSearchCriteria: seqNumber is nil")
		}
		enc_0 := ber.EncodeBigInt(v.SeqNumber)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation:
		enc_1 := ber.EncodeBitString(v.ProfileManagementOperation.Bytes, (8-(v.ProfileManagementOperation.BitLength%8))%8)
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RetrieveNotificationsListRequestSearchCriteria", v.Choice)
	}
}

// MarshalDER encodes RetrieveNotificationsListRequestSearchCriteria to DER format.
func (v *RetrieveNotificationsListRequestSearchCriteria) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes RetrieveNotificationsListRequestSearchCriteria from BER/DER format.
func (v *RetrieveNotificationsListRequestSearchCriteria) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RetrieveNotificationsListRequestSearchCriteria CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RetrieveNotificationsListRequestSearchCriteria: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RetrieveNotificationsListRequestSearchCriteria CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListRequestSearchCriteria", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = RetrieveNotificationsListRequestSearchCriteriaChoiceSeqNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding seqNumber: %w", intErr)
		}
		v.SeqNumber = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = RetrieveNotificationsListRequestSearchCriteriaChoiceProfileManagementOperation
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileManagementOperation: %w", tlvErr)
		}
		bsBytes, bsUnused, bsErr := ber.DecodeBitStringValue(rawVal)
		if bsErr != nil {
			return fmt.Errorf("decoding profileManagementOperation: %w", bsErr)
		}
		tmp := runtime.BitString{Bytes: bsBytes, BitLength: len(bsBytes)*8 - bsUnused}
		v.ProfileManagementOperation = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for RetrieveNotificationsListRequestSearchCriteria CHOICE", peekTag)
	}
	return nil
}

// MarshalBERRetrieveNotificationsListResponseNotificationList encodes a RetrieveNotificationsListResponseNotificationList list to BER.
func MarshalBERRetrieveNotificationsListResponseNotificationList(list RetrieveNotificationsListResponseNotificationList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERRetrieveNotificationsListResponseNotificationList decodes a RetrieveNotificationsListResponseNotificationList list from BER.
func UnmarshalBERRetrieveNotificationsListResponseNotificationList(data []byte) (RetrieveNotificationsListResponseNotificationList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RetrieveNotificationsListResponseNotificationList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RetrieveNotificationsListResponseNotificationList", Cause: ber.ErrExtraData}
	}
	var result RetrieveNotificationsListResponseNotificationList
	offset := 0
	for offset < len(content) {
		var elem PendingNotification
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBERLoadCRLResponseOkMissingParts encodes a LoadCRLResponseOkMissingParts list to BER.
func MarshalBERLoadCRLResponseOkMissingParts(list LoadCRLResponseOkMissingParts) ([]byte, error) {
	var children []byte
	for elemIndex, elem := range list {
		if elem == nil {
			return nil, fmt.Errorf("encoding LoadCRLResponseOkMissingParts[%d]: required INTEGER is nil", elemIndex)
		}
		children = append(children, ber.EncodeBigInt(elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERLoadCRLResponseOkMissingParts decodes a LoadCRLResponseOkMissingParts list from BER.
func UnmarshalBERLoadCRLResponseOkMissingParts(data []byte) (LoadCRLResponseOkMissingParts, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding LoadCRLResponseOkMissingParts: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "LoadCRLResponseOkMissingParts", Cause: ber.ErrExtraData}
	}
	var result LoadCRLResponseOkMissingParts
	offset := 0
	for offset < len(content) {
		val, n, intErr := ber.DecodeBigInt(content[offset:])
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ProfileInfoListRequestSearchCriteria to BER format.
func (v *ProfileInfoListRequestSearchCriteria) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ProfileInfoListRequestSearchCriteriaChoiceIsdpAid:
		enc_0 := ber.EncodeOctetString([]byte(*v.IsdpAid))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_0)
		return enc_0, nil
	case ProfileInfoListRequestSearchCriteriaChoiceIccid:
		enc_1 := ber.EncodeOctetString([]byte(*v.Iccid))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_1)
		return enc_1, nil
	case ProfileInfoListRequestSearchCriteriaChoiceProfileClass:
		if v.ProfileClass == nil {
			return nil, fmt.Errorf("choice ProfileInfoListRequestSearchCriteria: profileClass is nil")
		}
		enc_2 := ber.EncodeBigInt(v.ProfileClass.BigInt())
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ProfileInfoListRequestSearchCriteria", v.Choice)
	}
}

// MarshalDER encodes ProfileInfoListRequestSearchCriteria to DER format.
func (v *ProfileInfoListRequestSearchCriteria) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfoListRequestSearchCriteria from BER/DER format.
func (v *ProfileInfoListRequestSearchCriteria) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ProfileInfoListRequestSearchCriteria CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ProfileInfoListRequestSearchCriteria: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ProfileInfoListRequestSearchCriteria CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListRequestSearchCriteria", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 15 {
		v.Choice = ProfileInfoListRequestSearchCriteriaChoiceIsdpAid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdpAid: %w", tlvErr)
		}
		tmp := OctetTo16(rawVal)
		v.IsdpAid = &tmp
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
		v.Choice = ProfileInfoListRequestSearchCriteriaChoiceIccid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding iccid: %w", tlvErr)
		}
		tmp := Iccid(rawVal)
		v.Iccid = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
		v.Choice = ProfileInfoListRequestSearchCriteriaChoiceProfileClass
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding profileClass: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding profileClass: %w", intErr)
		}
		var named_profileclass ProfileClass
		if namedErr := named_profileclass.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding profileClass: %w", namedErr)
		}
		v.ProfileClass = &named_profileclass
	} else {
		return fmt.Errorf("unknown tag %s for ProfileInfoListRequestSearchCriteria CHOICE", peekTag)
	}
	return nil
}

// MarshalBERProfileInfoListResponseProfileInfoListOk encodes a ProfileInfoListResponseProfileInfoListOk list to BER.
func MarshalBERProfileInfoListResponseProfileInfoListOk(list ProfileInfoListResponseProfileInfoListOk) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERProfileInfoListResponseProfileInfoListOk decodes a ProfileInfoListResponseProfileInfoListOk list from BER.
func UnmarshalBERProfileInfoListResponseProfileInfoListOk(data []byte) (ProfileInfoListResponseProfileInfoListOk, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ProfileInfoListResponseProfileInfoListOk: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ProfileInfoListResponseProfileInfoListOk", Cause: ber.ErrExtraData}
	}
	var result ProfileInfoListResponseProfileInfoListOk
	offset := 0
	for offset < len(content) {
		var elem ProfileInfo
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBERProfileInfoNotificationConfigurationInfo encodes a ProfileInfoNotificationConfigurationInfo list to BER.
func MarshalBERProfileInfoNotificationConfigurationInfo(list ProfileInfoNotificationConfigurationInfo) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERProfileInfoNotificationConfigurationInfo decodes a ProfileInfoNotificationConfigurationInfo list from BER.
func UnmarshalBERProfileInfoNotificationConfigurationInfo(data []byte) (ProfileInfoNotificationConfigurationInfo, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ProfileInfoNotificationConfigurationInfo: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ProfileInfoNotificationConfigurationInfo", Cause: ber.ErrExtraData}
	}
	var result ProfileInfoNotificationConfigurationInfo
	offset := 0
	for offset < len(content) {
		var elem NotificationConfigurationInformation
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ProfileInfoIotSpecificProfileInfo to BER format.
func (v *ProfileInfoIotSpecificProfileInfo) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ProfileInfoIotSpecificProfileInfo to DER format.
func (v *ProfileInfoIotSpecificProfileInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProfileInfoIotSpecificProfileInfo from BER/DER format.
func (v *ProfileInfoIotSpecificProfileInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProfileInfoIotSpecificProfileInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProfileInfoIotSpecificProfileInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProfileInfoIotSpecificProfileInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EnableProfileRequestProfileIdentifier to BER format.
func (v *EnableProfileRequestProfileIdentifier) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case EnableProfileRequestProfileIdentifierChoiceIsdpAid:
		enc_0 := ber.EncodeOctetString([]byte(*v.IsdpAid))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_0)
		return enc_0, nil
	case EnableProfileRequestProfileIdentifierChoiceIccid:
		enc_1 := ber.EncodeOctetString([]byte(*v.Iccid))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EnableProfileRequestProfileIdentifier", v.Choice)
	}
}

// MarshalDER encodes EnableProfileRequestProfileIdentifier to DER format.
func (v *EnableProfileRequestProfileIdentifier) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes EnableProfileRequestProfileIdentifier from BER/DER format.
func (v *EnableProfileRequestProfileIdentifier) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for EnableProfileRequestProfileIdentifier CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EnableProfileRequestProfileIdentifier: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding EnableProfileRequestProfileIdentifier CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EnableProfileRequestProfileIdentifier", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 15 {
		v.Choice = EnableProfileRequestProfileIdentifierChoiceIsdpAid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdpAid: %w", tlvErr)
		}
		tmp := OctetTo16(rawVal)
		v.IsdpAid = &tmp
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
		v.Choice = EnableProfileRequestProfileIdentifierChoiceIccid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding iccid: %w", tlvErr)
		}
		tmp := Iccid(rawVal)
		v.Iccid = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for EnableProfileRequestProfileIdentifier CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes DisableProfileRequestProfileIdentifier to BER format.
func (v *DisableProfileRequestProfileIdentifier) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DisableProfileRequestProfileIdentifierChoiceIsdpAid:
		enc_0 := ber.EncodeOctetString([]byte(*v.IsdpAid))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 15, false, enc_0)
		return enc_0, nil
	case DisableProfileRequestProfileIdentifierChoiceIccid:
		enc_1 := ber.EncodeOctetString([]byte(*v.Iccid))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 26, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DisableProfileRequestProfileIdentifier", v.Choice)
	}
}

// MarshalDER encodes DisableProfileRequestProfileIdentifier to DER format.
func (v *DisableProfileRequestProfileIdentifier) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes DisableProfileRequestProfileIdentifier from BER/DER format.
func (v *DisableProfileRequestProfileIdentifier) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for DisableProfileRequestProfileIdentifier CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DisableProfileRequestProfileIdentifier: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DisableProfileRequestProfileIdentifier CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DisableProfileRequestProfileIdentifier", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 15 {
		v.Choice = DisableProfileRequestProfileIdentifierChoiceIsdpAid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdpAid: %w", tlvErr)
		}
		tmp := OctetTo16(rawVal)
		v.IsdpAid = &tmp
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 26 {
		v.Choice = DisableProfileRequestProfileIdentifierChoiceIccid
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding iccid: %w", tlvErr)
		}
		tmp := Iccid(rawVal)
		v.Iccid = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for DisableProfileRequestProfileIdentifier CHOICE", peekTag)
	}
	return nil
}

// MarshalBERProfilePolicyAuthorisationRuleAllowedOperators encodes a ProfilePolicyAuthorisationRuleAllowedOperators list to BER.
func MarshalBERProfilePolicyAuthorisationRuleAllowedOperators(list ProfilePolicyAuthorisationRuleAllowedOperators) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERProfilePolicyAuthorisationRuleAllowedOperators decodes a ProfilePolicyAuthorisationRuleAllowedOperators list from BER.
func UnmarshalBERProfilePolicyAuthorisationRuleAllowedOperators(data []byte) (ProfilePolicyAuthorisationRuleAllowedOperators, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ProfilePolicyAuthorisationRuleAllowedOperators: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ProfilePolicyAuthorisationRuleAllowedOperators", Cause: ber.ErrExtraData}
	}
	var result ProfilePolicyAuthorisationRuleAllowedOperators
	offset := 0
	for offset < len(content) {
		var elem OperatorId
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBERAuthenticateClientOkEs11EventEntries encodes a AuthenticateClientOkEs11EventEntries list to BER.
func MarshalBERAuthenticateClientOkEs11EventEntries(list AuthenticateClientOkEs11EventEntries) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERAuthenticateClientOkEs11EventEntries decodes a AuthenticateClientOkEs11EventEntries list from BER.
func UnmarshalBERAuthenticateClientOkEs11EventEntries(data []byte) (AuthenticateClientOkEs11EventEntries, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AuthenticateClientOkEs11EventEntries: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AuthenticateClientOkEs11EventEntries", Cause: ber.ErrExtraData}
	}
	var result AuthenticateClientOkEs11EventEntries
	offset := 0
	for offset < len(content) {
		var elem EventEntries
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}
